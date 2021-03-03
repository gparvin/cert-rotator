/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/x509/pkix"
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	certctrl "github.com/open-cluster-management/cert-controller/pkg/controller/certcontroller"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	// +kubebuilder:scaffold:imports

	certrotationcontroller "github.com/open-cluster-management/cert-controller/pkg/controller/certcontroller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var restartPods bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&restartPods, "restart-pods", false,
		"Enable restarting pods when the certificate changes. "+
			"Enabling this will ensure pods get restarted when the certificate rotates.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "aef253fd.my.domain",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	var generatedClient kubernetes.Interface = kubernetes.NewForConfigOrDie(mgr.GetConfig())

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("health", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("check", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")

	const (
		signerSecret      = "multicloud-ca-cert"
		caBundleConfigmap = "ca-bundle-configmap"
		signerNamePrefix  = "test-webhook"
	)

	var SigningCertValidity = time.Hour * 24 * 10
	var TargetCertValidity = time.Hour * 24 * 2
	var pkiname pkix.Name
	pkiname.OrganizationalUnit = []string{"hello-org-unit"}

	signingRotation := certrotationcontroller.SigningRotation{
		Namespace:        "open-cluster-management",
		Name:             signerSecret,
		SignerNamePrefix: signerNamePrefix,
		Validity:         SigningCertValidity,
		Client:           generatedClient,
	}
	caBundleRotation := certrotationcontroller.CABundleRotation{
		Namespace: "open-cluster-management",
		Name:      caBundleConfigmap,
		Client:    generatedClient,
	}
	targetRotations := []certrotationcontroller.TargetRotation{
		{
			Namespace:  "open-cluster-management",
			SecretName: "management-ingress-1dfac-tls-secret",
			Validity:   TargetCertValidity,
			HostNames:  []string{"multicloud-console.apps.gparvin.dev08.red-chesterfield.com", "management-ingress", "127.0.0.1", "localhost"},
			Client:     generatedClient,
		},
		{
			Namespace:  "open-cluster-management",
			SecretName: "oauth-proxy-tls-secret",
			Validity:   TargetCertValidity,
			HostNames:  []string{"multicloud-console.apps.gparvin.dev08.red-chesterfield.com"},
			Name:       pkiname,
			Client:     generatedClient,
		},
	}
	options := certrotationcontroller.Options{}
	options.RestartPods = true
	options.RestartSelf = false
	c := certrotationcontroller.CertRotationController{
		SigningRotation:  signingRotation,
		CABundleRotation: caBundleRotation,
		TargetRotations:  targetRotations,
		GeneratedClient:  generatedClient,
		Options:          options,
	}
	go certctrl.StartCertManagement(mgr, c, true)

	target := certrotationcontroller.TargetRotation{
		Namespace:  "default",
		SecretName: "added-secret",
		Validity:   time.Minute * 30,
		HostNames:  []string{"added-secret.default.svc"},
		Client:     generatedClient,
	}
	certctrl.AddTarget(context.TODO(), target)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}

}
