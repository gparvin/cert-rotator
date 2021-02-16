package certcontroller

import (
	"context"
	"fmt"
	"time"

	errorhelpers "github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/open-cluster-management/registration-operator/pkg/helpers"
)

var setupLog = ctrl.Log.WithName("certcontroller")

// Follow the rules below to set the value of SigningCertValidity/TargetCertValidity/ResyncInterval:
//
// 1) SigningCertValidity * 1/5 * 1/5 > ResyncInterval * 2
// 2) TargetCertValidity * 1/5 > ResyncInterval * 2
var DefaultCASigningCertValidity = time.Hour * 24 * 10
var DefaultTargetCertValidity = time.Hour * 24 * 2
var DefaultResyncInterval = time.Minute * 5
var ResyncInterval = time.Minute * 5

// certRotationController does:
//
// 1) continuously create a self-signed signing CA (via SigningRotation).
//    It creates the next one when a given percentage of the validity of the old CA has passed.
// 2) maintain a CA bundle with all not yet expired CA certs.
// 3) continuously create target cert/key pairs signed by the latest signing CA
//    It creates the next one when a given percentage of the validity of the previous cert has
//    passed, or when a new CA has been created.
type CertRotationController struct {
	SigningRotation  SigningRotation
	CABundleRotation CABundleRotation
	TargetRotations  []TargetRotation
}

// StartCertManagement manages a certificate using a controller to monitor changes to the secret
func StartCertManagement(mgr manager.Manager, certinfo CertRotationController, client kubernetes.Interface, loopflag bool) {

	var freq uint = 300
	setupLog.Info("Initializing controller")
	for {
		start := time.Now()

		err := sync(context.TODO(), certinfo, client)
		if err != nil {
			setupLog.Error(err, "Sync error")
		}

		if loopflag {
			//prometheus quantiles for processing delay in each cycle
			elapsed := time.Since(start)
			//making sure that if processing is > freq we don't sleep
			//if freq > processing we sleep for the remaining duration
			elapsed = time.Since(start) / 1000000000 // convert to seconds
			if float64(freq) > float64(elapsed) {
				remainingSleep := float64(freq) - float64(elapsed)
				time.Sleep(time.Duration(remainingSleep) * time.Second)
			}
		} else {
			return
		}
	}
}

func sync(ctx context.Context, c CertRotationController, client kubernetes.Interface) error {

	setupLog.Info("Running Sync")

	// check if namespace exists or not
	_, err := client.CoreV1().Namespaces().Get(ctx, helpers.ClusterManagerNamespace, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return fmt.Errorf("namespace %q does not exist yet", helpers.ClusterManagerNamespace)
	}
	if err != nil {
		return err
	}

	// reconcile cert/key pair for signer
	signingCertKeyPair, err := c.SigningRotation.EnsureSigningCertKeyPair()
	if err != nil {
		return err
	}

	// reconcile ca bundle
	cabundleCerts, err := c.CABundleRotation.EnsureConfigMapCABundle(signingCertKeyPair)
	if err != nil {
		return err
	}

	// reconcile target cert/key pairs
	errs := []error{}
	for _, targetRotation := range c.TargetRotations {
		if err := targetRotation.EnsureTargetCertKeyPair(signingCertKeyPair, cabundleCerts); err != nil {
			errs = append(errs, err)
		}
	}
	return errorhelpers.NewMultiLineAggregate(errs)
}
