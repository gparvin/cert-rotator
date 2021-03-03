package certcontroller

import (
	"context"
	"fmt"
	"sync"
	"time"

	errorhelpers "github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var setupLog = ctrl.Log.WithName("certcontroller")

// Follow the rules below to set the value of SigningCertValidity/TargetCertValidity/ResyncInterval:
//
// 1) SigningCertValidity * 1/5 * 1/5 > ResyncInterval * 2
// 2) TargetCertValidity * 1/5 > ResyncInterval * 2

// DefaultCASigningCertValidity is the default CA certificate lifetime in hours
var DefaultCASigningCertValidity uint = 24 * 365

// DefaultTargetCertValidity is th default signed certificate lifetime in hours
var DefaultTargetCertValidity uint = 24 * 90

// CertManagement is the CertRotationController details managed by this controller
var CertManagement CertRotationController

// firstSync is true only for the first sync call
var firstSync bool = true

var mutex sync.Mutex

// CertRotationController does:
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
	GeneratedClient  kubernetes.Interface
	Options          Options
}

// Options provides some configuration settings for the controller
type Options struct {
	// RestartPods restarts any pods with the secret mounted when the certificate is refreshed
	RestartPods bool
	// RestartSelf restarts the current process if any certificates are refreshed
	RestartSelf bool
	// Frequency is how often to resync the certificates; specified in seconds
	Frequency uint
	// CASigningCertValidity is the default time in hours that the CA certificate is valid
	CASigningCertValidity uint
	// TargetCertValidity is the default time in hours that a signed certificate is valid
	TargetCertValidity uint
}

// StartCertManagement manages a certificate using a controller to monitor changes to the secret
func StartCertManagement(mgr manager.Manager, certinfo CertRotationController, loopflag bool) {

	CertManagement = certinfo
	if CertManagement.Options.Frequency == 0 {
		CertManagement.Options.Frequency = 300
	}
	if CertManagement.Options.CASigningCertValidity == 0 {
		CertManagement.Options.CASigningCertValidity = DefaultCASigningCertValidity
	}
	if CertManagement.Options.TargetCertValidity == 0 {
		CertManagement.Options.TargetCertValidity = DefaultTargetCertValidity
	}
	setupLog.Info("Initializing controller")
	for {
		start := time.Now()

		mutex.Lock()
		err := syncCerts(context.TODO())
		mutex.Unlock()
		if err != nil {
			setupLog.Error(err, "Sync error")
		}

		if loopflag {
			//prometheus quantiles for processing delay in each cycle
			elapsed := time.Since(start)
			//making sure that if processing is > freq we don't sleep
			//if freq > processing we sleep for the remaining duration
			elapsed = time.Since(start) / 1000000000 // convert to seconds
			if float64(CertManagement.Options.Frequency) > float64(elapsed) {
				remainingSleep := float64(CertManagement.Options.Frequency) - float64(elapsed)
				time.Sleep(time.Duration(remainingSleep) * time.Second)
			}
		} else {
			return
		}
	}
}

// AddTarget appends a new target certificate to the list that are being managed by the controller
func AddTarget(ctx context.Context, addTarget TargetRotation) error {
	setupLog.Info("Running AddTarget")
	mutex.Lock()
	defer mutex.Unlock()
	CertManagement.TargetRotations = append(CertManagement.TargetRotations, addTarget)
	err := syncCerts(context.TODO())
	if err != nil {
		setupLog.Error(err, "Add target certificate sync error")
	}
	return err
}

// RemoveTarget removes an existing target certificate from the list being managed by the controller
func RemoveTarget(ctx context.Context, namespace string, secretName string) error {
	setupLog.Info("Running RemoveTarget")
	mutex.Lock()
	defer mutex.Unlock()
	found := false
	var index int
	for x, target := range CertManagement.TargetRotations {
		if target.Namespace == namespace && target.SecretName == secretName {
			found = true
			index = x
			break
		}
	}
	var err error
	if found {
		err = CertManagement.GeneratedClient.CoreV1().Secrets(namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
		if err != nil {
			setupLog.Error(err, "Target certificate secret error")
		}
		CertManagement.TargetRotations = append(CertManagement.TargetRotations[:index], CertManagement.TargetRotations[index+1:]...)
		err = syncCerts(context.TODO())
		if err != nil {
			setupLog.Error(err, "Remove target certificate sync error")
		}
	} else {
		err = fmt.Errorf("Target secret to remove was not found: %s/%s", namespace, secretName)
	}
	return err
}

func syncCerts(ctx context.Context) error {

	setupLog.Info("Running Sync")

	// check if namespace exists or not
	_, err := CertManagement.GeneratedClient.CoreV1().Namespaces().Get(ctx, CertManagement.SigningRotation.Namespace, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return fmt.Errorf("namespace %q does not exist yet", CertManagement.SigningRotation.Namespace)
	}
	if err != nil {
		return err
	}

	// reconcile cert/key pair for signer
	signingCertKeyPair, err := CertManagement.SigningRotation.EnsureSigningCertKeyPair()
	if err != nil {
		return err
	}

	// reconcile ca bundle
	cabundleCerts, err := CertManagement.CABundleRotation.EnsureConfigMapCABundle(signingCertKeyPair)
	if err != nil {
		return err
	}

	// reconcile target cert/key pairs
	errs := []error{}
	for _, targetRotation := range CertManagement.TargetRotations {
		if err := targetRotation.EnsureTargetCertKeyPair(signingCertKeyPair, cabundleCerts, CertManagement.GeneratedClient, CertManagement.Options.RestartPods); err != nil {
			errs = append(errs, err)
		}
	}
	firstSync = false
	return errorhelpers.NewMultiLineAggregate(errs)
}
