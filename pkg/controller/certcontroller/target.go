package certcontroller

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	"k8s.io/klog"

	"github.com/openshift/library-go/pkg/certs"
	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
)

const (
	restartLabel        = "security.open-cluster-management.io/time-restarted"
	noRestartAnnotation = "security.open-cluster-management.io/disable-auto-restart"
)

// TargetRotation rotates a key and cert signed by a CA. It creates a new one when 80%
// of the lifetime of the old cert has passed, or the CA used to signed the old cert is
// gone from the CA bundle.
type TargetRotation struct {
	Namespace  string
	SecretName string
	Validity   time.Duration
	HostNames  []string
	Name       pkix.Name
	Client     kubernetes.Interface
}

// EnsureTargetCertKeyPair makes sure the certificate is updated in the secret
func (c TargetRotation) EnsureTargetCertKeyPair(signingCertKeyPair *crypto.CA, caBundleCerts []*x509.Certificate, client kubernetes.Interface, restartPods bool) error {
	originalTargetCertKeyPairSecret, err := c.Client.CoreV1().Secrets(c.Namespace).Get(context.Background(), c.SecretName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	createSecret := false
	var targetCertKeyPairSecret *corev1.Secret
	if apierrors.IsNotFound(err) {
		// create an empty one
		targetCertKeyPairSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: c.Namespace, Name: c.SecretName}}
		createSecret = true
	} else {
		targetCertKeyPairSecret = originalTargetCertKeyPairSecret.DeepCopy()
	}
	targetCertKeyPairSecret.Type = corev1.SecretTypeTLS

	reason := needNewTargetCertKeyPair(targetCertKeyPairSecret, caBundleCerts)
	if len(reason) == 0 {
		return nil
	}

	if err := c.setTargetCertKeyPairSecret(targetCertKeyPairSecret, c.Validity, signingCertKeyPair); err != nil {
		return err
	}

	if createSecret {
		if _, err = c.Client.CoreV1().Secrets(c.Namespace).Create(context.Background(), targetCertKeyPairSecret, metav1.CreateOptions{}); err != nil {
			return err
		}
	} else {
		if _, err = c.Client.CoreV1().Secrets(c.Namespace).Update(context.Background(), targetCertKeyPairSecret, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	if restartPods && !firstSync {
		deploymentsInterface := client.AppsV1().Deployments(c.Namespace)
		statefulsetsInterface := client.AppsV1().StatefulSets(c.Namespace)
		daemonsetsInterface := client.AppsV1().DaemonSets(c.Namespace)
		restart(deploymentsInterface, statefulsetsInterface, daemonsetsInterface, c.SecretName, client)
	}
	return nil
}

// needNewTargetCertKeyPair returns a reason for creating a new target cert/key pair.
// Return empty if a valid cert/key pair is in place and no need to rotate it yet.
//
// We create a new target cert/key pair if
//   1) no cert/key pair exits
//   2) or the cert expired (then we are also pretty late)
//   3) or we are over the renewal percentage of the validity
//   4) or our old CA is gone from the bundle (then we are pretty late to the renewal party)
func needNewTargetCertKeyPair(secret *corev1.Secret, caBundleCerts []*x509.Certificate) string {
	certData := secret.Data["tls.crt"]
	if len(certData) == 0 {
		return "missing tls.crt"
	}

	certificates, err := cert.ParseCertsPEM(certData)
	if err != nil {
		return "bad certificate"
	}
	if len(certificates) == 0 {
		return "missing certificate"
	}

	cert := certificates[0]
	if time.Now().After(cert.NotAfter) {
		return "already expired"
	}

	maxWait := cert.NotAfter.Sub(cert.NotBefore) / 5
	latestTime := cert.NotAfter.Add(-maxWait)
	if time.Now().After(latestTime) {
		return fmt.Sprintf("expired in %6.3f seconds", cert.NotAfter.Sub(time.Now()).Seconds())
	}

	// check the signer common name against all the common names in our ca bundle so we don't refresh early
	for _, caCert := range caBundleCerts {
		if cert.Issuer.CommonName == caCert.Subject.CommonName {
			return ""
		}
	}

	return fmt.Sprintf("issuer %q not in ca bundle:\n%s", cert.Issuer.CommonName, certs.CertificateBundleToString(caBundleCerts))
}

// setTargetCertKeyPairSecret creates a new cert/key pair and sets them in the secret.
func (c TargetRotation) setTargetCertKeyPairSecret(targetCertKeyPairSecret *corev1.Secret, validity time.Duration, signer *crypto.CA) error {
	if targetCertKeyPairSecret.Data == nil {
		targetCertKeyPairSecret.Data = map[string][]byte{}
	}

	// make sure that we don't specify something past our signer
	targetValidity := validity
	// TODO: When creating a certificate, crypto.MakeServerCertForDuration accetps validity as input parameter,
	// It calls time.Now() as the current time to calculate NotBefore/NotAfter of new certificate, which might
	// be little later than the returned value of time.Now() call in the line below to get remainingSignerValidity.
	// 2 more seconds is added here as a buffer to make sure NotAfter of the new certificate does not past NotAfter
	// of the signing certificate. We may need a better way to handle this.
	remainingSignerValidity := signer.Config.Certs[0].NotAfter.Sub(time.Now().Add(time.Second * 2))
	if remainingSignerValidity < validity {
		targetValidity = remainingSignerValidity
	}
	certKeyPair, err := c.NewCertificate(signer, targetValidity)
	if err != nil {
		return err
	}
	targetCertKeyPairSecret.Data["tls.crt"], targetCertKeyPairSecret.Data["tls.key"], err = certKeyPair.GetPEMBytes()
	if err != nil {
		return err
	}

	return nil
}

func (c TargetRotation) customizeCertificate(certificate *x509.Certificate) error {
	certificate.Subject = c.Name
	return nil
}

// NewCertificate creates a new certificate
func (c TargetRotation) NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	if len(c.HostNames) == 0 {
		return nil, fmt.Errorf("no hostnames set")
	}
	return signer.MakeServerCertForDuration(sets.NewString(c.HostNames...), validity, c.customizeCertificate)
}

// restart will run every time a secret is updated for a certificate and when
// pod refresh is enabled. It will edit the deployments, statefulsets, and daemonsets
// that use the secret being updated, which will trigger the pod to be restarted.
func restart(deploymentsInterface appsv1.DeploymentInterface, statefulsetsInterface appsv1.StatefulSetInterface, daemonsetsInterface appsv1.DaemonSetInterface, secret string, client kubernetes.Interface) {
	listOptions := metav1.ListOptions{}
	deployments, _ := deploymentsInterface.List(context.TODO(), listOptions)
	statefulsets, _ := statefulsetsInterface.List(context.TODO(), listOptions)
	daemonsets, _ := daemonsetsInterface.List(context.TODO(), listOptions)

	update := time.Now().Format("2006-1-2.150417.000")
	updateOptions := metav1.UpdateOptions{}
NEXT_DEPLOYMENT:
	for _, adeployment := range deployments.Items {
		deployment := adeployment
		for _, volume := range deployment.Spec.Template.Spec.Volumes {
			if volume.Secret != nil && volume.Secret.SecretName != "" && volume.Secret.SecretName == secret && deployment.ObjectMeta.Annotations[noRestartAnnotation] != "true" {
				if deployment.ObjectMeta.Labels == nil {
					deployment.ObjectMeta.Labels = make(map[string]string)
				}
				deployment.ObjectMeta.Labels[restartLabel] = update
				if deployment.Spec.Template.ObjectMeta.Labels == nil {
					deployment.Spec.Template.ObjectMeta.Labels = make(map[string]string)
				}
				deployment.Spec.Template.ObjectMeta.Labels[restartLabel] = update
				_, err := deploymentsInterface.Update(context.TODO(), &deployment, updateOptions)
				if err != nil {
					klog.Errorf("Error updating deployment: %v", err)
				}
				klog.Infof("%s Cert-Rotator Restarting Resource: Secret=%s, Deployment=%s", update, secret, deployment.ObjectMeta.Name)
				continue NEXT_DEPLOYMENT
			}
		}
	}
NEXT_STATEFULSET:
	for _, astatefulset := range statefulsets.Items {
		statefulset := astatefulset
		for _, volume := range statefulset.Spec.Template.Spec.Volumes {
			if volume.Secret != nil && volume.Secret.SecretName != "" && volume.Secret.SecretName == secret && statefulset.ObjectMeta.Annotations[noRestartAnnotation] != "true" {
				if statefulset.ObjectMeta.Labels == nil {
					statefulset.ObjectMeta.Labels = make(map[string]string)
				}
				statefulset.ObjectMeta.Labels[restartLabel] = update
				if statefulset.Spec.Template.ObjectMeta.Labels == nil {
					statefulset.Spec.Template.ObjectMeta.Labels = make(map[string]string)
				}
				statefulset.Spec.Template.ObjectMeta.Labels[restartLabel] = update
				_, err := statefulsetsInterface.Update(context.TODO(), &statefulset, updateOptions)
				if err != nil {
					klog.Errorf("Error updating statefulset: %v", err)
				}
				klog.Infof("%s Cert-Rotator Restarting Resource: Secret=%s, StatefulSet=%s", update, secret, statefulset.ObjectMeta.Name)
				continue NEXT_STATEFULSET
			}
		}
	}
NEXT_DAEMONSET:
	for _, adaemonset := range daemonsets.Items {
		daemonset := adaemonset
		for _, volume := range daemonset.Spec.Template.Spec.Volumes {
			if volume.Secret != nil && volume.Secret.SecretName != "" && volume.Secret.SecretName == secret && daemonset.ObjectMeta.Annotations[noRestartAnnotation] != "true" {
				if daemonset.ObjectMeta.Labels == nil {
					daemonset.ObjectMeta.Labels = make(map[string]string)
				}
				daemonset.ObjectMeta.Labels[restartLabel] = update
				if daemonset.Spec.Template.ObjectMeta.Labels == nil {
					daemonset.Spec.Template.ObjectMeta.Labels = make(map[string]string)
				}
				daemonset.Spec.Template.ObjectMeta.Labels[restartLabel] = update
				_, err := daemonsetsInterface.Update(context.TODO(), &daemonset, updateOptions)
				if err != nil {
					klog.Errorf("Error updating daemonset: %v", err)
				}
				klog.Infof("%s Cert-Rotator Restarting Resource: Secret=%s, DaemonSet=%s", update, secret, daemonset.ObjectMeta.Name)
				continue NEXT_DAEMONSET
			}
		}
	}
}
