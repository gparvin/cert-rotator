package certcontroller

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
)

// SigningRotation rotates a self-signed signing CA stored in a secret. It creates a new one when 80%
// of the lifetime of the old CA has passed.
type SigningRotation struct {
	Namespace        string
	Name             string
	SignerNamePrefix string
	Validity         time.Duration
	Client           kubernetes.Interface
}

// EnsureSigningCertKeyPair makes sure the certificate is signed
func (c SigningRotation) EnsureSigningCertKeyPair() (*crypto.CA, error) {
	originalSigningCertKeyPairSecret, err := c.Client.CoreV1().Secrets(c.Namespace).Get(context.TODO(), c.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	createSecret := false
	var signingCertKeyPairSecret *corev1.Secret
	if apierrors.IsNotFound(err) {
		// create an empty one
		signingCertKeyPairSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: c.Namespace, Name: c.Name}}
		createSecret = true
	} else {
		signingCertKeyPairSecret = originalSigningCertKeyPairSecret.DeepCopy()
	}
	signingCertKeyPairSecret.Type = corev1.SecretTypeTLS

	if reason := needNewSigningCertKeyPair(signingCertKeyPairSecret); len(reason) > 0 {
		if err := setSigningCertKeyPairSecret(signingCertKeyPairSecret, c.SignerNamePrefix, c.Validity); err != nil {
			return nil, err
		}

		if createSecret {
			_, err = c.Client.CoreV1().Secrets(c.Namespace).Create(context.Background(), signingCertKeyPairSecret, metav1.CreateOptions{})
		} else {
			_, err = c.Client.CoreV1().Secrets(c.Namespace).Update(context.Background(), signingCertKeyPairSecret, metav1.UpdateOptions{})
		}
		if err != nil {
			return nil, err
		}
	}
	// at this point, the secret has the correct signer, so we should read that signer to be able to sign
	signingCertKeyPair, err := crypto.GetCAFromBytes(signingCertKeyPairSecret.Data["tls.crt"], signingCertKeyPairSecret.Data["tls.key"])
	if err != nil {
		return nil, err
	}

	return signingCertKeyPair, nil
}

func needNewSigningCertKeyPair(secret *corev1.Secret) string {
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

	return ""
}

// setSigningCertKeyPairSecret creates a new signing cert/key pair and sets them in the secret
func setSigningCertKeyPairSecret(signingCertKeyPairSecret *corev1.Secret, signerNamePrefix string, validity time.Duration) error {
	signerName := fmt.Sprintf("%s@%d", signerNamePrefix, time.Now().Unix())
	ca, err := crypto.MakeSelfSignedCAConfigForDuration(signerName, validity)
	if err != nil {
		return err
	}

	certBytes := &bytes.Buffer{}
	keyBytes := &bytes.Buffer{}
	if err := ca.WriteCertConfig(certBytes, keyBytes); err != nil {
		return err
	}

	if signingCertKeyPairSecret.Data == nil {
		signingCertKeyPairSecret.Data = map[string][]byte{}
	}
	signingCertKeyPairSecret.Data["tls.crt"] = certBytes.Bytes()
	signingCertKeyPairSecret.Data["tls.key"] = keyBytes.Bytes()

	return nil
}
