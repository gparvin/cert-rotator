package certcontroller

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"

	"github.com/openshift/library-go/pkg/crypto"
)

// CABundleRotation maintains a CA bundle config map, but adding new CA certs and removing expired old ones.
type CABundleRotation struct {
	Namespace string
	Name      string
	Client    kubernetes.Interface
}

// EnsureConfigMapCABundle validates the CA bundle is updated
func (c CABundleRotation) EnsureConfigMapCABundle(signingCertKeyPair *crypto.CA) ([]*x509.Certificate, error) {
	// by this point we have current signing cert/key pair.  We now need to make sure that the ca-bundle configmap has this cert and
	// doesn't have any expired certs
	originalCABundleConfigMap, err := c.Client.CoreV1().ConfigMaps(c.Namespace).Get(context.Background(), c.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	var caBundleConfigMap *corev1.ConfigMap
	createConfig := false
	if apierrors.IsNotFound(err) {
		// create an empty one
		caBundleConfigMap = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: c.Namespace, Name: c.Name}}
		createConfig = true
	} else {
		caBundleConfigMap = originalCABundleConfigMap.DeepCopy()
	}
	if _, err = manageCABundleConfigMap(caBundleConfigMap, signingCertKeyPair.Config.Certs[0]); err != nil {
		return nil, err
	}
	if originalCABundleConfigMap == nil || originalCABundleConfigMap.Data == nil || !equality.Semantic.DeepEqual(originalCABundleConfigMap.Data, caBundleConfigMap.Data) {
		if createConfig {
			_, err = c.Client.CoreV1().ConfigMaps(c.Namespace).Create(context.Background(), caBundleConfigMap, metav1.CreateOptions{})
		} else {
			_, err = c.Client.CoreV1().ConfigMaps(c.Namespace).Update(context.Background(), caBundleConfigMap, metav1.UpdateOptions{})
		}
		if err != nil {
			return nil, err
		}
	}

	caBundle := caBundleConfigMap.Data["ca-bundle.crt"]
	if len(caBundle) == 0 {
		return nil, fmt.Errorf("configmap/%s -n%s missing ca-bundle.crt", caBundleConfigMap.Name, caBundleConfigMap.Namespace)
	}
	certificates, err := cert.ParseCertsPEM([]byte(caBundle))
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

// manageCABundleConfigMap adds the new certificate to the list of cabundles, eliminates duplicates, and prunes the list of expired
// certs to trust as signers
func manageCABundleConfigMap(caBundleConfigMap *corev1.ConfigMap, currentSigner *x509.Certificate) ([]*x509.Certificate, error) {
	if caBundleConfigMap.Data == nil {
		caBundleConfigMap.Data = map[string]string{}
	}

	certificates := []*x509.Certificate{}
	caBundle := caBundleConfigMap.Data["ca-bundle.crt"]
	if len(caBundle) > 0 {
		var err error
		certificates, err = cert.ParseCertsPEM([]byte(caBundle))
		if err != nil {
			return nil, err
		}
	}
	certificates = append([]*x509.Certificate{currentSigner}, certificates...)
	certificates = crypto.FilterExpiredCerts(certificates...)

	finalCertificates := []*x509.Certificate{}
	// now check for duplicates. n^2, but super simple
	for i := range certificates {
		found := false
		for j := range finalCertificates {
			if reflect.DeepEqual(certificates[i].Raw, finalCertificates[j].Raw) {
				found = true
				break
			}
		}
		if !found {
			finalCertificates = append(finalCertificates, certificates[i])
		}
	}

	caBytes, err := crypto.EncodeCertificates(finalCertificates...)
	if err != nil {
		return nil, err
	}

	caBundleConfigMap.Data["ca-bundle.crt"] = string(caBytes)

	return finalCertificates, nil
}
