package certcontroller

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"github.com/tj/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	fakekube "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/cert"
)

const testClusterManagerName = "testclustermanager"
const testNamespace = "default"

var secretNames = []string{"signer-key-pair-secret", "serving-cert-key-pair-secret"}

type validateFunc func(t *testing.T, kubeClient kubernetes.Interface, err error)

func TestCertRotation(t *testing.T) {

	cases := []struct {
		name            string
		existingObjects []runtime.Object
		validate        validateFunc
	}{
		{
			name: "no namespace",
			validate: func(t *testing.T, kubeClient kubernetes.Interface, err error) {
				if err == nil {
					t.Fatalf("expected an error")
				}
				assertNoSecretCreated(t, kubeClient)
			},
		},
		{
			name: "rotate cert",
			existingObjects: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNamespace,
					},
				},
			},
			validate: func(t *testing.T, kubeClient kubernetes.Interface, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				assertSecretsExistAndValid(t, kubeClient)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kubeClient := fakekube.NewSimpleClientset(c.existingObjects...)

			signingRotation := SigningRotation{
				Namespace:        testNamespace,
				Name:             "signer-key-pair-secret",
				SignerNamePrefix: "test-signer",
				Validity:         time.Hour * 1,
				Client:           kubeClient,
			}

			caBundleRotation := CABundleRotation{
				Namespace: testNamespace,
				Name:      "ca-bundle-configmap",
				Client:    kubeClient,
			}
			targetRotations := []TargetRotation{
				{
					Namespace:  testNamespace,
					SecretName: "serving-cert-key-pair-secret",
					Validity:   time.Minute * 30,
					HostNames:  []string{fmt.Sprintf("service1.%s.svc", testNamespace)},
					Client:     kubeClient,
				},
			}
			options := Options{
				RestartPods:           true,
				RestartSelf:           true,
				Frequency:             300,
				CASigningCertValidity: 240,
				TargetCertValidity:    48,
			}
			controller := &CertRotationController{
				SigningRotation:  signingRotation,
				CABundleRotation: caBundleRotation,
				TargetRotations:  targetRotations,
				GeneratedClient:  kubeClient,
				Options:          options,
			}

			CertManagement = *controller
			err := syncCerts(context.TODO())
			c.validate(t, kubeClient, err)

		})
	}
}

func asseertSecretMissing(t *testing.T, kubeClient kubernetes.Interface, name string) {
	_, err := kubeClient.CoreV1().Secrets(testNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err == nil {
		t.Fatalf("unexpected secret %q", name)
	}
	if !errors.IsNotFound(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertNoSecretCreated(t *testing.T, kubeClient kubernetes.Interface) {
	for _, name := range secretNames {
		asseertSecretMissing(t, kubeClient, name)
	}
}

func assertSecretExistsAndValid(t *testing.T, kubeClient kubernetes.Interface, name string, namespace string) (*x509.Certificate, error) {
	secret, err := kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		t.Fatalf("secret not found: %v", name)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	certificates, err := cert.ParseCertsPEM(secret.Data["tls.crt"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certificates) == 0 {
		t.Fatalf("no certificate found")
	}

	now := time.Now()
	certificate := certificates[0]
	if now.After(certificate.NotAfter) {
		t.Fatalf("invalid NotAfter: %s", name)
	}
	if now.Before(certificate.NotBefore) {
		t.Fatalf("invalid NotBefore: %s", name)
	}
	return certificate, nil
}

func assertSecretsExistAndValid(t *testing.T, kubeClient kubernetes.Interface) {
	configmap, err := kubeClient.CoreV1().ConfigMaps(testNamespace).Get(context.Background(), "ca-bundle-configmap", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, name := range secretNames {
		certificate, _ := assertSecretExistsAndValid(t, kubeClient, name, testNamespace)

		if name == "signer-key-pair-secret" {
			continue
		}

		// ensure signing cert of serving certs in the ca bundle configmap
		caCerts, err := cert.ParseCertsPEM([]byte(configmap.Data["ca-bundle.crt"]))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		now := time.Now()
		for _, caCert := range caCerts {
			if certificate.Issuer.CommonName != caCert.Subject.CommonName {
				continue
			}
			if now.After(caCert.NotAfter) {
				t.Fatalf("invalid NotAfter of ca: %s", name)
			}
			if now.Before(caCert.NotBefore) {
				t.Fatalf("invalid NotBefore of ca: %s", name)
			}
			found = true
			break
		}
		if !found {
			t.Fatalf("no issuer found: %s", name)
		}
	}
}

func TestTargetUpdates(t *testing.T) {
	existingObjects := []runtime.Object{
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		},
	}

	kubeClient := fakekube.NewSimpleClientset(existingObjects...)

	signingRotation := SigningRotation{
		Namespace:        testNamespace,
		Name:             "signer-key-pair-secret",
		SignerNamePrefix: "test-signer",
		Validity:         time.Hour * 1,
		Client:           kubeClient,
	}

	caBundleRotation := CABundleRotation{
		Namespace: testNamespace,
		Name:      "ca-bundle-configmap",
		Client:    kubeClient,
	}
	targetRotations := []TargetRotation{
		{
			Namespace:  testNamespace,
			SecretName: "serving-cert-key-pair-secret",
			Validity:   time.Minute * 30,
			HostNames:  []string{fmt.Sprintf("service1.%s.svc", testNamespace)},
			Client:     kubeClient,
		},
	}
	options := Options{
		RestartPods:           true,
		RestartSelf:           true,
		Frequency:             300,
		CASigningCertValidity: 240,
		TargetCertValidity:    48,
	}
	controller := CertRotationController{
		SigningRotation:  signingRotation,
		CABundleRotation: caBundleRotation,
		TargetRotations:  targetRotations,
		GeneratedClient:  kubeClient,
		Options:          options,
	}
	target := TargetRotation{
		Namespace:  testNamespace,
		SecretName: "added-secret",
		Validity:   time.Minute * 30,
		HostNames:  []string{fmt.Sprintf("added1.%s.svc", testNamespace)},
		Client:     kubeClient,
	}

	CertManagement = controller
	err := syncCerts(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSecretsExistAndValid(t, kubeClient)

	err = AddTarget(context.TODO(), target)
	assertSecretExistsAndValid(t, kubeClient, target.SecretName, testNamespace)

	for _, entry := range CertManagement.TargetRotations {
		t.Logf("   Target %s/%s", entry.Namespace, entry.SecretName)
	}
	err = RemoveTarget(context.TODO(), target.Namespace, target.SecretName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret, err := kubeClient.CoreV1().Secrets(testNamespace).Get(context.Background(), target.SecretName, metav1.GetOptions{})
	if secret != nil || err == nil {
		t.Fatalf("secret was found: %v", target.SecretName)
	}
	asseertSecretMissing(t, kubeClient, target.SecretName)
}

func TestRollingDeployment(t *testing.T) {
	existingObjects := []runtime.Object{
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mydeployment",
				Namespace: testNamespace,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "mypod",
						Namespace: testNamespace,
					},
					Spec: corev1.PodSpec{
						Volumes: []corev1.Volume{
							{
								Name: "myvolume",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: "serving-cert-key-pair-secret",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	kubeClient := fakekube.NewSimpleClientset(existingObjects...)

	signingRotation := SigningRotation{
		Namespace:        testNamespace,
		Name:             "signer-key-pair-secret",
		SignerNamePrefix: "test-signer",
		Validity:         time.Hour * 1,
		Client:           kubeClient,
	}

	caBundleRotation := CABundleRotation{
		Namespace: testNamespace,
		Name:      "ca-bundle-configmap",
		Client:    kubeClient,
	}
	targetRotations := []TargetRotation{
		{
			Namespace:  testNamespace,
			SecretName: "serving-cert-key-pair-secret",
			Validity:   time.Minute * 30,
			HostNames:  []string{fmt.Sprintf("service1.%s.svc", testNamespace)},
			Client:     kubeClient,
		},
	}
	options := Options{
		RestartPods:           true,
		RestartSelf:           true,
		Frequency:             300,
		CASigningCertValidity: 240,
		TargetCertValidity:    48,
	}
	controller := CertRotationController{
		SigningRotation:  signingRotation,
		CABundleRotation: caBundleRotation,
		TargetRotations:  targetRotations,
		GeneratedClient:  kubeClient,
		Options:          options,
	}

	CertManagement = controller
	firstSync = true
	err := syncCerts(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSecretsExistAndValid(t, kubeClient)

	deployment, err := kubeClient.AppsV1().Deployments(testNamespace).Get(context.TODO(), "mydeployment", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	restarted := false
	for key, value := range deployment.Labels {
		t.Logf("Annotation: %s=%s", key, value)
		if key == "security.open-cluster-management.io/time-restarted" {
			restarted = true
		}
	}
	assert.False(t, restarted)

	// delete the secret
	kubeClient.CoreV1().Secrets(testNamespace).Delete(context.TODO(), "serving-cert-key-pair-secret", metav1.DeleteOptions{})
	// re-sync
	err = syncCerts(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSecretsExistAndValid(t, kubeClient)

	// the secret should exist and the deployment should have been restarted
	deployment, err = kubeClient.AppsV1().Deployments(testNamespace).Get(context.TODO(), "mydeployment", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	restarted = false
	for key, value := range deployment.Labels {
		t.Logf("Annotation: %s=%s", key, value)
		if key == "security.open-cluster-management.io/time-restarted" {
			restarted = true
		}
	}
	assert.True(t, restarted)
}

func TestCertificateFields(t *testing.T) {
	existingObjects := []runtime.Object{
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		},
	}

	kubeClient := fakekube.NewSimpleClientset(existingObjects...)

	signingRotation := SigningRotation{
		Namespace:        testNamespace,
		Name:             "signer-key-pair-secret",
		SignerNamePrefix: "test-signer",
		Validity:         time.Hour * 1,
		Client:           kubeClient,
	}

	caBundleRotation := CABundleRotation{
		Namespace: testNamespace,
		Name:      "ca-bundle-configmap",
		Client:    kubeClient,
	}
	targetRotations := []TargetRotation{
		{
			Namespace:  testNamespace,
			SecretName: "serving-cert-key-pair-secret",
			Validity:   time.Minute * 30,
			HostNames:  []string{fmt.Sprintf("service1.%s.svc", testNamespace)},
			Name: pkix.Name{
				OrganizationalUnit: []string{"Red Hat"},
			},
			Client: kubeClient,
		},
	}
	options := Options{
		RestartPods:           true,
		RestartSelf:           true,
		Frequency:             300,
		CASigningCertValidity: 240,
		TargetCertValidity:    48,
	}
	controller := CertRotationController{
		SigningRotation:  signingRotation,
		CABundleRotation: caBundleRotation,
		TargetRotations:  targetRotations,
		GeneratedClient:  kubeClient,
		Options:          options,
	}

	CertManagement = controller
	err := syncCerts(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, err := assertSecretExistsAndValid(t, kubeClient, "serving-cert-key-pair-secret", testNamespace)
	assert.True(t, cert.Subject.OrganizationalUnit[0] == "Red Hat")

}
