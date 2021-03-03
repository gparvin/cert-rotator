module github.com/open-cluster-management/cert-controller

go 1.15

require (
	github.com/open-cluster-management/api v0.0.0-20201210143210-581cab55c797
	github.com/open-cluster-management/registration-operator v0.0.0-20210120065033-cb2abf6370e6
	github.com/openshift/library-go v0.0.0-20210127081712-a4f002827e42
	github.com/tj/assert v0.0.3
	k8s.io/api v0.20.0
	k8s.io/apimachinery v0.20.0
	k8s.io/client-go v0.20.0
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.4.0
	sigs.k8s.io/controller-runtime v0.7.0
)
