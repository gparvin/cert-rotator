package controller

import (
	"github.com/open-cluster-management/cert-controller/pkg/controller/certcontroller"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, certcontroller.Add)
}
