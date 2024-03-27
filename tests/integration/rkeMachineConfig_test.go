package integration_test

import (
	"github.com/rancher/webhook/pkg/auth"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestRKEMachineConfig() {
	objGVK := schema.GroupVersionKind{
		Group:   "rke-machine-config.cattle.io",
		Version: "v1",
		Kind:    "AzureConfig",
	}
	newObj := func() *unstructured.Unstructured { return &unstructured.Unstructured{} }
	validCreateObj := &unstructured.Unstructured{}
	validCreateObj.SetName("test-rke.machine")
	validCreateObj.SetNamespace(testNamespace)
	validCreateObj.SetGroupVersionKind(objGVK)
	invalidUpdate := func(_ *unstructured.Unstructured) *unstructured.Unstructured {
		invalidUpdateObj := validCreateObj.DeepCopy()
		invalidUpdateObj.SetAnnotations(map[string]string{auth.CreatorIDAnn: "foobar"})
		return invalidUpdateObj
	}
	validUpdate := func(created *unstructured.Unstructured) *unstructured.Unstructured {
		validUpdateObj := created.DeepCopy()
		annotations := validUpdateObj.GetAnnotations()
		annotations["dark-knight"] = "batman"
		validUpdateObj.SetAnnotations(annotations)
		return validUpdateObj
	}
	validDelete := func() *unstructured.Unstructured {
		return validCreateObj
	}
	endPoints := &endPointObjs[*unstructured.Unstructured]{
		gvk:            objGVK,
		invalidCreate:  nil,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}
