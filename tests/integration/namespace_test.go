package integration_test

import (
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *IntegrationSuite) TestNamespace() {
	const (
		testNamespace          = "psatestns"
		enforceLabel           = "pod-security.kubernetes.io/enforce"
		enforceBaselineValue   = "baseline"
		enforceRestrictedValue = "restricted"
	)

	newObj := func() *corev1.Namespace { return &corev1.Namespace{} }
	validCreateObj := &corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name:   testNamespace,
			Labels: map[string]string{enforceLabel: enforceBaselineValue},
		},
	}
	invalidCreate := func() *corev1.Namespace {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.Labels[enforceLabel] = "foo"
		return invalidCreate
	}
	invalidUpdate := func(created *corev1.Namespace) *corev1.Namespace {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.Labels[enforceLabel] = "foo"
		return invalidUpdateObj
	}
	validUpdate := func(created *corev1.Namespace) *corev1.Namespace {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Labels[enforceLabel] = enforceRestrictedValue
		return validUpdateObj
	}
	validDelete := func() *corev1.Namespace {
		return validCreateObj
	}
	endPoints := &endPointObjs[*corev1.Namespace]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}

	validateEndpoints(m.T(), endPoints, m.clientFactory)
}
