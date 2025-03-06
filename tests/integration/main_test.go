// Package integration_test holds the integration test for the webhook.
package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rancher/lasso/pkg/client"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provisioningv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/wrangler/v3/pkg/gvk"
	"github.com/rancher/wrangler/v3/pkg/kubeconfig"
	"github.com/rancher/wrangler/v3/pkg/schemes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	testNamespace = "foo"
	testUser      = "test-user"
)

type IntegrationSuite struct {
	suite.Suite
	clientFactory client.SharedClientFactory
}

func TestIntegrationTest(t *testing.T) {
	suite.Run(t, new(IntegrationSuite))
}

func (m *IntegrationSuite) SetupSuite() {
	logrus.SetLevel(logrus.DebugLevel)
	kubeconfigPath := os.Getenv("KUBECONFIG")
	logrus.Infof("Setting up test with KUBECONFIG=%s", kubeconfigPath)
	restCfg, err := kubeconfig.GetNonInteractiveClientConfig(kubeconfigPath).ClientConfig()
	m.Require().NoError(err, "Failed to clientFactory config")
	m.clientFactory, err = client.NewSharedClientFactoryForConfig(restCfg)
	m.Require().NoError(err, "Failed to create clientFactory Interface")

	schemes.Register(v3.AddToScheme)
	schemes.Register(provisioningv1.AddToScheme)
	schemes.Register(corev1.AddToScheme)

	ns := &corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: testNamespace,
		},
	}
	m.createObj(ns, schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Namespace",
	})
}

func (m *IntegrationSuite) TearDownSuite() {
	ns := &corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: testNamespace,
		},
	}
	m.deleteObj(ns, schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Namespace",
	})
}

// Object is generic object to wrap runtime and metav1.
type Object interface {
	v1.Object
	runtime.Object
}
type endPointObjs[T Object] struct {
	invalidCreate  func() T
	validCreateObj T
	newObj         func() T
	invalidUpdate  func(obj T) T
	validUpdate    func(obj T) T
	invalidDelete  func() T
	validDelete    func() T
	gvk            schema.GroupVersionKind
}

// validateEndpoints performs basic create and update operations used for testing an endpoint.
// This function attempts the following operations in order.
// Create with invalidCreate (skipped if nil).
// Create with validCreate. newObj is used to store the result and can not return nil.
// Patch with output of the validCreate and Mutated by the invalidUpdate func (skipped if nil).
// Patch with output of the validCreate and Mutated by the validUpdate func (skipped if nil).
// Delete with the output of invalid Delete func() (skipped if nil).
// Delete with the output of valid Delete func() (skipped if nil).
func validateEndpoints[T Object](t *testing.T, objs *endPointObjs[T], clientFactory client.SharedClientFactory) *client.Client {
	t.Helper()
	result := objs.newObj()
	objGVK := objs.gvk
	if objGVK.Empty() {
		var err error
		objGVK, err = gvk.Get(objs.validCreateObj)
		require.NoError(t, err, "failed to get GVK")
	}
	client, err := clientFactory.ForKind(objGVK)
	require.NoError(t, err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if objs.invalidCreate != nil {
		invalidObj := objs.invalidCreate()
		err = client.Create(ctx, invalidObj.GetNamespace(), invalidObj, nil, v1.CreateOptions{})
		assert.Error(t, err, "No error returned during the creation of an invalid Object")
	}
	err = client.Create(ctx, objs.validCreateObj.GetNamespace(), objs.validCreateObj, result, v1.CreateOptions{})
	assert.NoError(t, err, "Error returned during the creation of a valid Object")
	if objs.invalidUpdate != nil {
		updatedObj := objs.invalidUpdate(result)
		patch, err := createPatch(result, updatedObj)
		assert.NoError(t, err, "Failed to create patch")
		err = client.Patch(ctx, updatedObj.GetNamespace(), updatedObj.GetName(), types.JSONPatchType, patch, result, v1.PatchOptions{})
		assert.Error(t, err, "No error returned during the update of an invalid Object")
	}
	if objs.validUpdate != nil {
		updatedObj := objs.validUpdate(result)
		patch, err := createPatch(result, updatedObj)
		assert.NoError(t, err, "Failed to create patch")
		err = client.Patch(ctx, updatedObj.GetNamespace(), updatedObj.GetName(), types.JSONPatchType, patch, result, v1.PatchOptions{})
		assert.NoError(t, err, "Error returned during the update of a valid Object")
	}
	if objs.invalidDelete != nil {
		deleteObj := objs.invalidDelete()
		err := client.Delete(ctx, deleteObj.GetNamespace(), deleteObj.GetName(), v1.DeleteOptions{})
		assert.Error(t, err, "No error returned during the update of an invalid Object")
	}
	if objs.validDelete != nil {
		deleteObj := objs.validDelete()
		err := client.Delete(ctx, deleteObj.GetNamespace(), deleteObj.GetName(), v1.DeleteOptions{})
		assert.NoError(t, err, "Error returned during the deletion of a valid Object")
	}

	return client
}

func Ptr[T any](val T) *T {
	return &val
}

func createPatch(oldObj, newObj any) ([]byte, error) {
	oldJSON, err := json.Marshal(oldObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal old obj: %w", err)
	}
	newJSON, err := json.Marshal(newObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new obj: %w", err)
	}

	patch := admission.PatchResponseFromRaw(oldJSON, newJSON)

	patchJSON, err := json.Marshal(patch.Patches)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal patch: %w", err)
	}
	return patchJSON, nil
}

func (m *IntegrationSuite) deleteObj(obj Object, objGVK schema.GroupVersionKind) {
	if objGVK.Empty() {
		var err error
		objGVK, err = gvk.Get(obj)
		m.Require().NoError(err, "failed to get GVK")
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "failed to create client")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = client.Delete(ctx, obj.GetNamespace(), obj.GetName(), v1.DeleteOptions{})
	m.Require().NoError(err, "failed to delete obj")
}

func (m *IntegrationSuite) createObj(obj Object, objGVK schema.GroupVersionKind) {
	if objGVK.Empty() {
		var err error
		objGVK, err = gvk.Get(obj)
		m.Require().NoError(err, "failed to get GVK")
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "failed to create client")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = client.Create(ctx, obj.GetNamespace(), obj, nil, v1.CreateOptions{})
	m.Require().NoError(err, "failed to create obj")
}
