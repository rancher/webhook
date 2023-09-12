package nodedriver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admission/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type NodeDriverValidationSuite struct {
	suite.Suite
}

func TestNodeDriverValidation(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(NodeDriverValidationSuite))
}

type mockLister struct {
	toReturn []runtime.Object
}

func (m *mockLister) List(_ schema.GroupVersionKind, _ string, _ labels.Selector) ([]runtime.Object, error) {
	return m.toReturn, nil
}

func (suite *NodeDriverValidationSuite) TestHappyPath() {
	ctrl := gomock.NewController(suite.T())
	mockNodeCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockNodeCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(&apiextensions.CustomResourceDefinition{}, nil)

	a := admitter{
		nodeCache: mockNodeCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{},
	}

	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
			Object:    runtime.RawExtension{Raw: newNodeDriver(false, nil)},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *NodeDriverValidationSuite) TestRKE1NotDeleted() {
	ctrl := gomock.NewController(suite.T())
	mockNodeCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockNodeCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{
		{Status: v3.NodeStatus{NodeTemplateSpec: &v3.NodeTemplateSpec{
			Driver: "testing",
		}}},
	}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(&apiextensions.CustomResourceDefinition{}, nil)

	a := admitter{
		nodeCache: mockNodeCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{},
	}

	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
			Object:    runtime.RawExtension{Raw: newNodeDriver(false, nil)},
		}})

	suite.Nil(err)
	suite.False(resp.Allowed, "admission request was allowed through")
}

func (suite *NodeDriverValidationSuite) TestRKE2NotDeleted() {
	ctrl := gomock.NewController(suite.T())
	mockNodeCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockNodeCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(&apiextensions.CustomResourceDefinition{}, nil)

	a := admitter{
		nodeCache: mockNodeCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{toReturn: []runtime.Object{&runtime.Unknown{}}},
	}

	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
			Object:    runtime.RawExtension{Raw: newNodeDriver(false, nil)},
		}})

	suite.Nil(err)
	suite.False(resp.Allowed, "admission request was allowed through")
}

func (suite *NodeDriverValidationSuite) TestNotDisablingDriver() {
	a := admitter{}
	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
			Object:    runtime.RawExtension{Raw: newNodeDriver(true, nil)},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *NodeDriverValidationSuite) TestDeleteGood() {
	ctrl := gomock.NewController(suite.T())
	mockNodeCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockNodeCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(&apiextensions.CustomResourceDefinition{}, nil)

	a := admitter{
		nodeCache: mockNodeCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{},
	}

	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Delete,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *NodeDriverValidationSuite) TestDeleteRKE1Bad() {
	ctrl := gomock.NewController(suite.T())
	mockCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{
		{Status: v3.NodeStatus{NodeTemplateSpec: &v3.NodeTemplateSpec{
			Driver: "testing",
		}}},
	}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(&apiextensions.CustomResourceDefinition{}, nil)

	a := admitter{
		nodeCache: mockCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{},
	}

	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Delete,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
		}})

	suite.Nil(err)
	suite.False(resp.Allowed, "admission request was allowed")
}

func (suite *NodeDriverValidationSuite) TestDeleteRKE2Bad() {
	ctrl := gomock.NewController(suite.T())
	mockCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(&apiextensions.CustomResourceDefinition{}, nil)

	a := admitter{
		nodeCache: mockCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{toReturn: []runtime.Object{&runtime.Unknown{}}},
	}

	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Delete,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
		}})

	suite.Nil(err)
	suite.False(resp.Allowed, "admission request was allowed")
}

func (suite *NodeDriverValidationSuite) TestCRDNotCreated() {
	ctrl := gomock.NewController(suite.T())
	mockNodeCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockNodeCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(nil, apierrors.NewNotFound(schema.GroupResource{}, "foobar"))

	a := admitter{
		nodeCache: mockNodeCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{},
	}

	resp, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
			Object:    runtime.RawExtension{Raw: newNodeDriver(false, nil)},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *NodeDriverValidationSuite) TestErrorFetchingCRD() {
	ctrl := gomock.NewController(suite.T())
	mockNodeCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockNodeCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)
	mockCRDCache := fake.NewMockNonNamespacedCacheInterface[*apiextensions.CustomResourceDefinition](ctrl)
	mockCRDCache.EXPECT().Get("testingmachines.rke-machine.cattle.io").Return(nil, errors.New("boom"))

	a := admitter{
		nodeCache: mockNodeCache,
		crdCache:  mockCRDCache,
		dynamic:   &mockLister{},
	}

	_, err := a.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			OldObject: runtime.RawExtension{Raw: newNodeDriver(true, nil)},
			Object:    runtime.RawExtension{Raw: newNodeDriver(false, nil)},
		}})

	suite.Error(err)
}

func newNodeDriver(active bool, annotations map[string]string) []byte {
	if annotations == nil {
		annotations = map[string]string{}
	}

	driver := v3.NodeDriver{
		ObjectMeta: v1.ObjectMeta{
			Annotations: annotations,
			Name:        "testing",
		},
		Spec: v3.NodeDriverSpec{
			Active: active,
		},
	}

	b, _ := json.Marshal(&driver)
	return b
}
