package nodedriver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admission/v1"
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
	mockCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)

	a := admitter{
		nodeCache: mockCache,
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
	mockCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{
		{Status: v3.NodeStatus{NodeTemplateSpec: &v3.NodeTemplateSpec{
			Driver: "testing",
		}}},
	}, nil)

	a := admitter{
		nodeCache: mockCache,
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
	mockCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)

	a := admitter{
		nodeCache: mockCache,
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
	mockCache := fake.NewMockCacheInterface[*v3.Node](ctrl)
	mockCache.EXPECT().List("", labels.Everything()).Return([]*v3.Node{}, nil)

	a := admitter{
		nodeCache: mockCache,
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

	a := admitter{
		nodeCache: mockCache,
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

	a := admitter{
		nodeCache: mockCache,
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

func newNodeDriver(active bool, annotations map[string]string) []byte {
	if annotations == nil {
		annotations = map[string]string{}
	}

	driver := v3.NodeDriver{
		ObjectMeta: v1.ObjectMeta{
			Annotations: annotations,
		},
		Spec: v3.NodeDriverSpec{
			DisplayName: "testing",
			Active:      active,
		},
	}

	b, _ := json.Marshal(&driver)
	return b
}
