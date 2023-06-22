package mocks

import (
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type MockRoleTemplateCache struct {
	// state is the internal state used to store our role templates for test purposes
	state []*v3.RoleTemplate
}

func NewMockRoleTemplateCache() *MockRoleTemplateCache {
	return &MockRoleTemplateCache{
		state: []*v3.RoleTemplate{},
	}
}

func (mc *MockRoleTemplateCache) Get(name string) (*v3.RoleTemplate, error) {
	for _, template := range mc.state {
		if template.Name == name {
			return template, nil
		}
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "roletemplate"}, name)
}

func (mc *MockRoleTemplateCache) List(_ labels.Selector) ([]*v3.RoleTemplate, error) {
	return mc.state, nil
}

func (mc *MockRoleTemplateCache) AddIndexer(string, controllerv3.RoleTemplateIndexer) {
}

func (mc *MockRoleTemplateCache) GetByIndex(string, string) ([]*v3.RoleTemplate, error) {
	return nil, fmt.Errorf("not implemented")
}

func (mc *MockRoleTemplateCache) Add(template *v3.RoleTemplate) {
	mc.state = append(mc.state, template)
}
