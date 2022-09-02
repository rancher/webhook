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
	// errAfterNext determines after how many calls to the cache an error will be thrown. If -1 don't ever throw error
	errAfterNext int
	// nextError is the next error that will be returned after errAfterNext calls
	nextError error
}

func NewMockRoleTemplateCache() *MockRoleTemplateCache {
	return &MockRoleTemplateCache{
		state:        []*v3.RoleTemplate{},
		errAfterNext: -1,
		nextError:    nil,
	}
}

func (mc *MockRoleTemplateCache) Get(name string) (*v3.RoleTemplate, error) {
	if mc.shouldReturnErr() {
		mc.decrementErrorCounter()
		return nil, mc.nextError
	}
	mc.decrementErrorCounter()
	for _, template := range mc.state {
		if template.Name == name {
			return template, nil
		}
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "roletemplate"}, name)
}

func (mc *MockRoleTemplateCache) List(selector labels.Selector) ([]*v3.RoleTemplate, error) {
	if mc.shouldReturnErr() {
		mc.decrementErrorCounter()
		return nil, mc.nextError
	}
	mc.decrementErrorCounter()
	return mc.state, nil
}

func (mc *MockRoleTemplateCache) AddIndexer(indexName string, indexer controllerv3.RoleTemplateIndexer) {
	//TODO: Add indexer method
}

func (mc *MockRoleTemplateCache) GetByIndex(indexName, key string) ([]*v3.RoleTemplate, error) {
	//TODO: Add GetByIndexer method
	return nil, fmt.Errorf("not implemented")
}

func (mc *MockRoleTemplateCache) Add(template *v3.RoleTemplate) {
	mc.state = append(mc.state, template)
}

func (mc *MockRoleTemplateCache) AddErr(calls int, err error) {
	mc.errAfterNext = calls
	mc.nextError = err
}

func (mc *MockRoleTemplateCache) shouldReturnErr() bool {
	return false
}

func (mc *MockRoleTemplateCache) decrementErrorCounter() {

}
