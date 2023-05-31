// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1 (interfaces: RoleCache,RoleController)

// Package fakes is a generated GoMock package.
package fakes

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	v1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	generic "github.com/rancher/wrangler/pkg/generic"
	v10 "k8s.io/api/rbac/v1"
	v11 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// MockRoleCache is a mock of RoleCache interface.
type MockRoleCache struct {
	ctrl     *gomock.Controller
	recorder *MockRoleCacheMockRecorder
}

// MockRoleCacheMockRecorder is the mock recorder for MockRoleCache.
type MockRoleCacheMockRecorder struct {
	mock *MockRoleCache
}

// NewMockRoleCache creates a new mock instance.
func NewMockRoleCache(ctrl *gomock.Controller) *MockRoleCache {
	mock := &MockRoleCache{ctrl: ctrl}
	mock.recorder = &MockRoleCacheMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRoleCache) EXPECT() *MockRoleCacheMockRecorder {
	return m.recorder
}

// AddIndexer mocks base method.
func (m *MockRoleCache) AddIndexer(arg0 string, arg1 v1.RoleIndexer) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddIndexer", arg0, arg1)
}

// AddIndexer indicates an expected call of AddIndexer.
func (mr *MockRoleCacheMockRecorder) AddIndexer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddIndexer", reflect.TypeOf((*MockRoleCache)(nil).AddIndexer), arg0, arg1)
}

// Get mocks base method.
func (m *MockRoleCache) Get(arg0, arg1 string) (*v10.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*v10.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockRoleCacheMockRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRoleCache)(nil).Get), arg0, arg1)
}

// GetByIndex mocks base method.
func (m *MockRoleCache) GetByIndex(arg0, arg1 string) ([]*v10.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByIndex", arg0, arg1)
	ret0, _ := ret[0].([]*v10.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByIndex indicates an expected call of GetByIndex.
func (mr *MockRoleCacheMockRecorder) GetByIndex(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByIndex", reflect.TypeOf((*MockRoleCache)(nil).GetByIndex), arg0, arg1)
}

// List mocks base method.
func (m *MockRoleCache) List(arg0 string, arg1 labels.Selector) ([]*v10.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0, arg1)
	ret0, _ := ret[0].([]*v10.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockRoleCacheMockRecorder) List(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockRoleCache)(nil).List), arg0, arg1)
}

// MockRoleController is a mock of RoleController interface.
type MockRoleController struct {
	ctrl     *gomock.Controller
	recorder *MockRoleControllerMockRecorder
}

// MockRoleControllerMockRecorder is the mock recorder for MockRoleController.
type MockRoleControllerMockRecorder struct {
	mock *MockRoleController
}

// NewMockRoleController creates a new mock instance.
func NewMockRoleController(ctrl *gomock.Controller) *MockRoleController {
	mock := &MockRoleController{ctrl: ctrl}
	mock.recorder = &MockRoleControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRoleController) EXPECT() *MockRoleControllerMockRecorder {
	return m.recorder
}

// AddGenericHandler mocks base method.
func (m *MockRoleController) AddGenericHandler(arg0 context.Context, arg1 string, arg2 generic.Handler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddGenericHandler", arg0, arg1, arg2)
}

// AddGenericHandler indicates an expected call of AddGenericHandler.
func (mr *MockRoleControllerMockRecorder) AddGenericHandler(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddGenericHandler", reflect.TypeOf((*MockRoleController)(nil).AddGenericHandler), arg0, arg1, arg2)
}

// AddGenericRemoveHandler mocks base method.
func (m *MockRoleController) AddGenericRemoveHandler(arg0 context.Context, arg1 string, arg2 generic.Handler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddGenericRemoveHandler", arg0, arg1, arg2)
}

// AddGenericRemoveHandler indicates an expected call of AddGenericRemoveHandler.
func (mr *MockRoleControllerMockRecorder) AddGenericRemoveHandler(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddGenericRemoveHandler", reflect.TypeOf((*MockRoleController)(nil).AddGenericRemoveHandler), arg0, arg1, arg2)
}

// Cache mocks base method.
func (m *MockRoleController) Cache() v1.RoleCache {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cache")
	ret0, _ := ret[0].(v1.RoleCache)
	return ret0
}

// Cache indicates an expected call of Cache.
func (mr *MockRoleControllerMockRecorder) Cache() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cache", reflect.TypeOf((*MockRoleController)(nil).Cache))
}

// Create mocks base method.
func (m *MockRoleController) Create(arg0 *v10.Role) (*v10.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0)
	ret0, _ := ret[0].(*v10.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockRoleControllerMockRecorder) Create(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockRoleController)(nil).Create), arg0)
}

// Delete mocks base method.
func (m *MockRoleController) Delete(arg0, arg1 string, arg2 *v11.DeleteOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockRoleControllerMockRecorder) Delete(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockRoleController)(nil).Delete), arg0, arg1, arg2)
}

// Enqueue mocks base method.
func (m *MockRoleController) Enqueue(arg0, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Enqueue", arg0, arg1)
}

// Enqueue indicates an expected call of Enqueue.
func (mr *MockRoleControllerMockRecorder) Enqueue(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Enqueue", reflect.TypeOf((*MockRoleController)(nil).Enqueue), arg0, arg1)
}

// EnqueueAfter mocks base method.
func (m *MockRoleController) EnqueueAfter(arg0, arg1 string, arg2 time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "EnqueueAfter", arg0, arg1, arg2)
}

// EnqueueAfter indicates an expected call of EnqueueAfter.
func (mr *MockRoleControllerMockRecorder) EnqueueAfter(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnqueueAfter", reflect.TypeOf((*MockRoleController)(nil).EnqueueAfter), arg0, arg1, arg2)
}

// Get mocks base method.
func (m *MockRoleController) Get(arg0, arg1 string, arg2 v11.GetOptions) (*v10.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1, arg2)
	ret0, _ := ret[0].(*v10.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockRoleControllerMockRecorder) Get(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRoleController)(nil).Get), arg0, arg1, arg2)
}

// GroupVersionKind mocks base method.
func (m *MockRoleController) GroupVersionKind() schema.GroupVersionKind {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GroupVersionKind")
	ret0, _ := ret[0].(schema.GroupVersionKind)
	return ret0
}

// GroupVersionKind indicates an expected call of GroupVersionKind.
func (mr *MockRoleControllerMockRecorder) GroupVersionKind() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GroupVersionKind", reflect.TypeOf((*MockRoleController)(nil).GroupVersionKind))
}

// Informer mocks base method.
func (m *MockRoleController) Informer() cache.SharedIndexInformer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Informer")
	ret0, _ := ret[0].(cache.SharedIndexInformer)
	return ret0
}

// Informer indicates an expected call of Informer.
func (mr *MockRoleControllerMockRecorder) Informer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Informer", reflect.TypeOf((*MockRoleController)(nil).Informer))
}

// List mocks base method.
func (m *MockRoleController) List(arg0 string, arg1 v11.ListOptions) (*v10.RoleList, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0, arg1)
	ret0, _ := ret[0].(*v10.RoleList)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockRoleControllerMockRecorder) List(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockRoleController)(nil).List), arg0, arg1)
}

// OnChange mocks base method.
func (m *MockRoleController) OnChange(arg0 context.Context, arg1 string, arg2 v1.RoleHandler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnChange", arg0, arg1, arg2)
}

// OnChange indicates an expected call of OnChange.
func (mr *MockRoleControllerMockRecorder) OnChange(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnChange", reflect.TypeOf((*MockRoleController)(nil).OnChange), arg0, arg1, arg2)
}

// OnRemove mocks base method.
func (m *MockRoleController) OnRemove(arg0 context.Context, arg1 string, arg2 v1.RoleHandler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnRemove", arg0, arg1, arg2)
}

// OnRemove indicates an expected call of OnRemove.
func (mr *MockRoleControllerMockRecorder) OnRemove(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnRemove", reflect.TypeOf((*MockRoleController)(nil).OnRemove), arg0, arg1, arg2)
}

// Patch mocks base method.
func (m *MockRoleController) Patch(arg0, arg1 string, arg2 types.PatchType, arg3 []byte, arg4 ...string) (*v10.Role, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1, arg2, arg3}
	for _, a := range arg4 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Patch", varargs...)
	ret0, _ := ret[0].(*v10.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Patch indicates an expected call of Patch.
func (mr *MockRoleControllerMockRecorder) Patch(arg0, arg1, arg2, arg3 interface{}, arg4 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1, arg2, arg3}, arg4...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Patch", reflect.TypeOf((*MockRoleController)(nil).Patch), varargs...)
}

// Update mocks base method.
func (m *MockRoleController) Update(arg0 *v10.Role) (*v10.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", arg0)
	ret0, _ := ret[0].(*v10.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Update indicates an expected call of Update.
func (mr *MockRoleControllerMockRecorder) Update(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockRoleController)(nil).Update), arg0)
}

// Updater mocks base method.
func (m *MockRoleController) Updater() generic.Updater {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Updater")
	ret0, _ := ret[0].(generic.Updater)
	return ret0
}

// Updater indicates an expected call of Updater.
func (mr *MockRoleControllerMockRecorder) Updater() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Updater", reflect.TypeOf((*MockRoleController)(nil).Updater))
}

// Watch mocks base method.
func (m *MockRoleController) Watch(arg0 string, arg1 v11.ListOptions) (watch.Interface, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Watch", arg0, arg1)
	ret0, _ := ret[0].(watch.Interface)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Watch indicates an expected call of Watch.
func (mr *MockRoleControllerMockRecorder) Watch(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Watch", reflect.TypeOf((*MockRoleController)(nil).Watch), arg0, arg1)
}