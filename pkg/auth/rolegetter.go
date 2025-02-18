package auth

import (
	"context"

	wranglerv1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/rbac/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// RBACRestGetter is used to encapsulate Getters for core RBAC resource types.
type RBACRestGetter struct {
	Roles               wranglerv1.RoleCache
	RoleBindings        wranglerv1.RoleBindingCache
	ClusterRoles        wranglerv1.ClusterRoleCache
	ClusterRoleBindings wranglerv1.ClusterRoleBindingCache
}

// GetRole gets role within the given namespace that matches the provided name.
func (r RBACRestGetter) GetRole(_ context.Context, namespace, name string) (*rbacv1.Role, error) {
	return r.Roles.Get(namespace, name)
}

// ListRoleBindings list all roleBindings in the given namespace.
func (r RBACRestGetter) ListRoleBindings(_ context.Context, namespace string) ([]*rbacv1.RoleBinding, error) {
	return r.RoleBindings.List(namespace, labels.NewSelector())
}

// GetClusterRole gets the clusterRole with the given name.
func (r RBACRestGetter) GetClusterRole(_ context.Context, name string) (*rbacv1.ClusterRole, error) {
	return r.ClusterRoles.Get(name)
}

// ListClusterRoleBindings list all clusterRoleBindings.
func (r RBACRestGetter) ListClusterRoleBindings(_ context.Context) ([]*rbacv1.ClusterRoleBinding, error) {
	return r.ClusterRoleBindings.List(labels.NewSelector())
}
