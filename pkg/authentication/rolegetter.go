package authentication

import (
	wranglerv1 "github.com/rancher/wrangler-api/pkg/generated/controllers/rbac/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type RBACRestGetter struct {
	Roles               wranglerv1.RoleCache
	RoleBindings        wranglerv1.RoleBindingCache
	ClusterRoles        wranglerv1.ClusterRoleCache
	ClusterRoleBindings wranglerv1.ClusterRoleBindingCache
}

func (r RBACRestGetter) GetRole(namespace, name string) (*rbacv1.Role, error) {
	return r.Roles.Get(namespace, name)
}

func (r RBACRestGetter) ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) {
	return r.RoleBindings.List(namespace, labels.NewSelector())
}

func (r RBACRestGetter) GetClusterRole(name string) (*rbacv1.ClusterRole, error) {
	return r.ClusterRoles.Get(name)
}

func (r RBACRestGetter) ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) {
	return r.ClusterRoleBindings.List(labels.NewSelector())
}
