package fleetworkspace

import (
	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/clients"
	corev1controller "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	rbacvacontroller "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"github.com/rancher/wrangler/pkg/webhook"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewMutator(client *clients.Clients) webhook.Handler {
	return &mutator{
		namespaces:          client.Core.Namespace(),
		rolebindings:        client.RBAC.RoleBinding(),
		clusterrolebindings: client.RBAC.ClusterRoleBinding(),
	}
}

type mutator struct {
	namespaces          corev1controller.NamespaceController
	rolebindings        rbacvacontroller.RoleBindingController
	clusterrolebindings rbacvacontroller.ClusterRoleBindingController
}

// When fleetworkspace is created, it will create the following resources:
// 1. Namespace. It will have the same name as fleetworkspace
// 2. fleetworkspace ClusterRole. It will create the cluster role that has * permission only to the current workspace
// 3. Two roleBinding
func (m *mutator) Admit(response *webhook.Response, request *webhook.Request) error {
	fw, err := fleetworkspaceObjects(request)
	if err != nil {
		return err
	}

	namespace := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: fw.Name,
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:               "FleetWorkspace",
					APIVersion:         management.GroupName,
					Name:               fw.Name,
					UID:                fw.UID,
					Controller:         new(bool),
					BlockOwnerDeletion: new(bool),
				},
			},
		},
	}
	if _, err := m.namespaces.Create(&namespace); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	role := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fleetworkspace-view-" + fw.Name,
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:               "FleetWorkspace",
					APIVersion:         management.GroupName,
					Name:               fw.Name,
					UID:                fw.UID,
					Controller:         new(bool),
					BlockOwnerDeletion: new(bool),
				},
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					management.GroupName,
				},
				Verbs: []string{
					"*",
				},
				Resources: []string{
					"fleetworkspaces",
				},
				ResourceNames: []string{
					fw.Name,
				},
			},
		},
	}

	rolebindingView := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fleetworkspace-view-binding-" + fw.Name,
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:               "FleetWorkspace",
					APIVersion:         management.GroupName,
					Name:               fw.Name,
					UID:                fw.UID,
					Controller:         new(bool),
					BlockOwnerDeletion: new(bool),
				},
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     request.UserInfo.UID,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     role.Name,
		},
	}
	if _, err := m.clusterrolebindings.Create(&rolebindingView); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	rolebinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fleetworkspace-admin-binding-" + fw.Name,
			Namespace: fw.Name,
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:               "FleetWorkspace",
					APIVersion:         management.GroupName,
					Name:               fw.Name,
					UID:                fw.UID,
					Controller:         new(bool),
					BlockOwnerDeletion: new(bool),
				},
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     request.UserInfo.UID,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "fleetworkspace-admin",
		},
	}
	if _, err := m.rolebindings.Create(&rolebinding); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	response.Allowed = true
	return nil
}

func fleetworkspaceObjects(request *webhook.Request) (*v3.FleetWorkspace, error) {
	object, err := request.DecodeObject()
	if err != nil {
		return nil, err
	}

	return object.(*v3.FleetWorkspace), nil
}
