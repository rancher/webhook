package fleetworkspace

import (
	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/clients"
	corev1controller "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	rbacvacontroller "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"github.com/rancher/wrangler/pkg/webhook"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

var (
	fleetAdminRole = "fleetworkspace-admin"
)

func NewMutator(client *clients.Clients) webhook.Handler {
	return &mutator{
		namespaces:          client.Core.Namespace(),
		rolebindings:        client.RBAC.RoleBinding(),
		clusterrolebindings: client.RBAC.ClusterRoleBinding(),
		clusterroles:        client.RBAC.ClusterRole(),
		resolver:            client.DefaultResolver,
	}
}

type mutator struct {
	namespaces          corev1controller.NamespaceController
	rolebindings        rbacvacontroller.RoleBindingController
	clusterrolebindings rbacvacontroller.ClusterRoleBindingController
	clusterroles        rbacvacontroller.ClusterRoleController
	resolver            validation.AuthorizationRuleResolver
}

// When fleetworkspace is created, it will create the following resources:
// 1. Namespace. It will have the same name as fleetworkspace
// 2. fleetworkspace ClusterRole. It will create the cluster role that has * permission only to the current workspace
// 3. Two roleBinding to bind the current user to fleet-admin roles and fleetworkspace roles
func (m *mutator) Admit(response *webhook.Response, request *webhook.Request) error {
	if request.DryRun != nil && *request.DryRun {
		response.Allowed = true
		return nil
	}

	fw, err := fleetworkspaceObjects(request)
	if err != nil {
		return err
	}

	namespace := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: fw.Name,
		},
	}
	ns, err := m.namespaces.Create(&namespace)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
		// check if user has enough privilege to create fleet admin rolebinding in the namespace
		cr, err := m.clusterroles.Cache().Get(fleetAdminRole)
		if err != nil {
			return err
		}

		auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, cr.Rules, namespace.Name, m.resolver))

		ns, err = m.namespaces.Get(namespace.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
	}

	// create rolebinding to bind current user with fleetworkspace-admin role in current namespace
	if err := m.createAdminRoleAndBindings(request, fw); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// create an own clusterRole and clusterRoleBindings to make sure the creator has full permission to its own fleetworkspace
	if err := m.createOwnRoleAndBinding(request, fw, ns); err != nil {
		return err
	}

	response.Allowed = true
	return nil
}

func (m *mutator) createAdminRoleAndBindings(request *webhook.Request, fw *v3.FleetWorkspace) error {
	rolebinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fleetworkspace-admin-binding-" + fw.Name,
			Namespace: fw.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     request.UserInfo.Username,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     fleetAdminRole,
		},
	}
	if _, err := m.rolebindings.Create(&rolebinding); err != nil {
		return err
	}
	return nil
}

func (m *mutator) createOwnRoleAndBinding(request *webhook.Request, fw *v3.FleetWorkspace, ns *v1.Namespace) error {
	clusterrole := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fleetworkspace-own-" + fw.Name,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Namespace",
					Name:               ns.Name,
					UID:                ns.UID,
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
	if _, err := m.clusterroles.Create(&clusterrole); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	rolebindingView := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fleetworkspace-own-binding-" + fw.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     request.UserInfo.Username,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterrole.Name,
		},
	}
	if _, err := m.clusterrolebindings.Create(&rolebindingView); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func fleetworkspaceObjects(request *webhook.Request) (*v3.FleetWorkspace, error) {
	object, err := request.DecodeObject()
	if err != nil {
		return nil, err
	}

	return object.(*v3.FleetWorkspace), nil
}
