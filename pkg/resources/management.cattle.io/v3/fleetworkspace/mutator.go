package fleetworkspace

import (
	"fmt"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/clients"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	corev1controller "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	rbacvacontroller "github.com/rancher/wrangler/v3/pkg/generated/controllers/rbac/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const k8sManagedLabel = "app.kubernetes.io/managed-by"

var (
	fleetAdminRole = "fleetworkspace-admin"

	gvr = schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "fleetworkspaces",
	}
)

// NewMutator returns an initialized Mutator.
func NewMutator(client *clients.Clients) *Mutator {
	return &Mutator{
		namespaces:          client.Core.Namespace(),
		rolebindings:        client.RBAC.RoleBinding(),
		clusterrolebindings: client.RBAC.ClusterRoleBinding(),
		clusterroles:        client.RBAC.ClusterRole(),
		resolver:            client.DefaultResolver,
	}
}

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct {
	namespaces          corev1controller.NamespaceController
	rolebindings        rbacvacontroller.RoleBindingController
	clusterrolebindings rbacvacontroller.ClusterRoleBindingController
	clusterroles        rbacvacontroller.ClusterRoleController
	resolver            validation.AuthorizationRuleResolver
}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.ClusterScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// When fleetworkspace is created, it will create the following resources:
// 1. Namespace. It will have the same name as fleetworkspace
// 2. fleetworkspace ClusterRole. It will create the cluster role that has * permission only to the current workspace
// 3. Two roleBinding to bind the current user to fleet-admin roles and fleetworkspace roles
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if (request.DryRun != nil && *request.DryRun) || request.Operation == admissionv1.Delete {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	fw, err := objectsv3.FleetWorkspaceFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	namespace := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   fw.Name,
			Labels: map[string]string{k8sManagedLabel: "rancher"},
		},
	}
	ns, err := m.namespaces.Create(&namespace)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
		ns, err = m.namespaces.Get(fw.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get fleetworkspace namespace '%s': %w", fw.Name, err)
		}
		if ns.Labels[k8sManagedLabel] != "rancher" {
			return admission.ResponseBadRequest(fmt.Sprintf("namespace '%s' already exists", fw.Name)), nil
		}
		cr, err := m.clusterroles.Cache().Get(fleetAdminRole)
		if err != nil {
			return nil, fmt.Errorf("failed to get fleetAdmin ClusterRole: %w", err)
		}
		err = auth.ConfirmNoEscalation(request, cr.Rules, namespace.Name, m.resolver)
		if err != nil {
			return admission.ResponseFailedEscalation(err.Error()), nil
		}
	}

	// create rolebinding to bind current user with fleetworkspace-admin role in current namespace
	if err := m.createAdminRoleAndBindings(request, fw); err != nil && !errors.IsAlreadyExists(err) {
		return nil, err
	}

	// create an own clusterRole and clusterRoleBindings to make sure the creator has full permission to its own fleetworkspace
	if err := m.createOwnRoleAndBinding(request, fw, ns); err != nil {
		return nil, err
	}

	return &admissionv1.AdmissionResponse{
		Allowed: true,
	}, nil
}

func (m *Mutator) createAdminRoleAndBindings(request *admission.Request, fw *v3.FleetWorkspace) error {
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

func (m *Mutator) createOwnRoleAndBinding(request *admission.Request, fw *v3.FleetWorkspace, ns *v1.Namespace) error {
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
