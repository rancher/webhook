package fleetworkspace

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	nsName = "test"
	user   = "test-user"
)

func TestAdmit(t *testing.T) {
	workspace := v3.FleetWorkspace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
		},
	}
	raw, _ := json.Marshal(workspace)
	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{Object: &workspace, Raw: raw},
			UserInfo: authenticationv1.UserInfo{
				Username: user,
			},
		},
	}

	tests := map[string]struct {
		m                  func(t *testing.T) Mutator
		req                *admission.Request
		expectAllowed      bool
		expectResultStatus *metav1.Status
		expectedErr        error
	}{
		"reject because namespace already exists": {
			m:             nsExistMutator,
			req:           req,
			expectAllowed: false,
			expectResultStatus: &metav1.Status{
				Status:  "Failure",
				Message: "namespace 'test' already exists",
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
		},
		"new namespace without the 'app.kubernetes.io/managed-by: rancher' label": {
			m:                  newNsMutator,
			req:                req,
			expectAllowed:      true,
			expectResultStatus: nil,
		},
		"existing namespace with the 'app.kubernetes.io/managed-by: rancher' label": {
			m:                  newNsWithLabelAndValidPermissionsMutator,
			req:                req,
			expectAllowed:      true,
			expectResultStatus: nil,
		},
		"reject existing namespace with the 'app.kubernetes.io/managed-by: rancher' label with invalid permissions": {
			m:             newNsWithLabelAndInvalidPermissionsMutator,
			req:           req,
			expectAllowed: false,
			expectResultStatus: &metav1.Status{
				Message: `user "test-user" (groups=[]) is attempting to grant RBAC permissions not currently held:
{APIGroups:["management.cattle.io"], Resources:["fleetworkspaces"], ResourceNames:["test"], Verbs:["*"]}`,
				Status: "Failure",
				Reason: metav1.StatusReasonForbidden,
				Code:   http.StatusForbidden,
			},
		},
		"reject because namespace can't be fetched": {
			m:           newNsErrorMutator,
			req:         req,
			expectedErr: errors.NewServerTimeout(schema.GroupResource{}, "", 2),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			m := test.m(t)
			admit, err := m.Admit(test.req)
			if test.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.Equalf(t, test.expectedErr, err, "Error doesn't match, wanted %v got %v", test.expectedErr, err)
				return
			}
			require.Equalf(t, test.expectAllowed, admit.Allowed, "Response was incorrectly validated, wanted response.Allowed = '%v' got %v: result=%+v", test.expectAllowed, admit.Allowed, admit.Result)
			require.Equalf(t, test.expectResultStatus, admit.Result, "Response was incorrectly validated, wanted response.Result = '%v' got %v", test.expectResultStatus, admit.Result)
		})
	}

}

func nsExistMutator(t *testing.T) Mutator {
	ctrl := gomock.NewController(t)
	mockNamespaceController := fake.NewMockNonNamespacedControllerInterface[*v1.Namespace, *v1.NamespaceList](ctrl)
	mockNamespaceController.EXPECT().Create(gomock.Any()).Return(nil, errors.NewAlreadyExists(schema.GroupResource{}, nsName))
	mockNamespaceController.EXPECT().Get(gomock.Any(), gomock.Any()).Return(&v1.Namespace{}, nil)

	return Mutator{
		namespaces: mockNamespaceController,
	}
}

func newNsMutator(t *testing.T) Mutator {
	ctrl := gomock.NewController(t)

	mockNamespaceController := fake.NewMockNonNamespacedControllerInterface[*v1.Namespace, *v1.NamespaceList](ctrl)
	mockNamespaceController.EXPECT().Create(gomock.Any()).Return(&v1.Namespace{}, nil)
	mockNamespaceController.EXPECT().Get(gomock.Any(), gomock.Any()).Times(0)
	mockRoleBindingController := fake.NewMockControllerInterface[*rbacv1.RoleBinding, *rbacv1.RoleBindingList](ctrl)
	mockRoleBindingController.EXPECT().Create(gomock.Any())
	mockClusterRoleBindingController := fake.NewMockNonNamespacedControllerInterface[*rbacv1.ClusterRoleBinding, *rbacv1.ClusterRoleBindingList](ctrl)
	mockClusterRoleBindingController.EXPECT().Create(gomock.Any())
	mockClusterRoleController := fake.NewMockNonNamespacedControllerInterface[*rbacv1.ClusterRole, *rbacv1.ClusterRoleList](ctrl)
	mockClusterRoleController.EXPECT().Create(gomock.Any())

	return Mutator{
		namespaces:          mockNamespaceController,
		rolebindings:        mockRoleBindingController,
		clusterrolebindings: mockClusterRoleBindingController,
		clusterroles:        mockClusterRoleController,
	}
}

func newNsWithLabelAndValidPermissionsMutator(t *testing.T) Mutator {
	ctrl := gomock.NewController(t)
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fleetworkspace-own-test",
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
					nsName,
				},
			},
		},
	}
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fleetworkspace-own-binding-test",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     user,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "fleetworkspace-own-test",
		},
	}

	mockNamespaceController := fake.NewMockNonNamespacedControllerInterface[*v1.Namespace, *v1.NamespaceList](ctrl)
	mockNamespaceController.EXPECT().Create(gomock.Any()).Return(nil, errors.NewAlreadyExists(schema.GroupResource{}, ""))
	mockNamespaceController.EXPECT().Get(gomock.Any(), gomock.Any()).Return(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app.kubernetes.io/managed-by": "rancher"},
		},
	}, nil)

	resolver, _ := validation.NewTestRuleResolver(nil, nil, []*rbacv1.ClusterRole{clusterRole}, []*rbacv1.ClusterRoleBinding{clusterRoleBinding})
	mockRoleBindingController := fake.NewMockControllerInterface[*rbacv1.RoleBinding, *rbacv1.RoleBindingList](ctrl)
	mockRoleBindingController.EXPECT().Create(gomock.Any())
	mockClusterRoleBindingController := fake.NewMockNonNamespacedControllerInterface[*rbacv1.ClusterRoleBinding, *rbacv1.ClusterRoleBindingList](ctrl)
	mockClusterRoleBindingController.EXPECT().Create(gomock.Any())
	mockClusterRoleController := fake.NewMockNonNamespacedControllerInterface[*rbacv1.ClusterRole, *rbacv1.ClusterRoleList](ctrl)
	mockClusterRoleController.EXPECT().Create(gomock.Any())
	mockClusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	mockClusterRoleCache.EXPECT().Get(fleetAdminRole).Return(clusterRole, nil)
	mockClusterRoleController.EXPECT().Cache().Return(mockClusterRoleCache)

	return Mutator{
		namespaces:          mockNamespaceController,
		rolebindings:        mockRoleBindingController,
		clusterrolebindings: mockClusterRoleBindingController,
		clusterroles:        mockClusterRoleController,
		resolver:            resolver,
	}
}

func newNsWithLabelAndInvalidPermissionsMutator(t *testing.T) Mutator {
	ctrl := gomock.NewController(t)
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fleetworkspace-own-test",
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
					nsName,
				},
			},
		},
	}
	mockNamespaceController := fake.NewMockNonNamespacedControllerInterface[*v1.Namespace, *v1.NamespaceList](ctrl)
	mockNamespaceController.EXPECT().Create(gomock.Any()).Return(nil, errors.NewAlreadyExists(schema.GroupResource{}, ""))
	mockNamespaceController.EXPECT().Get(gomock.Any(), gomock.Any()).Return(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app.kubernetes.io/managed-by": "rancher"},
		},
	}, nil)
	resolver, _ := validation.NewTestRuleResolver(nil, nil, []*rbacv1.ClusterRole{}, []*rbacv1.ClusterRoleBinding{})
	mockClusterRoleController := fake.NewMockNonNamespacedControllerInterface[*rbacv1.ClusterRole, *rbacv1.ClusterRoleList](ctrl)
	mockClusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	mockClusterRoleCache.EXPECT().Get(fleetAdminRole).Return(clusterRole, nil)
	mockClusterRoleController.EXPECT().Cache().Return(mockClusterRoleCache)

	return Mutator{
		namespaces:   mockNamespaceController,
		clusterroles: mockClusterRoleController,
		resolver:     resolver,
	}
}

func newNsErrorMutator(t *testing.T) Mutator {
	ctrl := gomock.NewController(t)

	mockNamespaceController := fake.NewMockNonNamespacedControllerInterface[*v1.Namespace, *v1.NamespaceList](ctrl)
	mockNamespaceController.EXPECT().Create(gomock.Any()).Return(nil, errors.NewServerTimeout(schema.GroupResource{}, "", 2))

	return Mutator{
		namespaces: mockNamespaceController,
	}
}
