package clusterroletemplatebinding_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/clusterroletemplatebinding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestGenerateDeterministicName(t *testing.T) {
	t.Parallel()

	t.Run("deterministic", func(t *testing.T) {
		name1 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-123")
		name2 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-123")
		assert.Equal(t, name1, name2, "same inputs must produce the same name")
	})

	t.Run("different subjects produce different names", func(t *testing.T) {
		name1 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-123")
		name2 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user2", "admin-role", "c-123")
		assert.NotEqual(t, name1, name2)
	})

	t.Run("different roleTemplates produce different names", func(t *testing.T) {
		name1 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-123")
		name2 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "read-role", "c-123")
		assert.NotEqual(t, name1, name2)
	})

	t.Run("different clusterNames produce different names", func(t *testing.T) {
		name1 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-123")
		name2 := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-456")
		assert.NotEqual(t, name1, name2)
	})

	t.Run("valid k8s name characters", func(t *testing.T) {
		name := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-123")
		assert.True(t, strings.HasPrefix(name, "crtb-"), "name should start with the prefix")
		// The suffix (after prefix) should only contain lowercase alphanumeric characters (base32 lowercase).
		suffix := strings.TrimPrefix(name, "crtb-")
		assert.Len(t, suffix, 10, "suffix should be 10 characters")
		for _, c := range suffix {
			assert.True(t, (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7'),
				"character %c is not a valid lowercase base32 character", c)
		}
	})

	t.Run("uses provided prefix", func(t *testing.T) {
		name := clusterroletemplatebinding.GenerateDeterministicName("myprefix-", "user1", "admin-role", "c-123")
		assert.True(t, strings.HasPrefix(name, "myprefix-"))
	})
}

func TestMutatorAdmit(t *testing.T) {
	t.Parallel()
	mutator := clusterroletemplatebinding.NewMutator()

	t.Run("skips when name is already set", func(t *testing.T) {
		crtb := &apisv3.ClusterRoleTemplateBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-explicit-name",
				Namespace: "c-123",
			},
			UserName:         "user1",
			RoleTemplateName: "admin-role",
			ClusterName:      "c-123",
		}

		req := createMutatingCRTBRequest(t, crtb, admissionv1.Create)
		resp, err := mutator.Admit(req)
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Nil(t, resp.Patch, "no patch expected when name is already set")
	})

	t.Run("rejects when both name and generateName are empty", func(t *testing.T) {
		crtb := &apisv3.ClusterRoleTemplateBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "",
				Namespace: "c-123",
			},
			UserName:         "user1",
			RoleTemplateName: "admin-role",
			ClusterName:      "c-123",
		}

		req := createMutatingCRTBRequest(t, crtb, admissionv1.Create)
		resp, err := mutator.Admit(req)
		require.NoError(t, err)
		assert.False(t, resp.Allowed, "should reject when both name and generateName are empty")
	})

	t.Run("mutates on CREATE with generateName", func(t *testing.T) {
		crtb := &apisv3.ClusterRoleTemplateBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "crtb-",
				Namespace:    "c-123",
			},
			UserName:         "user1",
			RoleTemplateName: "admin-role",
			ClusterName:      "c-123",
		}

		req := createMutatingCRTBRequest(t, crtb, admissionv1.Create)
		resp, err := mutator.Admit(req)
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.NotNil(t, resp.Patch, "patch expected when generateName is used")

		expectedName := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "user1", "admin-role", "c-123")
		assert.Contains(t, string(resp.Patch), expectedName)
	})

	t.Run("subject priority: userPrincipalName over userName", func(t *testing.T) {
		crtb := &apisv3.ClusterRoleTemplateBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "crtb-",
				Namespace:    "c-123",
			},
			UserPrincipalName: "local://user1",
			UserName:          "user1",
			RoleTemplateName:  "admin-role",
			ClusterName:       "c-123",
		}

		req := createMutatingCRTBRequest(t, crtb, admissionv1.Create)
		resp, err := mutator.Admit(req)
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.NotNil(t, resp.Patch)

		// The name should be based on userPrincipalName, not userName.
		expectedName := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "local://user1", "admin-role", "c-123")
		assert.Contains(t, string(resp.Patch), expectedName)
	})

	t.Run("subject priority: groupPrincipalName over groupName", func(t *testing.T) {
		crtb := &apisv3.ClusterRoleTemplateBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "crtb-",
				Namespace:    "c-123",
			},
			GroupPrincipalName: "ldap://admins",
			GroupName:          "admins",
			RoleTemplateName:   "admin-role",
			ClusterName:        "c-123",
		}

		req := createMutatingCRTBRequest(t, crtb, admissionv1.Create)
		resp, err := mutator.Admit(req)
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.NotNil(t, resp.Patch)

		expectedName := clusterroletemplatebinding.GenerateDeterministicName("crtb-", "ldap://admins", "admin-role", "c-123")
		assert.Contains(t, string(resp.Patch), expectedName)
	})

	t.Run("rejects when no subject fields are set", func(t *testing.T) {
		crtb := &apisv3.ClusterRoleTemplateBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "crtb-",
				Namespace:    "c-123",
			},
			RoleTemplateName: "admin-role",
			ClusterName:      "c-123",
		}

		req := createMutatingCRTBRequest(t, crtb, admissionv1.Create)
		resp, err := mutator.Admit(req)
		require.NoError(t, err)
		assert.False(t, resp.Allowed, "should reject when no subject is set")
	})

	t.Run("passes through non-CREATE operations", func(t *testing.T) {
		crtb := &apisv3.ClusterRoleTemplateBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "crtb-",
				Namespace:    "c-123",
			},
			UserName:         "user1",
			RoleTemplateName: "admin-role",
			ClusterName:      "c-123",
		}

		req := createMutatingCRTBRequest(t, crtb, admissionv1.Update)
		resp, err := mutator.Admit(req)
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Nil(t, resp.Patch, "no patch expected on update")
	})

	t.Run("two identical requests produce the same name", func(t *testing.T) {
		makeCRTB := func() *apisv3.ClusterRoleTemplateBinding {
			return &apisv3.ClusterRoleTemplateBinding{
				TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "crtb-",
					Namespace:    "c-123",
				},
				UserName:         "user1",
				RoleTemplateName: "admin-role",
				ClusterName:      "c-123",
			}
		}

		req1 := createMutatingCRTBRequest(t, makeCRTB(), admissionv1.Create)
		resp1, err := mutator.Admit(req1)
		require.NoError(t, err)

		req2 := createMutatingCRTBRequest(t, makeCRTB(), admissionv1.Create)
		resp2, err := mutator.Admit(req2)
		require.NoError(t, err)

		assert.Equal(t, string(resp1.Patch), string(resp2.Patch), "identical requests should produce the same patch")
	})
}

func createMutatingCRTBRequest(t *testing.T, crtb *apisv3.ClusterRoleTemplateBinding, op admissionv1.Operation) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ClusterRoleTemplateBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "clusterroletemplatebindings"}

	raw, err := json.Marshal(crtb)
	require.NoError(t, err, "failed to marshal CRTB")

	return &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            crtb.Name,
			Namespace:       crtb.Namespace,
			Operation:       op,
			UserInfo:        v1authentication.UserInfo{Username: "test-user", UID: ""},
			Object:          runtime.RawExtension{Raw: raw},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
}
