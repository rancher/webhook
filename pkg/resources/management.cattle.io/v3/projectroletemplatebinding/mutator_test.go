package projectroletemplatebinding_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"unicode"

	jsonpatch "github.com/evanphx/json-patch"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/projectroletemplatebinding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestGenerateDeterministicName(t *testing.T) {
	t.Parallel()

	t.Run("deterministic - same inputs produce same output", func(t *testing.T) {
		t.Parallel()
		name1 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		name2 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		assert.Equal(t, name1, name2, "same inputs should produce the same name")
	})

	t.Run("different subjects produce different names", func(t *testing.T) {
		t.Parallel()
		name1 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		name2 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user2", "admin-role", "cluster-id:project-id")
		assert.NotEqual(t, name1, name2, "different subjects should produce different names")
	})

	t.Run("different roleTemplateNames produce different names", func(t *testing.T) {
		t.Parallel()
		name1 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		name2 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "read-role", "cluster-id:project-id")
		assert.NotEqual(t, name1, name2, "different roleTemplateNames should produce different names")
	})

	t.Run("different projectNames produce different names", func(t *testing.T) {
		t.Parallel()
		name1 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		name2 := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:other-project")
		assert.NotEqual(t, name1, name2, "different projectNames should produce different names")
	})

	t.Run("name starts with prtb- prefix", func(t *testing.T) {
		t.Parallel()
		name := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		assert.True(t, len(name) > 5 && name[:5] == "prtb-", "name should start with 'prtb-'")
	})

	t.Run("total length is 15 characters", func(t *testing.T) {
		t.Parallel()
		name := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		assert.Equal(t, 15, len(name), "name should be 15 characters: 'prtb-' (5) + 10 hash chars")
	})

	t.Run("all characters are valid K8s name characters", func(t *testing.T) {
		t.Parallel()
		name := projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", "cluster-id:project-id")
		for _, c := range name {
			valid := unicode.IsLower(c) || unicode.IsDigit(c) || c == '-'
			assert.True(t, valid, "character '%c' should be a valid K8s name character (lowercase alphanumeric or '-')", c)
		}
	})

	t.Run("custom prefix is used", func(t *testing.T) {
		t.Parallel()
		name := projectroletemplatebinding.GenerateDeterministicName("custom-", "user1", "admin-role", "cluster-id:project-id")
		assert.True(t, len(name) > 7 && name[:7] == "custom-", "name should start with 'custom-'")
	})
}

func TestMutatorAdmit(t *testing.T) {
	t.Parallel()

	mutator := projectroletemplatebinding.NewMutator()

	tests := []struct {
		name       string
		prtb       func() *apisv3.ProjectRoleTemplateBinding
		wantPatch  bool
		wantName   string
		wantDenied bool
		wantError  bool
	}{
		{
			name: "CREATE with generateName and empty name - should set deterministic name",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "prtb-"
				return prtb
			},
			wantPatch: true,
			wantName:  projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID)),
		},
		{
			name: "CREATE with explicit name - should pass through without mutation",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = "ui-chosen-name"
				prtb.GenerateName = ""
				return prtb
			},
			wantPatch: false,
		},
		{
			name: "CREATE with both name and generateName set - should pass through without mutation",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = "ui-chosen-name"
				prtb.GenerateName = "prtb-"
				return prtb
			},
			wantPatch: false,
		},
		{
			name: "CREATE with both name and generateName empty - should reject",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = ""
				return prtb
			},
			wantDenied: true,
		},
		{
			name: "CREATE with custom generateName prefix - should use that prefix",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "custom-"
				return prtb
			},
			wantPatch: true,
			wantName:  projectroletemplatebinding.GenerateDeterministicName("custom-", "user1", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID)),
		},
		{
			name: "CREATE with name already correct - should not patch (idempotent)",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID))
				prtb.GenerateName = ""
				return prtb
			},
			wantPatch: false,
		},
		{
			name: "subject priority: UserPrincipalName takes precedence over UserName",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "prtb-"
				prtb.UserPrincipalName = "local://user1"
				prtb.UserName = "user1"
				return prtb
			},
			wantPatch: true,
			wantName:  projectroletemplatebinding.GenerateDeterministicName("prtb-", "local://user1", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID)),
		},
		{
			name: "subject priority: UserName when UserPrincipalName is empty",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "prtb-"
				prtb.UserPrincipalName = ""
				prtb.UserName = "user1"
				return prtb
			},
			wantPatch: true,
			wantName:  projectroletemplatebinding.GenerateDeterministicName("prtb-", "user1", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID)),
		},
		{
			name: "subject priority: GroupPrincipalName",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "prtb-"
				prtb.UserPrincipalName = ""
				prtb.UserName = ""
				prtb.GroupPrincipalName = "ldap://cn=admins"
				prtb.GroupName = "admins"
				return prtb
			},
			wantPatch: true,
			wantName:  projectroletemplatebinding.GenerateDeterministicName("prtb-", "ldap://cn=admins", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID)),
		},
		{
			name: "subject priority: GroupName when GroupPrincipalName is empty",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "prtb-"
				prtb.UserPrincipalName = ""
				prtb.UserName = ""
				prtb.GroupPrincipalName = ""
				prtb.GroupName = "admins"
				return prtb
			},
			wantPatch: true,
			wantName:  projectroletemplatebinding.GenerateDeterministicName("prtb-", "admins", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID)),
		},
		{
			name: "subject priority: ServiceAccount",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "prtb-"
				prtb.UserPrincipalName = ""
				prtb.UserName = ""
				prtb.GroupPrincipalName = ""
				prtb.GroupName = ""
				prtb.ServiceAccount = "system:serviceaccount:default:mysa"
				return prtb
			},
			wantPatch: true,
			wantName:  projectroletemplatebinding.GenerateDeterministicName("prtb-", "system:serviceaccount:default:mysa", "admin-role", fmt.Sprintf("%s:%s", clusterID, projectID)),
		},
		{
			name: "no subject set - should pass through without mutation",
			prtb: func() *apisv3.ProjectRoleTemplateBinding {
				prtb := newMutatorBasePRTB()
				prtb.Name = ""
				prtb.GenerateName = "prtb-"
				prtb.UserPrincipalName = ""
				prtb.UserName = ""
				prtb.GroupPrincipalName = ""
				prtb.GroupName = ""
				prtb.ServiceAccount = ""
				return prtb
			},
			wantPatch: false,
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			req := createMutatorPRTBRequest(t, test.prtb())
			resp, err := mutator.Admit(req)
			if test.wantError {
				require.Error(t, err, "expected error from Admit")
				return
			}
			require.NoError(t, err, "Admit failed")

			if test.wantDenied {
				require.False(t, resp.Allowed, "response should be denied")
				return
			}
			require.True(t, resp.Allowed, "response should be allowed")

			if test.wantPatch {
				require.NotNil(t, resp.Patch, "expected a patch in the response")

				patchObj, err := jsonpatch.DecodePatch(resp.Patch)
				require.NoError(t, err, "failed to decode patch from response")

				patchedJS, err := patchObj.Apply(req.Object.Raw)
				require.NoError(t, err, "failed to apply patch to Object")

				gotObj := &apisv3.ProjectRoleTemplateBinding{}
				err = json.Unmarshal(patchedJS, gotObj)
				require.NoError(t, err, "failed to unmarshal patched Object")

				assert.Equal(t, test.wantName, gotObj.Name, "patched name should match expected deterministic name")
				assert.Empty(t, gotObj.GenerateName, "generateName should be cleared after mutation")
			} else {
				assert.Nil(t, resp.Patch, "expected no patch in the response")
			}
		})
	}
}

func TestMutatorUnexpectedErrors(t *testing.T) {
	t.Parallel()
	mutator := projectroletemplatebinding.NewMutator()
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:       "1",
			Operation: v1.Create,
			Object:    runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	_, err := mutator.Admit(req)
	require.Error(t, err, "Admit should fail on bad request object")
}

func newMutatorBasePRTB() *apisv3.ProjectRoleTemplateBinding {
	return &apisv3.ProjectRoleTemplateBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ProjectRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "PRTB-new",
			GenerateName:      "prtb-",
			Namespace:         projectID,
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		UserName:         "user1",
		RoleTemplateName: "admin-role",
		ProjectName:      fmt.Sprintf("%s:%s", clusterID, projectID),
	}
}

func createMutatorPRTBRequest(t *testing.T, prtb *apisv3.ProjectRoleTemplateBinding) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ProjectRoleTemplateBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "projectroletemplatebindings"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            prtb.Name,
			Namespace:       prtb.Namespace,
			Operation:       v1.Create,
			UserInfo:        v1authentication.UserInfo{Username: "admin-userid", UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	req.Object.Raw, err = json.Marshal(prtb)
	assert.NoError(t, err, "Failed to marshal PRTB while creating request")
	return req
}
