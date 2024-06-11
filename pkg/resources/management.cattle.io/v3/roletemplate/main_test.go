package roletemplate_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v2/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var errTest = errors.New("bad error")

type testState struct {
	featureCacheMock     *fake.MockNonNamespacedCacheInterface[*v3.Feature]
	clusterRoleCacheMock *fake.MockNonNamespacedCacheInterface[*rbacv1.ClusterRole]
}

type tableTest struct {
	wantRT     func() *v3.RoleTemplate
	name       string
	args       args
	stateSetup func(state testState)
	wantError  bool
	allowed    bool
}

type args struct {
	oldRT    func() *v3.RoleTemplate
	newRT    func() *v3.RoleTemplate
	username string
}
type RoleTemplateSuite struct {
	suite.Suite
	ruleEmptyVerbs rbacv1.PolicyRule
	adminRT        *v3.RoleTemplate
	readNodesRT    *v3.RoleTemplate
	lockedRT       *v3.RoleTemplate
	adminCR        *rbacv1.ClusterRole
	manageNodeRole *rbacv1.ClusterRole
}

func TestRoleTemplates(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(RoleTemplateSuite))
}

func (c *RoleTemplateSuite) SetupSuite() {
	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	ruleWriteNodes := rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	ruleAdmin := rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	ruleAdminNonResource := rbacv1.PolicyRule{
		Verbs:           []string{"*"},
		NonResourceURLs: []string{"*"},
	}
	c.ruleEmptyVerbs = rbacv1.PolicyRule{
		Verbs:     nil,
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	c.readNodesRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
		Context:     "cluster",
	}
	c.adminRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName:    "Admin Role",
		Rules:          []rbacv1.PolicyRule{ruleAdmin, ruleAdminNonResource},
		Builtin:        true,
		Administrative: true,
		Context:        "cluster",
	}
	c.lockedRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods},
		Locked:      true,
		Context:     "cluster",
	}
	c.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{ruleAdmin, ruleAdminNonResource},
	}
	c.manageNodeRole = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "manage-nodes"},
		Rules:      []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
	}
}

// createRTRequest will return a new webhookRequest using the given RTs
// if oldRT is nil then a request will be returned as a create operation.
// if newRT is nil then a request will be returned as a delete operation.
// else the request will look like an update operation.
func createRTRequest(t *testing.T, oldRT, newRT *v3.RoleTemplate, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "RoleTemplate"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "roletemplates"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       v1.Create,
			UserInfo:        authenticationv1.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	if oldRT != nil {
		req.Operation = v1.Update
		req.Name = oldRT.Name
		req.Namespace = oldRT.Namespace
		req.OldObject.Raw, err = json.Marshal(oldRT)
		assert.NoError(t, err, "Failed to marshal RT while creating request")
	}
	if newRT != nil {
		req.Name = newRT.Name
		req.Namespace = newRT.Namespace
		req.Object.Raw, err = json.Marshal(newRT)
		assert.NoError(t, err, "Failed to marshal RT while creating request")
	} else {
		req.Operation = v1.Delete
	}

	return req
}

func newDefaultRT() *v3.RoleTemplate {
	return &v3.RoleTemplate{
		TypeMeta: metav1.TypeMeta{Kind: "RoleTemplate", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "rt-new",
			GenerateName:      "rt-",
			Namespace:         "c-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		DisplayName:           "test-RT",
		Description:           "Test Role Template",
		Context:               "cluster",
		RoleTemplateNames:     nil,
		Builtin:               false,
		External:              false,
		Hidden:                false,
		Locked:                false,
		ClusterCreatorDefault: false,
		ProjectCreatorDefault: false,
		Administrative:        false,
	}
}

func newNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "roletemplates"}, name)
}
