package roletemplate

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	circleRoleTemplateName   = "circleRef"
	adminUser                = "admin-userid"
	testUser                 = "test-userid"
	noPrivUser               = "no-priv-userid"
	notFoundRoleTemplateName = "not-found-roleTemplate"
)

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
		Rules:          []rbacv1.PolicyRule{ruleAdmin},
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
		Rules: []rbacv1.PolicyRule{ruleAdmin},
	}
	c.manageNodeRole = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "manage-nodes"},
		Rules:      []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
	}
}

func (c *RoleTemplateSuite) Test_CheckCircularRef() {
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

	tests := []struct {
		name           string
		depth          int
		circleDepth    int
		errorDepth     int
		hasCircularRef bool
		errDesired     bool
	}{
		{
			name:           "basic test case - no inheritance, no circular ref or error",
			depth:          0,
			circleDepth:    -1,
			errorDepth:     -1,
			hasCircularRef: false,
			errDesired:     false,
		},
		{
			name:           "basic inheritance case - depth 1 of input is circular",
			depth:          1,
			circleDepth:    0,
			errorDepth:     -1,
			hasCircularRef: true,
			errDesired:     false,
		},
		{
			name:           "self-reference inheritance case - single role template which inherits itself",
			depth:          0,
			circleDepth:    0,
			errorDepth:     -1,
			hasCircularRef: true,
			errDesired:     false,
		},
		{
			name:           "deeply nested inheritance case - role template inherits other templates which eventually becomes circular",
			depth:          3,
			circleDepth:    2,
			errorDepth:     -1,
			hasCircularRef: true,
			errDesired:     false,
		},
		{
			name:           "basic error case - role inherits another role which doesn't exist",
			depth:          1,
			circleDepth:    -1,
			errorDepth:     0,
			hasCircularRef: false,
			errDesired:     true,
		},
	}

	for i := range tests {
		testCase := tests[i]
		c.Run(testCase.name, func() {
			rtName := "input-role"
			if testCase.circleDepth == 0 && testCase.hasCircularRef {
				rtName = circleRoleTemplateName
			}

			ctrl := gomock.NewController(c.T())
			roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()

			newRT := createNestedRoleTemplate(rtName, roleTemplateCache, testCase.depth, testCase.circleDepth, testCase.errorDepth)

			req := createRTRequest(c.T(), nil, newRT, adminUser)
			clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
			roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
			validator := NewValidator(resolver, roleResolver, fakeSAR)

			resp, err := validator.admitter.Admit(req)
			if testCase.errDesired {
				c.Error(err, "circular reference check, expected err")
				return
			}
			c.NoError(err, "circular reference check, did not expect an err")

			if !testCase.hasCircularRef {
				c.True(resp.Allowed, "expected roleTemplate to be allowed")
				return
			}

			c.False(resp.Allowed, "expected roleTemplate to be denied")
			if c.NotNil(resp.Result, "expected response result to be set") {
				c.Contains(resp.Result.Message, circleRoleTemplateName, "response result does not contain circular RoleTemplate name.")
			}
		})
	}
}

func createNestedRoleTemplate(name string, cache *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate], depth int, circleDepth int, errDepth int) *v3.RoleTemplate {
	start := createRoleTemplate(name)
	prior := start

	if depth == 0 && circleDepth == 0 {
		start.RoleTemplateNames = []string{start.Name}
		cache.EXPECT().Get(start.Name).Return(start, nil).MinTimes(0)
	}
	for i := 0; i < depth; i++ {
		current := createRoleTemplate("current-" + strconv.Itoa(i))
		if i != errDepth {
			cache.EXPECT().Get(current.Name).Return(current, nil).MinTimes(0)
		} else {
			cache.EXPECT().Get(gomock.AssignableToTypeOf(current.Name)).Return(nil, fmt.Errorf("not found")).MinTimes(0)
		}
		priorInherits := []string{current.Name}
		if i == circleDepth {
			circle := createRoleTemplate(circleRoleTemplateName)
			cache.EXPECT().Get(circle.Name).Return(circle, nil).MinTimes(0)
			priorInherits = append(priorInherits, circle.Name)
			circle.RoleTemplateNames = []string{name}
		}
		prior.RoleTemplateNames = priorInherits
		prior = current
	}

	return start
}

func createRoleTemplate(name string) *v3.RoleTemplate {
	newRT := newDefaultRT()
	newRT.Name = name
	newRT.Rules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}
	return newRT
}

// createRTRequest will return a new webhookRequest with the using the given RTs
// if oldRT is nil then a request will be returned as a create operation.
// if newRT is nil then a request will be returned as a delete operation.
// else the request will look like and update operation.
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
