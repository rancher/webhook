package globalrole_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/rancher/wrangler/v2/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	adminUser = "admin-userid"
	testUser  = "test-user"
)

var (
	errServer = fmt.Errorf("server unavailable")
	baseCR    = &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cr",
		},
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	clusterRoles = []*v1.ClusterRole{adminCR, readPodsCR, baseCR}

	clusterRoleBindings = []*v1.ClusterRoleBinding{
		{
			Subjects: []v1.Subject{
				{Kind: v1.UserKind, Name: adminUser},
			},
			RoleRef: v1.RoleRef{APIGroup: v1.GroupName, Kind: "ClusterRole", Name: adminCR.Name},
		},
		{
			Subjects: []v1.Subject{
				{Kind: v1.UserKind, Name: testUser},
			},
			RoleRef: v1.RoleRef{APIGroup: v1.GroupName, Kind: "ClusterRole", Name: readPodsCR.Name},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-crb",
			},
			RoleRef: v1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     baseCR.Name,
			},
			Subjects: []v1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     testUser,
				},
			},
		},
	}
	baseRT = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-rt",
		},
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	baseGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-gr",
		},
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{baseRT.Name},
	}
	baseGRB = v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-grb",
		},
		GlobalRoleName: baseGR.Name,
		UserName:       testUser,
	}

	ruleReadPods = v1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	ruleWriteNodes = v1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	ruleEmptyVerbs = v1.PolicyRule{
		Verbs:     nil,
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	ruleAdmin = v1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	adminCR = &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []v1.PolicyRule{ruleAdmin},
	}
	readPodsCR = &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "read-pods"},
		Rules:      []v1.PolicyRule{ruleReadPods},
	}

	roleTemplate = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rt",
		},
		Context: "cluster",
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"*"},
			},
		},
	}
)

type testCase struct {
	name    string
	args    args
	allowed bool
	wantErr bool
}

type args struct {
	oldGR      func() *v3.GlobalRole
	newGR      func() *v3.GlobalRole
	stateSetup func(testState)
	username   string
}

type testState struct {
	rtCacheMock  *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	grCacheMock  *fake.MockNonNamespacedCacheInterface[*v3.GlobalRole]
	grbCacheMock *fake.MockNonNamespacedCacheInterface[*v3.GlobalRoleBinding]
	sarMock      *k8fake.FakeSubjectAccessReviews
	resolver     validation.AuthorizationRuleResolver
}

// createGRRequest will return a new webhookRequest using the given GRs
// if oldGR is nil then a request will be returned as a create operation.
// if newGR is nil then a request will be returned as a delete operation.
// else the request will look like an update operation.
// if the args.username is empty testUser will be used.
func createGRRequest(t *testing.T, test testCase) *admission.Request {
	t.Helper()
	username := test.args.username
	if username == "" {
		username = testUser
	}
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRole"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalrolebindings"}
	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       admissionv1.Create,
			UserInfo:        v1authentication.UserInfo{Username: username, UID: "", Extra: map[string]v1authentication.ExtraValue{"test": []string{"test"}}},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	var oldGR, newGR *v3.GlobalRole

	if test.args.newGR != nil {
		newGR = test.args.newGR()
	}
	if test.args.oldGR != nil {
		oldGR = test.args.oldGR()
	}
	if oldGR != nil {
		req.Operation = admissionv1.Update
		req.Name = oldGR.Name
		req.Namespace = oldGR.Namespace
		req.OldObject.Raw, err = json.Marshal(oldGR)
		assert.NoError(t, err, "Failed to marshal GR while creating request")
	}
	if newGR != nil {
		req.Name = newGR.Name
		req.Namespace = newGR.Namespace
		req.Object.Raw, err = json.Marshal(newGR)
		assert.NoError(t, err, "Failed to marshal GR while creating request")
	} else {
		req.Operation = admissionv1.Delete
	}

	return req
}

func newDefaultGR() *v3.GlobalRole {
	return &v3.GlobalRole{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalRole", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gr-new",
			GenerateName:      "gr-",
			Namespace:         "c-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		DisplayName:    "Test Global Role",
		Description:    "This is a role created for testing.",
		Rules:          nil,
		NewUserDefault: false,
		Builtin:        false,
	}
}

func newDefaultState(t *testing.T) testState {
	t.Helper()
	ctrl := gomock.NewController(t)
	rtCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	grCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRole](ctrl)
	grbCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRoleBinding](ctrl)
	grbs := []*v3.GlobalRoleBinding{&baseGRB}
	grbCacheMock.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey(testUser, "")).Return(grbs, nil).AnyTimes()
	grbCacheMock.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey(adminUser, "")).Return(grbs, nil).AnyTimes()
	grbCacheMock.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()
	grCacheMock.EXPECT().Get(baseGR.Name).Return(&baseGR, nil).AnyTimes()
	rtCacheMock.EXPECT().Get(baseRT.Name).Return(&baseRT, nil).AnyTimes()
	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)
	return testState{
		rtCacheMock:  rtCacheMock,
		grCacheMock:  grCacheMock,
		grbCacheMock: grbCacheMock,
		sarMock:      fakeSAR,
		resolver:     resolver,
	}
}

func (m *testState) createBaseGRBResolver() *resolvers.GRBClusterRuleResolver {
	grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(m.rtCacheMock, nil, nil), m.grCacheMock)
	return resolvers.NewGRBClusterRuleResolver(m.grbCacheMock, grResolver)
}
