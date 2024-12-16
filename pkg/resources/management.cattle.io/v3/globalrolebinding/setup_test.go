package globalrolebinding_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	adminUser           = "admin-user"
	restrictedAdminUser = "restricted-admin-user"
	testUser            = "test-user"
	noPrivUser          = "no-priv-user"
	newUser             = "newUser-user"
	newGroupPrinc       = "local://group"
	testGroup           = "testGroup"
	notFoundName        = "not-found"
	errName             = "error-Name"
)

type testCase struct {
	wantGRB   func() *v3.GlobalRoleBinding
	name      string
	args      args
	wantError bool
	allowed   bool
}

type testState struct {
	rtCacheMock  *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	grCacheMock  *fake.MockNonNamespacedCacheInterface[*v3.GlobalRole]
	grbCacheMock *fake.MockNonNamespacedCacheInterface[*v3.GlobalRoleBinding]
	sarMock      *k8fake.FakeSubjectAccessReviews
	resolver     validation.AuthorizationRuleResolver
}

type args struct {
	stateSetup func(testState)
	oldGRB     func() *v3.GlobalRoleBinding
	newGRB     func() *v3.GlobalRoleBinding
	username   string
}

var (
	errServer = fmt.Errorf("server not available")
	ruleAdmin = rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{ruleAdmin},
	}
	baseCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	clusterRoles = []*rbacv1.ClusterRole{adminCR, baseCR}

	clusterRoleBindings = []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: adminCR.Name},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-crb",
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     baseCR.Name,
			},
			Subjects: []rbacv1.Subject{
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
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	clusterOwnerRT = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-owner",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"*",
				},
				Resources: []string{
					"*",
				},
				Verbs: []string{
					"*",
				},
			},
		},
	}
	baseGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{baseRT.Name},
		InheritedFleetWorkspacePermissions: &v3.FleetWorkspacePermission{
			ResourceRules:  fwResourceRules,
			WorkspaceVerbs: fwWorkspaceVerbs,
		},
	}
	adminGR = &v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName: "Admin Role",
		Rules:       []rbacv1.PolicyRule{ruleAdmin},
		Builtin:     true,
	}
	baseGRB = v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-grb",
		},
		GlobalRoleName: baseGR.Name,
		UserName:       testUser,
	}
	restrictedAdminGRB = v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "res-grb",
		},
		GlobalRoleName: restrictedAdminGR.Name,
		UserName:       restrictedAdminUser,
	}
	adminRT = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "escalation-rt",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"*"},
			},
		},
	}

	lockedRT = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-rt",
		},
		Locked: true,
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	adminClusterGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-cluster-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			adminRT.Name,
		},
	}
	lockedRoleGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			lockedRT.Name,
		},
	}
	notFoundRoleGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-found-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			"not-found",
		},
	}
	errorRoleGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			errName,
		},
	}
	namespacedRulesGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespacedRules-gr",
		},
		NamespacedRules: map[string][]rbacv1.PolicyRule{
			"ns1": {
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
					Verbs:     []string{"*"},
				},
			},
		},
	}
	restrictedAdminGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restricted-admin",
		},
	}
	fwResourceRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"fleet.cattle.io"},
			Resources: []string{"gitrepos"},
			Verbs:     []string{"get"},
		},
	}
	fwWorkspaceVerbs     = []string{"GET"}
	fwResourceRulesAdmin = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		},
	}
	fwWorkspaceVerbsAdmin = []string{"*"}
	fwGR                  = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespacedRules-gr",
		},
		InheritedFleetWorkspacePermissions: &v3.FleetWorkspacePermission{
			ResourceRules:  fwResourceRules,
			WorkspaceVerbs: fwWorkspaceVerbs,
		},
	}
	fwGRResourceRulesAdmin = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespacedRules-gr",
		},
		InheritedFleetWorkspacePermissions: &v3.FleetWorkspacePermission{
			ResourceRules:  fwResourceRulesAdmin,
			WorkspaceVerbs: fwWorkspaceVerbs,
		},
	}
	fwGRWorkspaceVerbsAdmin = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespacedRules-gr",
		},
		InheritedFleetWorkspacePermissions: &v3.FleetWorkspacePermission{
			ResourceRules:  fwResourceRules,
			WorkspaceVerbs: fwWorkspaceVerbsAdmin,
		},
	}
)

// createGRBRequest will return a new webhookRequest using the given GRBs
// if oldGRB is nil then a request will be returned as a create operation.
// if newGRB is nil then a request will be returned as a delete operation.
// else the request will look like an update operation.
// if the test.args.username is empty testUser will be used.
func createGRBRequest(t *testing.T, test testCase) *admission.Request {
	t.Helper()
	username := test.args.username
	if username == "" {
		username = testUser
	}
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRoleBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalrolebindings"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       v1.Create,
			UserInfo:        v1authentication.UserInfo{Username: username, UID: "", Extra: map[string]v1authentication.ExtraValue{"test": []string{"test"}}},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	var oldGRB, newGRB *v3.GlobalRoleBinding

	if test.args.newGRB != nil {
		newGRB = test.args.newGRB()
	}
	if test.args.oldGRB != nil {
		oldGRB = test.args.oldGRB()
	}
	if oldGRB != nil {
		req.Operation = v1.Update
		req.Name = oldGRB.Name
		req.Namespace = oldGRB.Namespace
		req.OldObject.Raw, err = json.Marshal(oldGRB)
		assert.NoError(t, err, "Failed to marshal GRB while creating request")
	}
	if newGRB != nil {
		req.Name = newGRB.Name
		req.Namespace = newGRB.Namespace
		req.Object.Raw, err = json.Marshal(newGRB)
		assert.NoError(t, err, "Failed to marshal GRB while creating request")
	} else {
		req.Operation = v1.Delete
	}

	return req
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
	grbCacheMock.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey(restrictedAdminUser, "")).Return([]*v3.GlobalRoleBinding{&restrictedAdminGRB}, nil).AnyTimes()

	grbCacheMock.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()
	grCacheMock.EXPECT().Get(baseGR.Name).Return(&baseGR, nil).AnyTimes()
	grCacheMock.EXPECT().Get(restrictedAdminGR.Name).Return(&restrictedAdminGR, nil).AnyTimes()
	grCacheMock.EXPECT().Get(adminGR.Name).Return(adminGR, nil).AnyTimes()
	grCacheMock.EXPECT().Get(notFoundName).Return(nil, newNotFound(notFoundName)).AnyTimes()
	grCacheMock.EXPECT().Get("").Return(nil, newNotFound("")).AnyTimes()
	rtCacheMock.EXPECT().Get(baseRT.Name).Return(&baseRT, nil).AnyTimes()
	rtCacheMock.EXPECT().Get(clusterOwnerRT.Name).Return(&clusterOwnerRT, nil).AnyTimes()

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

func newDefaultGRB() *v3.GlobalRoleBinding {
	return &v3.GlobalRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalRoleBinding", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "grb-new",
			GenerateName:      "grb-",
			Namespace:         "g-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		UserName:       "user1",
		GlobalRoleName: "admin-role",
	}
}

func newNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "globalRole"}, name)
}
