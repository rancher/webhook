package resolvers

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
)

type GRBClusterRuleResolverSuite struct {
	suite.Suite
	userInfo           user.Info
	broUserInfo        user.Info
	broDefaultUserInfo user.Info
	fleetUserInfo      user.Info
	otherSAUserInfo    user.Info
	groupGRB           *v3.GlobalRoleBinding
	errorGroupGRB      *v3.GlobalRoleBinding
	userGRB            *v3.GlobalRoleBinding
	errorUserGRB       *v3.GlobalRoleBinding
	globalUserRules    []rbacv1.PolicyRule
	globalGroupRules   []rbacv1.PolicyRule
	userClusterRules   []rbacv1.PolicyRule
	groupClusterRules  []rbacv1.PolicyRule
}

func TestGRBClusterRuleResolver(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(GRBClusterRuleResolverSuite))
}

func (g *GRBClusterRuleResolverSuite) SetupSuite() {
	g.userInfo = NewUserInfo("test-user", "test-group")
	g.broUserInfo = NewUserInfo("system:serviceaccount:cattle-resources-system:rancher-backup", "system:serviceaccounts")
	g.broDefaultUserInfo = NewUserInfo("system:serviceaccount:default:rancher-backup", "system:serviceaccounts")
	g.fleetUserInfo = NewUserInfo("system:serviceaccount:cattle-fleet-local-system:fleet-agent", "system:serviceaccounts")
	g.otherSAUserInfo = NewUserInfo("system:serviceaccount:default:default", "system:serviceaccounts")
	g.groupGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-grb",
		},
		GlobalRoleName:     "group-gr",
		GroupPrincipalName: "test-group",
	}
	g.errorGroupGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-group-grb",
		},
		GlobalRoleName:     "error-group-gr",
		GroupPrincipalName: "test-group",
	}
	g.userGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user-grb",
		},
		GlobalRoleName: "user-gr",
		UserName:       "test-user",
	}
	g.errorUserGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-user-grb",
		},
		GlobalRoleName: "error-user-gr",
		UserName:       "test-user",
	}
	g.globalUserRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
	}
	g.globalGroupRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get"},
		},
	}

	g.userClusterRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get"},
		},
	}
	g.groupClusterRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"apps"},
			Resources: []string{"statefulsets"},
			Verbs:     []string{"get"},
		},
	}
}

func (g *GRBClusterRuleResolverSuite) TestGRBClusterRuleResolver() {
	type testState struct {
		grCache  *fake.MockNonNamespacedCacheInterface[*v3.GlobalRole]
		grbCache *fake.MockNonNamespacedCacheInterface[*v3.GlobalRoleBinding]
		rtCache  *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
		sar      *k8fake.FakeSubjectAccessReviews
	}

	tests := []struct {
		name      string
		userInfo  user.Info
		setup     func(state testState)
		namespace string
		wantRules []rbacv1.PolicyRule
		wantError bool
	}{
		{
			name:      "test rule resolution, valid + invalid user/group bindings",
			namespace: "",
			userInfo:  g.userInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB, g.errorUserGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB, g.errorGroupGRB}, nil)
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorUserGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
				state.grCache.EXPECT().Get(g.errorGroupGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
			},
			wantRules: append(g.userClusterRules, g.groupClusterRules...),
			wantError: true,
		},
		{
			name:      "test state resolution group indexer error",
			namespace: "",
			userInfo:  g.userInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB, g.errorUserGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return(nil, fmt.Errorf("server unavailable"))
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorUserGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))

			},
			wantRules: g.userClusterRules,
			wantError: true,
		},
		{
			name:      "test state resolution user indexer error",
			namespace: "",
			userInfo:  g.userInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return(nil, fmt.Errorf("server unavailable"))
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB, g.errorGroupGRB}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorGroupGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))

			},
			wantRules: g.groupClusterRules,
			wantError: true,
		},
		{
			name:      "test state resolution local cluster",
			namespace: "local",
			userInfo:  g.userInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB, g.errorUserGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB, g.errorGroupGRB}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorUserGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
				state.grCache.EXPECT().Get(g.errorGroupGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
			},

			wantRules: append(g.globalUserRules, g.globalGroupRules...),
			wantError: true,
		},
		{
			name:      "test state resolution non-local cluster",
			namespace: "not-local",
			userInfo:  g.userInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

			},

			wantRules: append(g.userClusterRules, g.groupClusterRules...),
			wantError: false,
		},
		{
			name:      "test state resolution no error, no namespace",
			namespace: "",
			userInfo:  g.userInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

			},

			wantRules: append(g.userClusterRules, g.groupClusterRules...),
			wantError: false,
		},
		{
			name:      "test backup-restore service account",
			namespace: "",
			userInfo:  g.broUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.broUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.broUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.broUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.broUserInfo.GetGroups()[0] {
						review.Status.Allowed = true
						return true, review, nil
					}
					return false, nil, nil
				})

			},

			wantRules: adminRules,
			wantError: false,
		},
		{
			name:      "test backup-restore service account, non-admin",
			namespace: "",
			userInfo:  g.broUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.broUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.broUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.broUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.broUserInfo.GetGroups()[0] {
						review.Status.Allowed = false
						return true, review, nil
					}
					return false, nil, nil
				})

			},

			wantRules: []rbacv1.PolicyRule{},
			wantError: false,
		},
		{
			name:      "test backup-restore service account, error when evaluting SAR",
			namespace: "",
			userInfo:  g.broUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.broUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.broUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.broUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.broUserInfo.GetGroups()[0] {
						return true, review, fmt.Errorf("unable to process request")
					}
					return false, nil, nil
				})

			},
			wantRules: []rbacv1.PolicyRule{},
			wantError: true,
		},
		{
			name:      "test backup-restore service account, nil SAR result",
			namespace: "",
			userInfo:  g.broUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.broUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.broUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.broUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.broUserInfo.GetGroups()[0] {
						return true, nil, nil
					}
					return false, nil, nil
				})

			},
			wantRules: []rbacv1.PolicyRule{},
			wantError: true,
		},
		{
			name:      "test fleet service account",
			namespace: "",
			userInfo:  g.fleetUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.fleetUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.fleetUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.fleetUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.fleetUserInfo.GetGroups()[0] {
						review.Status.Allowed = true
						return true, review, nil
					}
					return false, nil, nil
				})

			},

			wantRules: adminRules,
			wantError: false,
		},
		{
			name:      "test fleet service account, non-admin permissions",
			namespace: "",
			userInfo:  g.fleetUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.fleetUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.fleetUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.fleetUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.fleetUserInfo.GetGroups()[0] {
						review.Status.Allowed = false
						return true, review, nil
					}
					return false, nil, nil
				})

			},

			wantRules: []rbacv1.PolicyRule{},
			wantError: false,
		},
		{
			name:      "test fleet service account, error when processing SAR",
			namespace: "",
			userInfo:  g.fleetUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.fleetUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.fleetUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.fleetUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.fleetUserInfo.GetGroups()[0] {
						return true, review, fmt.Errorf("unable to process sar")
					}
					return false, nil, nil
				})

			},

			wantRules: []rbacv1.PolicyRule{},
			wantError: true,
		},
		{
			name:      "test fleet service account, nil SAR result",
			namespace: "",
			userInfo:  g.fleetUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.fleetUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.fleetUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.fleetUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.fleetUserInfo.GetGroups()[0] {
						return true, nil, nil
					}
					return false, nil, nil
				})

			},

			wantRules: []rbacv1.PolicyRule{},
			wantError: true,
		},

		{
			name:      "test bro default service account",
			namespace: "",
			userInfo:  g.broDefaultUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.broDefaultUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.broDefaultUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.sar.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
					createAction := action.(k8testing.CreateActionImpl)
					review := createAction.GetObject().(*v1.SubjectAccessReview)
					spec := review.Spec
					attributes := spec.ResourceAttributes
					isAdminPerm := attributes != nil && attributes.Group == rbacv1.APIGroupAll &&
						attributes.Resource == rbacv1.ResourceAll && attributes.Verb == rbacv1.VerbAll &&
						attributes.Version == rbacv1.APIGroupAll
					if isAdminPerm && spec.User == g.broDefaultUserInfo.GetName() && len(spec.Groups) == 1 && spec.Groups[0] == g.broDefaultUserInfo.GetGroups()[0] {
						review.Status.Allowed = true
						return true, review, nil
					}
					return false, nil, nil
				})

			},

			wantRules: adminRules,
			wantError: false,
		},

		{
			name:      "test other service account",
			namespace: "",
			userInfo:  g.otherSAUserInfo,
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.otherSAUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.otherSAUserInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{}, nil)
			},
			wantRules: []rbacv1.PolicyRule{},
			wantError: false,
		},
		{
			name:      "test backup-restore not in sa group",
			namespace: "",
			userInfo:  NewUserInfo(g.broUserInfo.GetName()),
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.broUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
			},
			wantRules: []rbacv1.PolicyRule{},
			wantError: false,
		},
		{
			name:      "test fleet not in sa group",
			namespace: "",
			userInfo:  NewUserInfo(g.fleetUserInfo.GetName()),
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.fleetUserInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{}, nil)
			},
			wantRules: []rbacv1.PolicyRule{},
			wantError: false,
		},
	}

	for _, test := range tests {
		test := test
		g.Run(test.name, func() {
			ctrl := gomock.NewController(g.T())
			grbCache := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRoleBinding](ctrl)
			grbCache.EXPECT().AddIndexer(grbSubjectIndex, gomock.Any()).AnyTimes()

			rtCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			grCache := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRole](ctrl)
			k8Fake := &k8testing.Fake{}
			fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

			state := testState{
				grCache:  grCache,
				grbCache: grbCache,
				rtCache:  rtCache,
				sar:      fakeSAR,
			}

			if test.setup != nil {
				test.setup(state)
			}

			grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCache, nil), state.grCache)
			grbResolver := NewGRBClusterRuleResolver(state.grbCache, grResolver, state.sar)

			rules, err := grbResolver.RulesFor(test.userInfo, test.namespace)
			g.Require().Len(rules, len(test.wantRules))
			for _, rule := range test.wantRules {
				g.Require().Contains(rules, rule)
			}
			if test.wantError {
				g.Require().Error(err)
			} else {
				g.Require().NoError(err)
			}
		})
	}
}

func (g *GRBClusterRuleResolverSuite) Test_grbSubjectIndexer() {
	tests := []struct {
		name        string
		grb         *v3.GlobalRoleBinding
		wantIndexes []string
		wantError   bool
	}{
		{
			name: "user key",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName: "test-user",
			},
			wantIndexes: []string{"user:test-user-"},
			wantError:   false,
		},
		{
			name: "group key",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				GroupPrincipalName: "test-group",
			},
			wantIndexes: []string{"group:test-group-"},
			wantError:   false,
		},
		{
			name: "user + group key",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:           "test-user",
				GroupPrincipalName: "test-group",
			},
			wantIndexes: []string{"user:test-user-"},
			wantError:   false,
		},
		{
			name: "no subject",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
			},
			wantIndexes: nil,
			wantError:   false,
		},
	}
	for _, test := range tests {
		test := test
		g.Run(test.name, func() {
			indexes, err := grbBySubject(test.grb)
			if test.wantError {
				g.Require().Error(err)
			} else {
				g.Require().NoError(err)
				g.Require().Len(indexes, len(test.wantIndexes))
				for _, index := range test.wantIndexes {
					g.Require().Contains(indexes, index)
				}
			}
		})
	}

}
