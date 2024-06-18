package roletemplate_test

import (
	"fmt"
	"strconv"
	"time"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/roletemplate"
	"github.com/rancher/wrangler/pkg/generic/fake"
	v1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	circleRoleTemplateName   = "circleRef"
	adminUser                = "admin-userid"
	testUser                 = "test-userid"
	noPrivUser               = "no-priv-userid"
	notFoundRoleTemplateName = "not-found-roleTemplate"
	expectedIndexerName      = "management.cattle.io/rt-by-reference"
)

func (r *RoleTemplateSuite) Test_PrivilegeEscalation() {
	clusterRoles := []*rbacv1.ClusterRole{r.adminCR, r.manageNodeRole}

	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: r.adminCR.Name},
		},
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: testUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: r.manageNodeRole.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(r.T())

	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any()).AnyTimes()
	roleTemplateCache.EXPECT().Get(r.adminRT.Name).Return(r.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(r.readNodesRT.Name).Return(r.readNodesRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(notFoundRoleTemplateName).Return(nil, newNotFound(notFoundRoleTemplateName)).AnyTimes()
	roleTemplateCache.EXPECT().List(gomock.Any()).Return([]*v3.RoleTemplate{r.adminRT, r.readNodesRT}, nil).AnyTimes()

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		spec := review.Spec
		if spec.User == noPrivUser {
			return true, nil, fmt.Errorf("expected error")
		}

		review.Status.Allowed = spec.User == testUser &&
			spec.ResourceAttributes.Verb == "escalate"
		return true, review, nil
	})

	tests := []tableTest{
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.adminCR.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: true,
		},

		{
			name: "binding to equal privilege level",
			args: args{
				username: testUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: true,
		},

		{
			name: "privilege escalation denied",
			args: args{
				username: noPrivUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.adminCR.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: false,
		},

		{
			name: "privilege escalation with escalate",
			args: args{
				username: testUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.adminCR.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: true,
		},

		{
			name: "inherited privileges check",
			args: args{
				username: noPrivUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = nil
					baseRT.RoleTemplateNames = []string{r.readNodesRT.Name}
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: false,
		},
		{
			name: "user with escalate permissions can create external RoleTemplates with externalRules",
			args: args{
				username: testUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.External = true
					baseRT.ExternalRules = r.manageNodeRole.Rules

					return baseRT
				},
			},
			stateSetup: func(state testState) {
				state.featureCacheMock.EXPECT().Get(auth.ExternalRulesFeature).Return(&v3.Feature{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: v3.FeatureSpec{
						Value: &[]bool{true}[0],
					},
				}, nil)
			},
			allowed: true,
		},
		{
			name: "user without escalate permissions can't create external RoleTemplates with externalRules",
			args: args{
				username: noPrivUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.External = true
					baseRT.ExternalRules = r.manageNodeRole.Rules

					return baseRT
				},
			},
			stateSetup: func(state testState) {
				state.featureCacheMock.EXPECT().Get(auth.ExternalRulesFeature).Return(&v3.Feature{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: v3.FeatureSpec{
						Value: &[]bool{true}[0],
					},
				}, nil)
			},
			allowed: false,
		},
		{
			name: "user without escalate permissions can't create external RoleTemplates with externalRules when the feature flag is off",
			args: args{
				username: noPrivUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.External = true
					baseRT.ExternalRules = r.manageNodeRole.Rules

					return baseRT
				},
			},
			stateSetup: func(state testState) {
				state.featureCacheMock.EXPECT().Get(auth.ExternalRulesFeature).Return(&v3.Feature{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: v3.FeatureSpec{
						Value: &[]bool{false}[0],
					},
				}, nil)
				state.clusterRoleCacheMock.EXPECT().Get(newDefaultRT().Name).Return(&rbacv1.ClusterRole{}, nil)
			},
			allowed: false,
		},
		{
			name: "user without escalate permissions can't update external RoleTemplates with externalRules",
			args: args{
				username: noPrivUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()

					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.External = true
					baseRT.ExternalRules = r.manageNodeRole.Rules

					return baseRT
				},
			},
			stateSetup: func(state testState) {
				state.featureCacheMock.EXPECT().Get(auth.ExternalRulesFeature).Return(&v3.Feature{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: v3.FeatureSpec{
						Value: &[]bool{true}[0],
					},
				}, nil)
			},
			allowed: false,
		},
		{
			name: "user with escalate permissions ca update external RoleTemplates with externalRules",
			args: args{
				username: testUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()

					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.External = true
					baseRT.ExternalRules = r.manageNodeRole.Rules

					return baseRT
				},
			},
			stateSetup: func(state testState) {
				state.featureCacheMock.EXPECT().Get(auth.ExternalRulesFeature).Return(&v3.Feature{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: v3.FeatureSpec{
						Value: &[]bool{true}[0],
					},
				}, nil)
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		r.Run(test.name, func() {
			r.T().Parallel()
			featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
			clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)

			state := testState{
				clusterRoleCacheMock: clusterRoleCache,
				featureCacheMock:     featureCache,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache, state.featureCacheMock)
			validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)
			admitters := validator.Admitters()
			r.Len(admitters, 1, "wanted only one admitter")
			req := createRTRequest(r.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			resp, err := admitters[0].Admit(req)
			if r.NoError(err, "Admit failed") {
				r.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (r *RoleTemplateSuite) Test_UpdateValidation() {
	clusterRoles := []*rbacv1.ClusterRole{r.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: r.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(r.T())
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any())
	roleTemplateCache.EXPECT().Get(r.adminRT.Name).Return(r.adminRT, nil).AnyTimes()
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache, featureCache)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		if review.Spec.User == noPrivUser {
			return true, review, fmt.Errorf("expected error")
		}

		return true, review, nil
	})

	validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)
	admitters := validator.Admitters()
	r.Len(admitters, 1, "wanted only one admitter")

	tests := []tableTest{
		{
			name: "base test valid RT annotation update",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Annotations = nil
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Annotations = map[string]string{"foo": "bar"}
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update displayName",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.DisplayName = "old display"
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.DisplayName = "new display"
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update displayName with builtin set to true",
			args: args{
				username: testUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.DisplayName = "old display"
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.DisplayName = "new display"
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update custerCreatorDefault with builtin set to true",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.ClusterCreatorDefault = true
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.ClusterCreatorDefault = false
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update projectCreatorDefault with builtin set to true",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.ProjectCreatorDefault = true
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.ProjectCreatorDefault = false
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update locked with builtin set to true",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Locked = false
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Locked = true
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update annotation of builtin",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Builtin = true
					baseRT.Annotations = nil
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Builtin = true
					baseRT.Annotations = map[string]string{"foo": "bar"}
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update Builtin field from true to false",
			args: args{
				username: testUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = false
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update Builtin field from false to true",
			args: args{
				username: testUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = false
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{r.ruleEmptyVerbs}
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{r.ruleEmptyVerbs}
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update Administrative of cluster context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Context = "cluster"
					baseRT.Administrative = false
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Context = "cluster"
					baseRT.Administrative = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update Administrative of non cluster context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Context = "project"
					baseRT.Administrative = false
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Context = "project"
					baseRT.Administrative = true
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules being deleted",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{r.ruleEmptyVerbs}
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{r.ruleEmptyVerbs}
					baseRT.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return baseRT
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		r.Run(test.name, func() {
			r.T().Parallel()
			req := createRTRequest(r.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			resp, err := admitters[0].Admit(req)
			if r.NoError(err, "Admit failed") {
				r.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (r *RoleTemplateSuite) Test_Create() {
	clusterRoles := []*rbacv1.ClusterRole{r.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: r.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(r.T())
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any()).AnyTimes()
	roleTemplateCache.EXPECT().Get(r.adminRT.Name).Return(r.adminRT, nil).AnyTimes()

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

	tests := []tableTest{
		{
			name: "base test valid RT",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "missing rule verbs",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{r.ruleEmptyVerbs}
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "unknown context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Context = "namespace"
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "project context with administrative",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = r.manageNodeRole.Rules
					baseRT.Administrative = true
					baseRT.Context = "namespace"
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "create new builtIn RoleTemplate",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "create new external RoleTemplate when feature flag is off",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					rt := newDefaultRT()
					rt.External = true
					return rt
				},
			},
			stateSetup: func(state testState) {
				state.featureCacheMock.EXPECT().Get(auth.ExternalRulesFeature).Return(&v3.Feature{
					Spec: v3.FeatureSpec{
						Value: &[]bool{false}[0],
					},
				}, nil)
				state.clusterRoleCacheMock.EXPECT().Get("rt-new").Return(&rbacv1.ClusterRole{}, nil)
			},
			allowed: true,
		},
		{
			name: "create new external RoleTemplate when feature flag is off, context is project and backing ClusterRole doesn't exist",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					rt := newDefaultRT()
					rt.External = true
					rt.Context = "project"
					return rt
				},
			},
			stateSetup: func(state testState) {
				state.featureCacheMock.EXPECT().Get(auth.ExternalRulesFeature).Return(&v3.Feature{
					Spec: v3.FeatureSpec{
						Value: &[]bool{false}[0],
					},
				}, nil)
			},
			allowed: true,
		},
		{
			name: "invalid external rules",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					rt := newDefaultRT()
					rt.External = true
					rt.ExternalRules = []rbacv1.PolicyRule{r.ruleEmptyVerbs}
					return rt
				},
			},
			allowed:   false,
			wantError: true,
		},
		{
			name: "ExternalRules can't be set in RoleTemplates with external=false",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					rt := newDefaultRT()
					rt.External = false
					rt.ExternalRules = r.manageNodeRole.Rules
					return rt
				},
			},
			allowed:   false,
			wantError: true,
		},
	}

	for i := range tests {
		test := tests[i]
		r.Run(test.name, func() {
			r.T().Parallel()
			featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
			clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
			state := testState{
				clusterRoleCacheMock: clusterRoleCache,
				featureCacheMock:     featureCache,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache, state.featureCacheMock)
			validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)
			admitters := validator.Admitters()
			r.Len(admitters, 1, "wanted only one admitter")

			req := createRTRequest(r.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			resp, err := admitters[0].Admit(req)

			r.NoError(err, "Admit failed")
			r.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (r *RoleTemplateSuite) Test_Delete() {
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

	tests := []struct {
		tableTest
		wantError      bool
		createResolver func(ctrl *gomock.Controller) *auth.RoleTemplateResolver
	}{
		{
			tableTest: tableTest{
				name: "test basic delete",
				args: args{
					username: adminUser,
					oldRT: func() *v3.RoleTemplate {
						return r.readNodesRT
					},
					newRT: func() *v3.RoleTemplate {
						return nil
					},
				},
				allowed: true,
			},
			createResolver: func(ctrl *gomock.Controller) *auth.RoleTemplateResolver {
				roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
				cacheIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, map[string]cache.IndexFunc{})
				roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any()).Do(func(name string, indexFunc func(rt *v3.RoleTemplate) ([]string, error)) {
					cacheIndexer.AddIndexers(map[string]cache.IndexFunc{name: func(obj interface{}) (strings []string, e error) {
						return indexFunc(obj.(*v3.RoleTemplate))
					}})
				})
				roleTemplateCache.EXPECT().GetByIndex(expectedIndexerName, gomock.Any()).DoAndReturn(func(indexName string, key string) ([]*v3.RoleTemplate, error) {
					objs, err := cacheIndexer.ByIndex(indexName, key)
					if err != nil {
						return nil, err
					}
					result := make([]*v3.RoleTemplate, 0, len(objs))
					for _, obj := range objs {
						result = append(result, obj.(*v3.RoleTemplate))
					}
					return result, nil
				})
				defaultRT := newDefaultRT()
				defaultRT.RoleTemplateNames = []string{r.adminRT.Name}
				cacheIndexer.Add(defaultRT)
				cacheIndexer.Add(r.readNodesRT)
				return auth.NewRoleTemplateResolver(roleTemplateCache, nil, nil)
			},
		},
		{
			tableTest: tableTest{
				name: "test inherited delete",
				args: args{
					username: adminUser,
					oldRT: func() *v3.RoleTemplate {
						return r.adminRT
					},
					newRT: func() *v3.RoleTemplate {
						return nil
					},
				},
				allowed: false,
			},

			createResolver: func(ctrl *gomock.Controller) *auth.RoleTemplateResolver {
				roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
				cacheIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, map[string]cache.IndexFunc{})
				roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any()).Do(func(name string, indexFunc func(rt *v3.RoleTemplate) ([]string, error)) {
					cacheIndexer.AddIndexers(map[string]cache.IndexFunc{name: func(obj interface{}) (strings []string, e error) {
						return indexFunc(obj.(*v3.RoleTemplate))
					}})
				})
				roleTemplateCache.EXPECT().GetByIndex(expectedIndexerName, gomock.Any()).DoAndReturn(func(indexName string, key string) ([]*v3.RoleTemplate, error) {
					objs, err := cacheIndexer.ByIndex(indexName, key)
					if err != nil {
						return nil, err
					}
					result := make([]*v3.RoleTemplate, 0, len(objs))
					for _, obj := range objs {
						result = append(result, obj.(*v3.RoleTemplate))
					}
					return result, nil
				})
				defaultRT := newDefaultRT()
				defaultRT.RoleTemplateNames = []string{r.adminRT.Name}
				defaultRT2 := newDefaultRT()
				defaultRT2.Name = "default2"
				defaultRT2.RoleTemplateNames = []string{r.adminRT.Name}
				cacheIndexer.Add(defaultRT)
				cacheIndexer.Add(defaultRT2)
				cacheIndexer.Add(r.readNodesRT)
				return auth.NewRoleTemplateResolver(roleTemplateCache, nil, nil)
			},
		},
		{
			tableTest: tableTest{
				name: "test fail to list templates",
				args: args{
					username: adminUser,
					oldRT: func() *v3.RoleTemplate {
						return r.adminRT
					},
					newRT: func() *v3.RoleTemplate {
						return nil
					},
				},
			},
			wantError: true,
			createResolver: func(ctrl *gomock.Controller) *auth.RoleTemplateResolver {
				roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
				roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any())
				roleTemplateCache.EXPECT().GetByIndex(expectedIndexerName, gomock.Any()).Return(nil, errTest)
				return auth.NewRoleTemplateResolver(roleTemplateCache, nil, nil)
			},
		},
	}

	for i := range tests {
		test := tests[i]
		r.Run(test.name, func() {
			r.T().Parallel()
			ctrl := gomock.NewController(r.T())
			validator := roletemplate.NewValidator(resolver, test.createResolver(ctrl), fakeSAR)
			req := createRTRequest(r.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			admitters := validator.Admitters()
			r.Len(admitters, 1, "wanted only one admitter")
			resp, err := admitters[0].Admit(req)
			if test.wantError {
				r.Error(err, "Admit expected an error")
				return
			}
			if !r.NoError(err, "Admit failed") {
				return
			}
			r.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (r *RoleTemplateSuite) Test_ErrorHandling() {
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	ctrl := gomock.NewController(r.T())
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any())
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache, featureCache)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)
	admitters := validator.Admitters()
	r.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	req := createRTRequest(r.T(), newDefaultRT(), newDefaultRT(), testUser)
	req.Operation = v1.Connect
	_, err := admitter.Admit(req)
	r.Error(err, "Admit should fail on unknown handled operations")

	req = createRTRequest(r.T(), newDefaultRT(), newDefaultRT(), testUser)
	req.Object = runtime.RawExtension{}
	_, err = admitter.Admit(req)

	r.Error(err, "Admit should fail on bad request object")

	newRT := newDefaultRT()
	newRT.RoleTemplateNames = []string{notFoundRoleTemplateName}
	roleTemplateCache.EXPECT().Get(notFoundRoleTemplateName).Return(nil, newNotFound(""))
	req = createRTRequest(r.T(), nil, newRT, testUser)
	_, err = admitter.Admit(req)
	r.Error(err, "Admit should fail on unknown inherited RoleTemplate")
}

func (r *RoleTemplateSuite) Test_CheckCircularRef() {
	clusterRoles := []*rbacv1.ClusterRole{r.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: r.adminCR.Name},
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
		r.Run(testCase.name, func() {
			rtName := "input-role"
			if testCase.circleDepth == 0 && testCase.hasCircularRef {
				rtName = circleRoleTemplateName
			}

			ctrl := gomock.NewController(r.T())
			roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			roleTemplateCache.EXPECT().Get(r.adminRT.Name).Return(r.adminRT, nil).AnyTimes()
			roleTemplateCache.EXPECT().AddIndexer(expectedIndexerName, gomock.Any())

			newRT := createNestedRoleTemplate(rtName, roleTemplateCache, testCase.depth, testCase.circleDepth, testCase.errorDepth)

			req := createRTRequest(r.T(), nil, newRT, adminUser)
			clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
			featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
			roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache, featureCache)

			validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)
			admitters := validator.Admitters()
			r.Len(admitters, 1, "wanted only one admitter")
			resp, err := admitters[0].Admit(req)
			if testCase.errDesired {
				r.Error(err, "circular reference check, expected err")
				return
			}
			r.NoError(err, "circular reference check, did not expect an err")

			if !testCase.hasCircularRef {
				r.True(resp.Allowed, "expected roleTemplate to be allowed")
				return
			}

			r.False(resp.Allowed, "expected roleTemplate to be denied")
			if r.NotNil(resp.Result, "expected response result to be set") {
				r.Contains(resp.Result.Message, circleRoleTemplateName, "response result does not contain circular RoleTemplate name.")
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
