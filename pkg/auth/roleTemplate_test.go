package auth_test

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	wranglerv1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const invalidName = "bad-template-name"

type Rules []rbacv1.PolicyRule

func (r Rules) Len() int      { return len(r) }
func (r Rules) Swap(i, j int) { r[i], r[j] = r[j], r[i] }
func (r Rules) Less(i, j int) bool {
	iData, _ := json.Marshal(r[i])
	jData, _ := json.Marshal(r[j])
	return string(iData) < string(jData)
}

// Equal check if to list of policy rules are equal ignoring rule order, but not duplicates.
func (r Rules) Equal(r2 Rules) bool {
	if r == nil && r2 == nil {
		return true
	}
	if r == nil || r2 == nil {
		return false
	}
	if r.Len() != r2.Len() {
		return false
	}
	// sort the list since we don't care about rule order
	sort.Stable(r)
	sort.Stable(r2)

	for i := range r {
		if !reflect.DeepEqual(r[i], r2[i]) {
			return false
		}
	}
	return true
}

type RoleTemplateResolverSuite struct {
	suite.Suite
	adminRT                      *apisv3.RoleTemplate
	readNodesRT                  *apisv3.RoleTemplate
	writeNodesRT                 *apisv3.RoleTemplate
	inheritedRT                  *apisv3.RoleTemplate
	externalClusterRT            *apisv3.RoleTemplate
	externalProjectRT            *apisv3.RoleTemplate
	externalNoContextRT          *apisv3.RoleTemplate
	invalidInheritedRT           *apisv3.RoleTemplate
	externalClusterInheritedRT   *apisv3.RoleTemplate
	externalProjectInheritedRT   *apisv3.RoleTemplate
	externalNoContextInheritedRT *apisv3.RoleTemplate

	readPodCR     *rbacv1.ClusterRole
	readServiceCR *rbacv1.ClusterRole
	writeNodeCR   *rbacv1.ClusterRole
}

func TestRoleTemplateResolver(t *testing.T) {
	suite.Run(t, new(RoleTemplateResolverSuite))
}

func (r *RoleTemplateResolverSuite) SetupSuite() {
	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	ruleReadServices := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"services"},
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
	r.readPodCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "read-pods"},
		Rules:      []rbacv1.PolicyRule{ruleReadPods},
	}
	r.readServiceCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "read-services"},
		Rules:      []rbacv1.PolicyRule{ruleReadServices},
	}
	r.writeNodeCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "write-nodes"},
		Rules:      []rbacv1.PolicyRule{ruleWriteNodes},
	}

	r.readNodesRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods},
		Context:     "cluster",
	}
	r.writeNodesRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "write-role",
		},
		DisplayName:       "Read Role",
		Rules:             []rbacv1.PolicyRule{ruleWriteNodes},
		RoleTemplateNames: []string{r.readNodesRT.Name},
		Context:           "cluster",
	}
	r.adminRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName:    "Admin Role",
		Rules:          []rbacv1.PolicyRule{ruleAdmin},
		Builtin:        true,
		Administrative: true,
		Context:        "cluster",
	}
	r.externalClusterRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.readPodCR.Name,
		},
		DisplayName: "External Cluster Role",
		Context:     "cluster",
		External:    true,
	}
	r.externalProjectRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.readServiceCR.Name,
		},
		DisplayName: "External Project Role",
		Context:     "project",
		External:    true,
	}
	r.externalNoContextRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.writeNodeCR.Name,
		},
		DisplayName: "External No Context Role",
		Context:     "",
		External:    true,
	}

	r.inheritedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "inherited-role",
		},
		DisplayName:       "Inherited Role",
		Locked:            true,
		Context:           "cluster",
		RoleTemplateNames: []string{r.writeNodesRT.Name},
	}
	r.externalClusterInheritedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "external-cluster-inherited-role",
		},
		DisplayName: "External Cluster Inherited Role",
		Context:     "cluster",
		RoleTemplateNames: []string{
			r.externalClusterRT.Name,
			r.externalProjectRT.Name,
			r.externalNoContextRT.Name,
		},
	}
	r.externalProjectInheritedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "external-project-inherited-role",
		},
		DisplayName: "External Project Inherited Role",
		Context:     "project",
		RoleTemplateNames: []string{
			r.externalClusterRT.Name,
			r.externalProjectRT.Name,
			r.externalNoContextRT.Name,
		},
	}
	r.externalNoContextInheritedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "external-no-context-inherited-role",
		},
		DisplayName: "External No Context Inherited Role",
		Context:     "",
		RoleTemplateNames: []string{
			r.externalClusterRT.Name,
			r.externalProjectRT.Name,
			r.externalNoContextRT.Name,
		},
	}
	r.invalidInheritedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-inherited-role",
		},
		DisplayName:       "Inherited Role",
		Locked:            true,
		Context:           "cluster",
		RoleTemplateNames: []string{invalidName},
	}
}

func (r *RoleTemplateResolverSuite) TestRoleTemplateResolver() {
	type args struct {
		name   string
		caches func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache)
	}
	tests := []struct {
		name    string
		args    args
		want    Rules
		wantErr bool
	}{
		// Base Get simple role
		{
			name: "Test simple Role Template",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.adminRT.Name).Return(r.adminRT, nil).AnyTimes()
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.adminRT.Name,
			},
			want:    r.adminRT.Rules,
			wantErr: false,
		},
		// Get double inherited
		{
			name: "Test inherited Role Templates",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.inheritedRT.Name).Return(r.inheritedRT, nil)
					roleTemplateCache.EXPECT().Get(r.readNodesRT.Name).Return(r.readNodesRT, nil)
					roleTemplateCache.EXPECT().Get(r.writeNodesRT.Name).Return(r.writeNodesRT, nil)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.inheritedRT.Name,
			},
			want:    append(r.inheritedRT.Rules, append(r.readNodesRT.Rules, r.writeNodesRT.Rules...)...),
			wantErr: false,
		},
		// Get external cluster role
		{
			name: "Test external cluster role",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.externalClusterRT.Name).Return(r.externalClusterRT, nil)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					clusterRoleCache.EXPECT().Get(r.readPodCR.Name).Return(r.readPodCR, nil)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.externalClusterRT.Name,
			},
			want:    r.readPodCR.Rules,
			wantErr: false,
		},
		// Get external project role
		{
			name: "Test external project role",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.externalProjectRT.Name).Return(r.externalProjectRT, nil)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					clusterRoleCache.EXPECT().Get(r.readServiceCR.Name).Return(r.readServiceCR, nil)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.externalProjectRT.Name,
			},
			want:    r.readServiceCR.Rules,
			wantErr: false,
		},
		// Get external no context role
		{
			name: "Test external no context role",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.externalNoContextRT.Name).Return(r.externalNoContextRT, nil)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					clusterRoleCache.EXPECT().Get(r.writeNodeCR.Name).Return(r.writeNodeCR, nil)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.externalNoContextRT.Name,
			},
			want:    r.writeNodeCR.Rules,
			wantErr: false,
		},
		// Get inherited from an external cluster role
		{
			name: "Test external cluster inherited role",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.externalClusterRT.Name).Return(r.externalClusterRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalProjectRT.Name).Return(r.externalProjectRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalNoContextRT.Name).Return(r.externalNoContextRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalClusterInheritedRT.Name).Return(r.externalClusterInheritedRT, nil)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					clusterRoleCache.EXPECT().Get(r.readPodCR.Name).Return(r.readPodCR, nil)
					clusterRoleCache.EXPECT().Get(r.readServiceCR.Name).Return(r.readServiceCR, nil)
					clusterRoleCache.EXPECT().Get(r.writeNodeCR.Name).Return(r.writeNodeCR, nil)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.externalClusterInheritedRT.Name,
			},
			want:    append(r.readPodCR.Rules, append(r.readServiceCR.Rules, r.writeNodeCR.Rules...)...),
			wantErr: false,
		},
		// Get inherited from an external project role
		{
			name: "Test external project inherited role",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.externalClusterRT.Name).Return(r.externalClusterRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalProjectRT.Name).Return(r.externalProjectRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalNoContextRT.Name).Return(r.externalNoContextRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalProjectInheritedRT.Name).Return(r.externalProjectInheritedRT, nil)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					clusterRoleCache.EXPECT().Get(r.readPodCR.Name).Return(r.readPodCR, nil)
					clusterRoleCache.EXPECT().Get(r.readServiceCR.Name).Return(r.readServiceCR, nil)
					clusterRoleCache.EXPECT().Get(r.writeNodeCR.Name).Return(r.writeNodeCR, nil)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.externalProjectInheritedRT.Name,
			},
			want:    append(r.readPodCR.Rules, append(r.readServiceCR.Rules, r.writeNodeCR.Rules...)...),
			wantErr: false,
		},
		// Get inherited from an external no context role
		{
			name: "Test external no context inherited role",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.externalClusterRT.Name).Return(r.externalClusterRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalProjectRT.Name).Return(r.externalProjectRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalNoContextRT.Name).Return(r.externalNoContextRT, nil)
					roleTemplateCache.EXPECT().Get(r.externalNoContextInheritedRT.Name).Return(r.externalNoContextInheritedRT, nil)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					clusterRoleCache.EXPECT().Get(r.readPodCR.Name).Return(r.readPodCR, nil)
					clusterRoleCache.EXPECT().Get(r.readServiceCR.Name).Return(r.readServiceCR, nil)
					clusterRoleCache.EXPECT().Get(r.writeNodeCR.Name).Return(r.writeNodeCR, nil)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.externalNoContextInheritedRT.Name,
			},
			want:    append(r.readPodCR.Rules, append(r.readServiceCR.Rules, r.writeNodeCR.Rules...)...),
			wantErr: false,
		},
		// Get unknown role
		{
			name: "Test invalid template name",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(invalidName).Return(nil, errExpected)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					return roleTemplateCache, clusterRoleCache
				},
				name: invalidName,
			},
			want:    nil,
			wantErr: true,
		},
		// get unknown inherited role
		{
			name: "Test invalid inherited template name",
			args: args{
				caches: func() (v3.RoleTemplateCache, wranglerv1.ClusterRoleCache) {
					ctrl := gomock.NewController(r.T())
					roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
					roleTemplateCache.EXPECT().Get(r.invalidInheritedRT.Name).Return(r.invalidInheritedRT, nil)
					roleTemplateCache.EXPECT().Get(invalidName).Return(nil, errExpected)
					clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
					return roleTemplateCache, clusterRoleCache
				},
				name: r.invalidInheritedRT.Name,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for i := range tests {
		test := tests[i]
		r.Run(test.name, func() {
			r.T().Parallel()
			resolver := auth.NewRoleTemplateResolver(test.args.caches())

			got, err := resolver.RulesFromTemplateName(test.args.name)
			if test.wantErr {
				r.Error(err, "expected tests to have error.")
			} else {
				r.NoError(err, "unexpected err in test.")
			}
			if !test.want.Equal(got) {
				r.Fail("List of rules did not match", "wanted=%+v got=%+v", test.want, got)
			}
		})
	}
}

func (r *RoleTemplateResolverSuite) TestGetCache() {
	ctrl := gomock.NewController(r.T())
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	resolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	r.Equal(resolver.RoleTemplateCache(), roleTemplateCache, "Resolver did not correctly return cache")
}
