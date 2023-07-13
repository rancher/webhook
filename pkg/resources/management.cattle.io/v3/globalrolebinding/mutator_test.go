package globalrolebinding_test

import (
	"encoding/json"
	"errors"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrolebinding"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (g *GlobalRoleBindingSuite) Test_MutatorCreate() {
	const adminUser = "admin-userid"
	const notFoundGlobalRoleName = "not-found-globalRole"
	const errorGlobalRoleName = "err-globalRole"
	var ergRest = errors.New("bad error")

	ctrl := gomock.NewController(g.T())
	globalRoleCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.GlobalRole](ctrl)
	globalRoleCache.EXPECT().Get(g.adminGR.Name).Return(g.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()
	globalRoleCache.EXPECT().Get(errorGlobalRoleName).Return(nil, ergRest).AnyTimes()

	validator := globalrolebinding.NewMutator(globalRoleCache)

	tests := []tableTest{
		{
			name: "base test valid GRB",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = g.adminGR.Name
					baseGRB.Annotations = nil
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.Annotations = map[string]string{
					"cleanup.cattle.io/grbUpgradeCluster": "true",
				}
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: g.adminGR.APIVersion,
						Kind:       g.adminGR.Kind,
						Name:       g.adminGR.Name,
						UID:        g.adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "not found global role",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "failed Global Role get",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = errorGlobalRoleName
					return baseGRB
				},
			},
			wantError: true,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			req := createGRBRequest(g.T(), nil, test.args.newGRB(), test.args.username)
			resp, err := validator.Admit(req)
			if test.wantError {
				g.Error(err, "expected error from Admit")
				return
			}
			g.Require().NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
			if test.wantGRB != nil {
				patchObj, err := jsonpatch.DecodePatch(resp.Patch)
				g.Require().NoError(err, "failed to decode patch from response")

				patchedJS, err := patchObj.Apply(req.Object.Raw)
				g.Require().NoError(err, "failed to apply patch to Object")

				gotObj := &apisv3.GlobalRoleBinding{}
				err = json.Unmarshal(patchedJS, gotObj)
				g.Require().NoError(err, "failed to unmarshall patched Object")

				g.True(equality.Semantic.DeepEqual(test.wantGRB(), gotObj), "patched object and desired object are not equivalent wanted=%#v got=%#v", test.wantGRB(), gotObj)
			}
		})
	}
}

func (g *GlobalRoleBindingSuite) Test_MutatorErrorHandling() {
	mutator := &globalrolebinding.Mutator{}

	req := createGRBRequest(g.T(), newDefaultGRB(), newDefaultGRB(), testUser)
	req.Object = runtime.RawExtension{}
	_, err := mutator.Admit(req)
	g.Error(err, "Admit should fail on bad request object")
}
