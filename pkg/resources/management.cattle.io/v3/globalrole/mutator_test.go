package globalrole_test

import (
	"encoding/json"

	jsonpatch "github.com/evanphx/json-patch"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrole"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
)

func (g *GlobalRoleSuite) TestMutator_Admit() {
	mutator := &globalrole.Mutator{}
	tests := []tableTest{
		{
			name: "no annotations set",
			args: args{
				username: adminUser,
				newGR: func() *v3.GlobalRole {
					obj := newDefaultGR()
					obj.Annotations = map[string]string{}
					return obj
				},
			},
			wantGR: func() *v3.GlobalRole {
				obj := newDefaultGR()
				obj.Annotations = map[string]string{
					"cleanup.cattle.io/rtUpgradeCluster": "true",
				}
				return obj
			},
			allowed: true,
		},
		{
			name: "annotations is set override",
			args: args{
				username: adminUser,
				newGR: func() *v3.GlobalRole {
					obj := newDefaultGR()
					obj.Annotations = map[string]string{
						"cleanup.cattle.io/rtUpgradeCluster": "true",
					}
					return obj
				},
			},
			wantGR:  nil,
			allowed: true,
		},
		{
			name: "annotation is nil",
			args: args{
				username: adminUser,
				newGR: func() *v3.GlobalRole {
					obj := newDefaultGR()
					obj.Annotations = nil
					return obj
				},
			},
			wantGR: func() *v3.GlobalRole {
				obj := newDefaultGR()
				obj.Annotations = map[string]string{
					"cleanup.cattle.io/rtUpgradeCluster": "true",
				}
				return obj
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			req := createGRRequest(g.T(), nil, test.args.newGR(), test.args.username)
			resp, err := mutator.Admit(req)
			if test.wantError {
				g.Error(err, "expected error from Admit")
				return
			}
			g.Require().NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
			if test.wantGR == nil {
				g.Empty(resp.Patch, "unexpected patch returned")
				return
			}
			patchObj, err := jsonpatch.DecodePatch(resp.Patch)
			g.Require().NoError(err, "failed to decode patch from response")

			patchedJS, err := patchObj.Apply(req.Object.Raw)
			g.Require().NoError(err, "failed to apply patch to Object")

			gotObj := &v3.GlobalRole{}
			err = json.Unmarshal(patchedJS, gotObj)
			g.Require().NoError(err, "failed to unmarshall patched Object")

			g.True(equality.Semantic.DeepEqual(test.wantGR(), gotObj), "patched object and desired object are not equivalent wanted=%#v got=%#v", test.wantGR(), gotObj)

		})
	}
}

func (g *GlobalRoleSuite) Test_MutatorErrorHandling() {
	mutator := &globalrole.Mutator{}

	req := createGRRequest(g.T(), newDefaultGR(), newDefaultGR(), testUser)
	req.Object = runtime.RawExtension{}
	_, err := mutator.Admit(req)
	g.Error(err, "Admit should fail on bad request object")
}
