package roletemplate_test

import (
	"encoding/json"

	jsonpatch "github.com/evanphx/json-patch"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/roletemplate"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
)

func (r *RoleTemplateSuite) TestMutator_Admit() {
	mutator := &roletemplate.Mutator{}
	tests := []tableTest{
		{
			name: "no annotations set",
			args: args{
				username: adminUser,
				newRT: func() *v3.RoleTemplate {
					obj := newDefaultRT()
					obj.Annotations = map[string]string{}
					return obj
				},
			},
			wantRT: func() *v3.RoleTemplate {
				obj := newDefaultRT()
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
				newRT: func() *v3.RoleTemplate {
					obj := newDefaultRT()
					obj.Annotations = map[string]string{
						"cleanup.cattle.io/rtUpgradeCluster": "true",
					}
					return obj
				},
			},
			wantRT:  nil,
			allowed: true,
		},
		{
			name: "annotation is nil",
			args: args{
				username: adminUser,
				newRT: func() *v3.RoleTemplate {
					obj := newDefaultRT()
					obj.Annotations = nil
					return obj
				},
			},
			wantRT: func() *v3.RoleTemplate {
				obj := newDefaultRT()
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
		r.Run(test.name, func() {
			req := createRTRequest(r.T(), nil, test.args.newRT(), test.args.username)
			resp, err := mutator.Admit(req)
			if test.wantError {
				r.Error(err, "expected error from Admit")
				return
			}
			r.Require().NoError(err, "Admit failed")
			r.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
			if test.wantRT == nil {
				r.Empty(resp.Patch, "unexpected patch returned")
				return
			}
			patchObj, err := jsonpatch.DecodePatch(resp.Patch)
			r.Require().NoError(err, "failed to decode patch from response")

			patchedJS, err := patchObj.Apply(req.Object.Raw)
			r.Require().NoError(err, "failed to apply patch to Object")

			gotObj := &v3.RoleTemplate{}
			err = json.Unmarshal(patchedJS, gotObj)
			r.Require().NoError(err, "failed to unmarshall patched Object")

			r.True(equality.Semantic.DeepEqual(test.wantRT(), gotObj), "patched object and desired object are not equivalent wanted=%#v got=%#v", test.wantRT(), gotObj)

		})
	}
}
func (r *RoleTemplateSuite) Test_MutatorErrorHandling() {
	mutator := &roletemplate.Mutator{}

	req := createRTRequest(r.T(), newDefaultRT(), newDefaultRT(), testUser)
	req.Object = runtime.RawExtension{}
	_, err := mutator.Admit(req)
	r.Error(err, "Admit should fail on bad request object")
}
