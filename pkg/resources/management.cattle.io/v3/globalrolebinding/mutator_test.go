package globalrolebinding_test

import (
	"encoding/json"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrolebinding"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func Test_MutatorAdmit(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	globalRoleCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.GlobalRole](ctrl)
	globalRoleCache.EXPECT().Get(adminGR.Name).Return(adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundName).Return(nil, newNotFound(notFoundName)).AnyTimes()
	globalRoleCache.EXPECT().Get(errName).Return(nil, errServer).AnyTimes()

	validator := globalrolebinding.NewMutator(globalRoleCache)

	tests := []testCase{
		{
			name: "base test valid GRB",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
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
					baseGRB.GlobalRoleName = notFoundName
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
					baseGRB.GlobalRoleName = errName
					return baseGRB
				},
			},
			wantError: true,
		},
		{
			name: "multiple owner references test valid GRB",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					baseGRB.OwnerReferences = []metav1.OwnerReference{
						{
							APIVersion: baseRT.APIVersion,
							Kind:       baseRT.Kind,
							Name:       baseRT.Name,
							UID:        baseRT.UID,
						},
					}
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: baseRT.APIVersion,
						Kind:       baseRT.Kind,
						Name:       baseRT.Name,
						UID:        baseRT.UID,
					},
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "similar owner references different Version",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					baseGRB.OwnerReferences = []metav1.OwnerReference{
						{
							APIVersion: "DifferentVersion",
							Kind:       adminGR.Kind,
							Name:       adminGR.Name,
							UID:        adminGR.UID,
						},
					}
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: "DifferentVersion",
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
					},
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "similar owner references different Name",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					baseGRB.OwnerReferences = []metav1.OwnerReference{
						{
							APIVersion: adminGR.APIVersion,
							Kind:       adminGR.Kind,
							Name:       "DifferentName",
							UID:        adminGR.UID,
						},
					}
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       "DifferentName",
						UID:        adminGR.UID,
					},
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "similar owner references different UID",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					baseGRB.OwnerReferences = []metav1.OwnerReference{
						{
							APIVersion: adminGR.APIVersion,
							Kind:       adminGR.Kind,
							Name:       adminGR.Name,
							UID:        "DifferentUID",
						},
					}
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        "DifferentUID",
					},
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "similar owner references different Controller",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					baseGRB.OwnerReferences = []metav1.OwnerReference{
						{
							APIVersion: adminGR.APIVersion,
							Kind:       adminGR.Kind,
							Name:       adminGR.Name,
							UID:        adminGR.UID,
							Controller: new(bool),
						},
					}
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
						Controller: new(bool),
					},
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "similar owner references different BlockOwnerDeletion",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					baseGRB.OwnerReferences = []metav1.OwnerReference{
						{
							APIVersion:         adminGR.APIVersion,
							Kind:               adminGR.Kind,
							Name:               adminGR.Name,
							UID:                adminGR.UID,
							BlockOwnerDeletion: new(bool),
						},
					}
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion:         adminGR.APIVersion,
						Kind:               adminGR.Kind,
						Name:               adminGR.Name,
						UID:                adminGR.UID,
						BlockOwnerDeletion: new(bool),
					},
					{
						APIVersion: adminGR.APIVersion,
						Kind:       adminGR.Kind,
						Name:       adminGR.Name,
						UID:        adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "duplicate owner references test valid GRB",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					baseGRB.Annotations = nil
					baseGRB.OwnerReferences = []metav1.OwnerReference{
						{
							APIVersion: adminGR.APIVersion,
							Kind:       adminGR.Kind,
							Name:       adminGR.Name,
							UID:        adminGR.UID,
						},
					}
					return baseGRB
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			req := createGRBRequest(t, test)
			resp, err := validator.Admit(req)
			if test.wantError {
				require.Error(t, err, "expected error from Admit")
				return
			}
			require.NoError(t, err, "Admit failed")
			require.Equalf(t, test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
			if test.wantGRB != nil {
				patchObj, err := jsonpatch.DecodePatch(resp.Patch)
				require.NoError(t, err, "failed to decode patch from response")

				patchedJS, err := patchObj.Apply(req.Object.Raw)
				require.NoError(t, err, "failed to apply patch to Object")

				gotObj := &apisv3.GlobalRoleBinding{}
				err = json.Unmarshal(patchedJS, gotObj)
				require.NoError(t, err, "failed to unmarshall patched Object")

				require.True(t, equality.Semantic.DeepEqual(test.wantGRB(), gotObj), "patched object and desired object are not equivalent wanted=%#v got=%#v", test.wantGRB(), gotObj)
			} else {
				require.Nil(t, resp.Patch, "unexpected patch request received")
			}
		})
	}
}

func Test_MutatorUnexpectedErrors(t *testing.T) {
	t.Parallel()
	mutator := &globalrolebinding.Mutator{}
	test := testCase{
		args: args{
			newGRB: newDefaultGRB,
			oldGRB: newDefaultGRB,
		},
	}
	req := createGRBRequest(t, test)
	req.Object = runtime.RawExtension{}
	_, err := mutator.Admit(req)
	require.Error(t, err, "Admit should fail on bad request object")
}
