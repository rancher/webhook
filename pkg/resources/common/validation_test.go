package common

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateRules(t *testing.T) {
	t.Parallel()

	gResource := "something-global"
	nsResource := "something-namespaced"

	gField := field.NewPath(gResource)
	nsField := field.NewPath(nsResource)

	tests := []struct {
		name   string            // label for testcase
		data   rbacv1.PolicyRule // policy rule to be validated
		haserr bool              // error expected ?
	}{
		{
			name: "ok",
			data: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"*"},
			},
		},
		{
			name: "no-verbs",
			data: rbacv1.PolicyRule{
				Verbs:     []string{},
				APIGroups: []string{""},
				Resources: []string{"*"},
			},
			haserr: true,
		},
		{
			name: "no-api-groups",
			data: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{},
				Resources: []string{"*"},
			},
			haserr: true,
		},
		{
			name: "no-resources",
			data: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{},
			},
			haserr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run("global/"+test.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateRules([]rbacv1.PolicyRule{
				test.data,
			}, false, gField)
			if test.haserr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
		t.Run("namespaced/"+test.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateRules([]rbacv1.PolicyRule{
				test.data,
			}, true, nsField)
			if test.haserr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCheckCreatorPrincipalName(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	userCache := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
	userCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(name string) (*v3.User, error) {
		switch name {
		case "u-12345":
			return &v3.User{
				ObjectMeta: metav1.ObjectMeta{
					Name: "u-12345",
				},
				PrincipalIDs: []string{"local://12345", "keycloak_user://12345"},
			}, nil
		case "u-error":
			return nil, fmt.Errorf("some error")
		default:
			return nil, apierrors.NewNotFound(schema.GroupResource{}, name)
		}
	}).AnyTimes()

	tests := []struct {
		desc          string
		creatorID     string
		principalName string
		fieldErr      bool
		err           bool
	}{
		{
			desc: "no principal name annotation",
		},
		{
			desc:          "creator id and principal name match",
			creatorID:     "u-12345",
			principalName: "keycloak_user://12345",
		},
		{
			desc:          "no creatorId annotation",
			principalName: "keycloak_user://12345",
			fieldErr:      true,
		},
		{
			desc:          "principal doesn't belong to creator",
			creatorID:     "u-12345",
			principalName: "keycloak_user://12346",
			fieldErr:      true,
		},
		{
			desc:          "creator user doesn't exist",
			creatorID:     "u-12346",
			principalName: "keycloak_user://12345",
			fieldErr:      true,
		},
		{
			desc:          "error getting creator user",
			creatorID:     "u-error",
			principalName: "keycloak_user://12345",
			err:           true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			annotations := map[string]string{}
			if test.creatorID != "" {
				annotations[CreatorIDAnn] = test.creatorID
			}
			if test.principalName != "" {
				annotations[CreatorPrincipalNameAnn] = test.principalName
			}

			fieldErr, err := CheckCreatorPrincipalName(userCache, &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
				},
			})
			require.Equal(t, test.fieldErr, fieldErr != nil)
			require.Equal(t, test.err, err != nil)
		})
	}
}

func TestCheckCreatorAnnotationsOnUpdate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc     string
		oldObj   metav1.Object
		newObj   metav1.Object
		fieldErr bool
	}{
		{
			desc:   "no annotations",
			oldObj: &v3.Project{},
			newObj: &v3.Project{},
		},
		{
			desc: "no change",
			oldObj: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						CreatorIDAnn:            "u-12345",
						CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			newObj: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						CreatorIDAnn:            "u-12345",
						CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
		},
		{
			desc: "annotations removed",
			oldObj: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						CreatorIDAnn:            "u-12345",
						CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			newObj: &v3.Project{},
		},
		{
			desc: "creator id changed",
			oldObj: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						CreatorIDAnn: "u-12345",
					},
				},
			},
			newObj: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						CreatorIDAnn: "u-12346",
					},
				},
			},
			fieldErr: true,
		},
		{
			desc: "principal name changed",
			oldObj: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			newObj: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						CreatorPrincipalNameAnn: "keycloak_user://12346",
					},
				},
			},
			fieldErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			fieldErr := CheckCreatorAnnotationsOnUpdate(test.oldObj, test.newObj)
			require.Equal(t, test.fieldErr, fieldErr != nil)
		})
	}
}
