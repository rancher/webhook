package common

import (
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateRules(t *testing.T) {
	t.Parallel()

	gResource := "something-global"
	nsResource := "something-namespaced"

	gField := field.NewPath(gResource)
	nsField := field.NewPath(nsResource)

	// Note: The partial error message is prefixed with the resource name during test execution
	tests := []struct {
		name string            // label for testcase
		data rbacv1.PolicyRule // policy rule to be validated
		err  string            // partial error returned for a resource,     empty string -> no error
	}{
		{
			name: "ok",
			data: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"*"},
			},
			err: "",
		},
		{
			name: "no-verbs",
			data: rbacv1.PolicyRule{
				Verbs:     []string{},
				APIGroups: []string{""},
				Resources: []string{"*"},
			},
			err: "[0].verbs: Required value: verbs must contain at least one value",
		},
		{
			name: "no-api-groups",
			data: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{},
				Resources: []string{"*"},
			},
			err: "[0].apiGroups: Required value: resource rules must supply at least one api group",
		},
		{
			name: "no-resources",
			data: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{},
			},
			err: "[0].resources: Required value: resource rules must supply at least one resource",
		},
	}

	for _, testcase := range tests {
		t.Run("global/"+testcase.name, func(t *testing.T) {
			err := ValidateRules([]v1.PolicyRule{
				testcase.data,
			}, false, gField)
			if testcase.err == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Equal(t, err.Error(), gResource+testcase.err)
		})
		t.Run("namespaced/"+testcase.name, func(t *testing.T) {
			err := ValidateRules([]v1.PolicyRule{
				testcase.data,
			}, true, nsField)
			if testcase.err == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Equal(t, err.Error(), nsResource+testcase.err)
		})
	}
}
