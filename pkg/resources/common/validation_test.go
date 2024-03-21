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

	for _, testcase := range tests {
		t.Run("global/"+testcase.name, func(t *testing.T) {
			err := ValidateRules([]v1.PolicyRule{
				testcase.data,
			}, false, gField)
			if testcase.haserr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
		t.Run("namespaced/"+testcase.name, func(t *testing.T) {
			err := ValidateRules([]v1.PolicyRule{
				testcase.data,
			}, true, nsField)
			if testcase.haserr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
