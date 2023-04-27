package roletemplate

import (
	"strconv"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/mocks"
	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var defaultRules = []rbacv1.PolicyRule{
	{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "list", "watch"},
	},
}

var circleRoleTemplateName = "circleRef"

func TestCheckCircularRef(t *testing.T) {
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

	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			mockCache := mocks.NewMockRoleTemplateCache()
			rtName := "input-role"
			if testCase.circleDepth == 0 && testCase.hasCircularRef {
				rtName = circleRoleTemplateName
			}
			inputRole := createNestedRoleTemplate(rtName, mockCache, testCase.depth, testCase.circleDepth, testCase.errorDepth)
			validator := createValidator(mockCache)
			result, err := validator.checkCircularRef(inputRole)
			if testCase.errDesired {
				assert.NotNil(t, err, "checkCircularRef(), expected err but did not get an error")
			} else {
				assert.Nil(t, err, "checkCircularRef(), got error %v but did not expect an error", err)
			}
			if testCase.hasCircularRef {
				assert.NotNil(t, result, "checkCircularRef(), expected result but was nil")
				assert.Equal(t, circleRoleTemplateName, result.Name, "checkCircularRef(), expected roleTemplate with name %s but got %v", circleRoleTemplateName, result)
			} else {
				assert.Nil(t, result, "checkCircularRef(), expected result to be nil but was %v", result)
			}
		})
	}
}

func createNestedRoleTemplate(name string, cache *mocks.MockRoleTemplateCache, depth int, circleDepth int, errDepth int) *v3.RoleTemplate {
	start := createRoleTemplate(name, defaultRules)
	prior := start

	if depth == 0 && circleDepth == 0 {
		start.RoleTemplateNames = []string{start.Name}
		cache.Add(start)
	}
	for i := 0; i < depth; i++ {
		current := createRoleTemplate("current-"+strconv.Itoa(i), defaultRules)
		if i != errDepth {
			cache.Add(current)
		}
		priorInherits := []string{current.Name}
		if i == circleDepth {
			circle := createRoleTemplate(circleRoleTemplateName, defaultRules)
			cache.Add(circle)
			priorInherits = append(priorInherits, circle.Name)
			circle.RoleTemplateNames = []string{name}
		}
		prior.RoleTemplateNames = priorInherits
		prior = current
	}

	return start
}

func createRoleTemplate(name string, rules []rbacv1.PolicyRule) *v3.RoleTemplate {
	return &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Rules: rules,
	}
}

func createValidator(cache controllerv3.RoleTemplateCache) *Validator {
	return &Validator{
		roleTemplateResolver: auth.NewRoleTemplateResolver(cache, nil),
	}
}
