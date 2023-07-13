package globalrole_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var errTest = errors.New("bad error")

type tableTest struct {
	wantGR    func() *v3.GlobalRole
	name      string
	args      args
	wantError bool
	allowed   bool
}

type args struct {
	oldGR    func() *v3.GlobalRole
	newGR    func() *v3.GlobalRole
	username string
}

type GlobalRoleSuite struct {
	suite.Suite
	ruleReadPods   rbacv1.PolicyRule
	ruleWriteNodes rbacv1.PolicyRule
	ruleAdmin      rbacv1.PolicyRule
	ruleEmptyVerbs rbacv1.PolicyRule
	adminCR        *rbacv1.ClusterRole
	readPodsCR     *rbacv1.ClusterRole
}

func TestGlobalRoles(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(GlobalRoleSuite))
}

func (c *GlobalRoleSuite) SetupSuite() {
	c.ruleReadPods = rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	c.ruleWriteNodes = rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	c.ruleEmptyVerbs = rbacv1.PolicyRule{
		Verbs:     nil,
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	c.ruleAdmin = rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	c.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{c.ruleAdmin},
	}
	c.readPodsCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "read-pods"},
		Rules:      []rbacv1.PolicyRule{c.ruleReadPods},
	}
}

// createGRRequest will return a new webhookRequest with the using the given GRs
// if oldGR is nil then a request will be returned as a create operation.
// if newGR is nil then a request will be returned as a delete operation.
// else the request will look like and update operation.
func createGRRequest(t *testing.T, oldGR, newGR *v3.GlobalRole, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRole"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalrolebindings"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       v1.Create,
			UserInfo:        v1authentication.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	if oldGR != nil {
		req.Operation = v1.Update
		req.Name = oldGR.Name
		req.Namespace = oldGR.Namespace
		req.OldObject.Raw, err = json.Marshal(oldGR)
		assert.NoError(t, err, "Failed to marshal GR while creating request")
	}
	if newGR != nil {
		req.Name = newGR.Name
		req.Namespace = newGR.Namespace
		req.Object.Raw, err = json.Marshal(newGR)
		assert.NoError(t, err, "Failed to marshal GR while creating request")
	} else {
		req.Operation = v1.Delete
	}

	return req
}

func newDefaultGR() *v3.GlobalRole {
	return &v3.GlobalRole{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalRole", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gr-new",
			GenerateName:      "gr-",
			Namespace:         "c-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		DisplayName:    "Test Global Role",
		Description:    "This is a role created for testing.",
		Rules:          nil,
		NewUserDefault: false,
		Builtin:        false,
	}
}
