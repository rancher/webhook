package globalrolebinding_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var errTest = errors.New("bad error")

type tableTest struct {
	wantGRB   func() *apisv3.GlobalRoleBinding
	name      string
	args      args
	wantError bool
	allowed   bool
}

type args struct {
	oldGRB   func() *apisv3.GlobalRoleBinding
	newGRB   func() *apisv3.GlobalRoleBinding
	username string
}

type GlobalRoleBindingSuite struct {
	suite.Suite
	adminGR        *apisv3.GlobalRole
	manageNodesGR  *apisv3.GlobalRole
	adminCR        *rbacv1.ClusterRole
	manageNodeRole *rbacv1.ClusterRole
}

func TestGlobalRoleBindings(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(GlobalRoleBindingSuite))
}

func (g *GlobalRoleBindingSuite) SetupSuite() {
	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
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
	g.manageNodesGR = &apisv3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
	}
	g.adminGR = &apisv3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName: "Admin Role",
		Rules:       []rbacv1.PolicyRule{ruleAdmin},
		Builtin:     true,
	}
	g.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{ruleAdmin},
	}
	g.manageNodeRole = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "manage-nodes"},
		Rules:      []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
	}
}

// createGRBRequest will return a new webhookRequest with the using the given GRBs
// if oldGRB is nil then a request will be returned as a create operation.
// if newGRB is nil then a request will be returned as a delete operation.
// else the request will look like and update operation.
func createGRBRequest(t *testing.T, oldGRB, newGRB *apisv3.GlobalRoleBinding, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRoleBinding"}
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
	if oldGRB != nil {
		req.Operation = v1.Update
		req.Name = oldGRB.Name
		req.Namespace = oldGRB.Namespace
		req.OldObject.Raw, err = json.Marshal(oldGRB)
		assert.NoError(t, err, "Failed to marshal GRB while creating request")
	}
	if newGRB != nil {
		req.Name = newGRB.Name
		req.Namespace = newGRB.Namespace
		req.Object.Raw, err = json.Marshal(newGRB)
		assert.NoError(t, err, "Failed to marshal GRB while creating request")
	} else {
		req.Operation = v1.Delete
	}

	return req
}

func newDefaultGRB() *apisv3.GlobalRoleBinding {
	return &apisv3.GlobalRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalRoleBinding", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "grb-new",
			GenerateName:      "grb-",
			Namespace:         "g-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		UserName:       "user1",
		GlobalRoleName: "admin-role",
	}
}

func newNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "globalRole"}, name)
}
