package auth_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

var errExpected = errors.New("expected test error")

type EscalationSuite struct {
	suite.Suite
	ruleReadPods     rbacv1.PolicyRule
	ruleReadServices rbacv1.PolicyRule
	ruleWriteNodes   rbacv1.PolicyRule
	ruleAdmin        rbacv1.PolicyRule
	adminCR          *rbacv1.ClusterRole
	writeNodeCR      *rbacv1.ClusterRole
	readServiceRole  *rbacv1.Role
}

func TestEscalation(t *testing.T) {
	suite.Run(t, new(EscalationSuite))
}

func (e *EscalationSuite) SetupSuite() {
	e.ruleReadPods = rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	e.ruleReadServices = rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"services"},
	}
	e.ruleWriteNodes = rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	e.ruleAdmin = rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	e.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{e.ruleAdmin},
	}
	e.writeNodeCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "write-role"},
		Rules:      []rbacv1.PolicyRule{e.ruleWriteNodes, e.ruleReadPods},
	}
	e.readServiceRole = &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "read-service"},
		Rules:      []rbacv1.PolicyRule{e.ruleReadServices},
	}
}

func (e *EscalationSuite) newDefaultRequest(userName string) *admission.Request {
	return &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:       "1",
			Name:      "default",
			Namespace: "namespace1",
			Operation: v1.Create,
			UserInfo: authenticationv1.UserInfo{
				Username: userName,
				UID:      "u-1",
				Extra:    map[string]authenticationv1.ExtraValue{"extra": []string{"v1", "v2"}},
			},
		},
		Context: context.Background(),
	}
}

func (e *EscalationSuite) TestConfirmNoEscalation() {
	const adminUser = "admin-user"
	const testUser = "test-user"
	roles := []*rbacv1.Role{e.readServiceRole}
	clusterRoles := []*rbacv1.ClusterRole{e.adminCR}
	roleBindings := []*rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: e.readServiceRole.Namespace},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: testUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: e.readServiceRole.Name},
		},
	}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: e.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(roles, roleBindings, clusterRoles, clusterRoleBindings)
	type args struct {
		request *admission.Request
		rules   []rbacv1.PolicyRule
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// No escalation occurred
		{
			name: "Admin no escalation",
			args: args{
				request: e.newDefaultRequest(adminUser),
				rules:   []rbacv1.PolicyRule{e.ruleReadPods, e.ruleReadServices, e.ruleWriteNodes},
			},
		},
		{
			name: "testUser denied escalation",
			args: args{
				request: e.newDefaultRequest(testUser),
				rules:   []rbacv1.PolicyRule{e.ruleReadPods, e.ruleReadServices, e.ruleWriteNodes},
			},
			wantErr: true,
		},
		// Denied Escalation attemptß
	}
	for i := range tests {
		test := tests[i]
		e.Run(test.name, func() {
			err := auth.ConfirmNoEscalation(test.args.request, test.args.rules, test.args.request.Namespace, resolver)
			resp := &v1.AdmissionResponse{
				UID:     test.args.request.UID,
				Allowed: false,
				Result:  &metav1.Status{},
			}

			auth.SetEscalationResponse(resp, err)
			if test.wantErr {
				e.Error(err, "expected tests to have error.")
				e.False(resp.Allowed, "Response allowed incorrectly set to true.")
				e.NotEmpty(resp.Result.Message, "Response message was not set.")
				e.NotEmpty(resp.Result.Status, "Response status was not set.")
			} else {
				e.NoError(err, "unexpected error in test.")
				e.True(resp.Allowed, "Response allowed incorrectly set to false")
			}
		})
	}
}

func (e *EscalationSuite) TestEscalationAuthorized() {
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "roletemplates",
	}
	const namespace = "namespace1"
	const testUser = "testUser"
	const unknownUser = "unknownUser"
	const errorUser = "errorUser"
	goodRequest := e.newDefaultRequest(testUser)
	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		spec := review.Spec
		if spec.User == errorUser {
			return true, nil, errExpected
		}

		review.Status.Allowed = spec.User == testUser &&
			spec.UID == goodRequest.UserInfo.UID &&
			reflect.DeepEqual(spec.Groups, goodRequest.UserInfo.Groups) &&
			spec.ResourceAttributes.Version == gvr.Version &&
			spec.ResourceAttributes.Group == gvr.Group &&
			spec.ResourceAttributes.Resource == gvr.Resource &&
			spec.ResourceAttributes.Namespace == namespace &&
			spec.ResourceAttributes.Verb == "escalate"
		return true, review, nil
	})
	tests := []struct {
		name    string
		request *admission.Request
		want    bool
		wantErr bool
	}{
		{
			name:    "escalate verb present",
			request: goodRequest,
			want:    true,
			wantErr: false,
		},
		{
			name:    "escalate verb not present",
			request: e.newDefaultRequest(unknownUser),
			want:    false,
			wantErr: false,
		},
		{
			name:    "escalate check error",
			request: e.newDefaultRequest(errorUser),
			want:    false,
			wantErr: true,
		},
	}
	for i := range tests {
		test := tests[i]
		e.Run(test.name, func() {
			got, err := auth.EscalationAuthorized(test.request, gvr, fakeSAR, namespace)
			if test.wantErr {
				e.Error(err, "expected tests to have error.")
			} else {
				e.NoError(err, "unexpected error in test.")
			}
			if got != test.want {
				e.Fail("Incorrect response allowed result", "got=%s wanted=%s", got, test.want)
			}
		})
	}
}
