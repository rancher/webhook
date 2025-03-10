package users

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	authorizationFake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
)

const (
	managerUserName   = "manage-user"
	defaultUserName   = "test-user"
	sarErrorUser      = "sar-error-user"
	ssrErrorUser      = "ssr-error-user"
	requesterUserName = "requester-user"
)

var (
	defaultUser = v3.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultUserName,
		},
	}
	getPods = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
	}
	starPods = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"*"},
		},
	}
)

func Test_Admit(t *testing.T) {
	k8Fake := &k8testing.Fake{}
	fakeAuthz := &authorizationFake.FakeAuthorizationV1{Fake: k8Fake}
	fakeSAR := fakeAuthz.SubjectAccessReviews()
	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		spec := review.Spec
		if spec.User == sarErrorUser {
			return true, nil, fmt.Errorf("expected error")
		}
		review.Status.Allowed = spec.User == managerUserName &&
			spec.ResourceAttributes.Verb == "manage-users"
		return true, review, nil
	})

	ctrl := gomock.NewController(t)

	tests := []struct {
		name             string
		oldUser          *v3.User
		newUser          *v3.User
		resolverRulesFor func(string) ([]rbacv1.PolicyRule, error)
		requestUserName  string
		allowed          bool
		wantErr          bool
	}{
		{
			name:            "User has manage-users verb. delete operation",
			oldUser:         defaultUser.DeepCopy(),
			requestUserName: managerUserName,
			allowed:         true,
		},
		{
			name:            "User has manage-users verb. update operation",
			requestUserName: managerUserName,
			oldUser:         defaultUser.DeepCopy(),
			newUser:         defaultUser.DeepCopy(),
			allowed:         true,
		},
		{
			name:            "error checking manage-users verb",
			requestUserName: sarErrorUser,
			oldUser:         defaultUser.DeepCopy(),
			allowed:         false,
			wantErr:         true,
		},
		{
			name:            "error getting rules for User",
			oldUser:         defaultUser.DeepCopy(),
			requestUserName: requesterUserName,
			resolverRulesFor: func(_ string) ([]rbacv1.PolicyRule, error) {
				return nil, fmt.Errorf("expected error")
			},
			allowed: false,
			wantErr: true,
		},
		{
			name:            "users have same level of privileges. delete operation",
			oldUser:         defaultUser.DeepCopy(),
			requestUserName: requesterUserName,
			resolverRulesFor: func(s string) ([]rbacv1.PolicyRule, error) {
				if s == requesterUserName {
					return getPods, nil
				} else if s == defaultUserName {
					return getPods, nil
				}
				return nil, fmt.Errorf("unexpected error")
			},
			allowed: true,
		},
		{
			name:            "users have same level of privileges. update operation",
			oldUser:         defaultUser.DeepCopy(),
			newUser:         defaultUser.DeepCopy(),
			requestUserName: requesterUserName,
			resolverRulesFor: func(s string) ([]rbacv1.PolicyRule, error) {
				if s == requesterUserName {
					return getPods, nil
				} else if s == defaultUserName {
					return getPods, nil
				}
				return nil, fmt.Errorf("unexpected error")
			},
			allowed: true,
		},
		{
			name:            "requester has more privileges than user. delete operation",
			oldUser:         defaultUser.DeepCopy(),
			requestUserName: requesterUserName,
			resolverRulesFor: func(s string) ([]rbacv1.PolicyRule, error) {
				if s == requesterUserName {
					return starPods, nil
				} else if s == defaultUserName {
					return getPods, nil
				}
				return nil, fmt.Errorf("unexpected error")
			},
			allowed: true,
		},
		{
			name:            "requester has more privileges than user. update operation",
			oldUser:         defaultUser.DeepCopy(),
			newUser:         defaultUser.DeepCopy(),
			requestUserName: requesterUserName,
			resolverRulesFor: func(s string) ([]rbacv1.PolicyRule, error) {
				if s == requesterUserName {
					return starPods, nil
				} else if s == defaultUserName {
					return getPods, nil
				}
				return nil, fmt.Errorf("unexpected error")
			},
			allowed: true,
		},
		{
			name:            "user has more privileges than requester. delete operation",
			oldUser:         defaultUser.DeepCopy(),
			requestUserName: requesterUserName,
			resolverRulesFor: func(s string) ([]rbacv1.PolicyRule, error) {
				if s == requesterUserName {
					return getPods, nil
				} else if s == defaultUserName {
					return starPods, nil
				}
				return nil, fmt.Errorf("unexpected error")
			},
			allowed: false,
		},
		{
			name:            "user has more privileges than requester. update operation",
			oldUser:         defaultUser.DeepCopy(),
			newUser:         defaultUser.DeepCopy(),
			requestUserName: requesterUserName,
			resolverRulesFor: func(s string) ([]rbacv1.PolicyRule, error) {
				if s == requesterUserName {
					return getPods, nil
				} else if s == defaultUserName {
					return starPods, nil
				}
				return nil, fmt.Errorf("unexpected error")
			},
			allowed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &admitter{
				sar: fakeSAR,
			}

			// Handle fake resolver
			if tt.resolverRulesFor != nil {
				userAttributeCache := fake.NewMockNonNamespacedCacheInterface[*v3.UserAttribute](ctrl)
				userAttributeCache.EXPECT().Get(tt.oldUser.Name).Return(&v3.UserAttribute{}, nil)
				a.userAttributeCache = userAttributeCache

				a.resolver = &fakeResolver{
					rulesFor: tt.resolverRulesFor,
				}
			}

			req := createUserRequest(t, tt.oldUser, tt.newUser, tt.requestUserName)
			got, err := a.Admit(req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.allowed, got.Allowed)
		})
	}
}

func createUserRequest(t *testing.T, oldUser, newUser *v3.User, username string) *admission.Request {
	t.Helper()

	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "User"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "users"}

	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       admissionv1.Create,
			UserInfo:        authenticationv1.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	if oldUser != nil {
		req.Operation = admissionv1.Update
		req.Name = oldUser.Name
		req.Namespace = oldUser.Namespace
		req.OldObject.Raw, err = json.Marshal(oldUser)
		assert.NoError(t, err, "Failed to marshal User while creating request")
	}
	if newUser != nil {
		req.Name = newUser.Name
		req.Namespace = newUser.Namespace
		req.Object.Raw, err = json.Marshal(newUser)
		assert.NoError(t, err, "Failed to marshal User while creating request")
	} else {
		req.Operation = admissionv1.Delete
	}
	return req
}

type fakeResolver struct {
	rulesFor func(string) ([]rbacv1.PolicyRule, error)
}

func (f *fakeResolver) GetRoleReferenceRules(_ context.Context, _ rbacv1.RoleRef, _ string) ([]rbacv1.PolicyRule, error) {
	return nil, nil
}

func (f *fakeResolver) RulesFor(_ context.Context, u user.Info, _ string) ([]rbacv1.PolicyRule, error) {
	return f.rulesFor(u.GetName())
}

func (f *fakeResolver) VisitRulesFor(_ context.Context, _ user.Info, _ string, _ func(fmt.Stringer, *rbacv1.PolicyRule, error) bool) {
}
