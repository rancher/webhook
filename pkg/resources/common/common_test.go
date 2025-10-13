package common

import (
	"context"
	"fmt"
	"testing"

	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	v1Authorization "k8s.io/client-go/kubernetes/typed/authorization/v1"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
)

func TestIsModifyingLabel(t *testing.T) {
	t.Parallel()

	type args struct {
		oldLabels map[string]string
		newLabels map[string]string
		label     string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "all maps are nil",
			args: args{
				oldLabels: nil,
				newLabels: nil,
				label:     "label",
			},
			want: false,
		},
		{
			name: "all maps are empty",
			args: args{
				oldLabels: map[string]string{},
				newLabels: map[string]string{},
				label:     "label",
			},
			want: false,
		},
		{
			name: "old label is nil, new is populated",
			args: args{
				oldLabels: nil,
				newLabels: map[string]string{"label": "test"},
				label:     "label",
			},
			want: false,
		},
		{
			name: "old label is empty, new is populated",
			args: args{
				oldLabels: map[string]string{},
				newLabels: map[string]string{"label": "test"},
				label:     "label",
			},
			want: false,
		},
		{
			name: "new label is nil, old is populated",
			args: args{
				oldLabels: map[string]string{"label": "test"},
				newLabels: nil,
				label:     "label",
			},
			want: true,
		},
		{
			name: "new label is empty, old is populated",
			args: args{
				oldLabels: map[string]string{"label": "test"},
				newLabels: map[string]string{},
				label:     "label",
			},
			want: true,
		},
		{
			name: "neither map have the desired label",
			args: args{
				oldLabels: map[string]string{"label": "test"},
				newLabels: map[string]string{"label": "test2"},
				label:     "bad_label",
			},
			want: false,
		},
		{
			name: "label's value is being modified",
			args: args{
				oldLabels: map[string]string{"label": "test"},
				newLabels: map[string]string{"label": "test2"},
				label:     "label",
			},
			want: true,
		},
		{
			name: "label is being removed",
			args: args{
				oldLabels: map[string]string{"label": "test", "label2": "test2"},
				newLabels: map[string]string{"label2": "test2"},
				label:     "label",
			},
			want: true,
		},
		{
			name: "label is populated and unchanged",
			args: args{
				oldLabels: map[string]string{"label": "test"},
				newLabels: map[string]string{"label": "test"},
				label:     "label",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsModifyingLabel(tt.args.oldLabels, tt.args.newLabels, tt.args.label); got != tt.want {
				t.Errorf("IsModifyingLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testRuleResolver struct {
	returnRules []v1.PolicyRule
}

func (t testRuleResolver) GetRoleReferenceRules(context.Context, v1.RoleRef, string) ([]v1.PolicyRule, error) {
	return nil, nil
}

func (t testRuleResolver) RulesFor(context.Context, user.Info, string) ([]v1.PolicyRule, error) {
	return t.returnRules, nil
}

func (t testRuleResolver) VisitRulesFor(context.Context, user.Info, string, func(fmt.Stringer, *v1.PolicyRule, error) bool) {
}

var (
	adminRule = v1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
)

func TestIsRulesAllowed(t *testing.T) {
	request := &admission.Request{}
	gvr := schema.GroupVersionResource{}
	type stateSnapshot struct {
		sar                func() v1Authorization.SubjectAccessReviewInterface
		resolver           testRuleResolver
		wantError          bool
		hasVerbBeenChecked bool
		hasVerb            bool
	}

	tests := []struct {
		name   string
		rules  []v1.PolicyRule
		states []stateSnapshot
	}{
		{
			name:  "no escalation",
			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						return nil
					},
					resolver:  testRuleResolver{returnRules: []v1.PolicyRule{adminRule}},
					wantError: false,
				},
			},
		},
		{
			name:  "escalation, no verb",
			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (bool, runtime.Object, error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = false
							return true, review, nil
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          true,
					hasVerbBeenChecked: true,
					hasVerb:            false,
				},
			},
		},
		{
			name: "escalation, verb",

			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = true
							return true, review, nil
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          false,
					hasVerb:            true,
					hasVerbBeenChecked: true,
				},
			},
		},
		{
			name: "checking verb give an error",

			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(_ k8testing.Action) (handled bool, ret runtime.Object, err error) {
							return true, nil, fmt.Errorf("error")
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          true,
					hasVerb:            false,
					hasVerbBeenChecked: false,
				},
			},
		},
		{
			name:  "no escalation first call, escalation second call",
			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						return nil
					},
					resolver:           testRuleResolver{returnRules: []v1.PolicyRule{adminRule}},
					wantError:          false,
					hasVerbBeenChecked: false,
					hasVerb:            false,
				},
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (bool, runtime.Object, error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = false
							return true, review, nil
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          true,
					hasVerbBeenChecked: true,
					hasVerb:            false,
				},
			},
		},
		{
			name:  "escalation with verb, bypass second call",
			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = true
							return true, review, nil
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          false,
					hasVerbBeenChecked: true,
					hasVerb:            true,
				},
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						// this would return false if it gets called
						// since we already checked for the verb, it gets bypassed
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (bool, runtime.Object, error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = false
							return true, review, nil
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          false,
					hasVerbBeenChecked: true,
					hasVerb:            true, // still has verb
				},
			},
		},
		{
			name:  "escalation without verb, bypass second call",
			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (bool, runtime.Object, error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = false
							return true, review, nil
						})
						return fakeSAR
					},

					resolver:           testRuleResolver{},
					wantError:          true,
					hasVerbBeenChecked: true,
					hasVerb:            false,
				},
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						// this would return false if it gets called
						// since we already checked for the verb, it gets bypassed
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (bool, runtime.Object, error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = false
							return true, review, nil
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          true,
					hasVerbBeenChecked: true,
					hasVerb:            false, // still doesn't have verb
				},
			},
		},
		{
			name:  "escalation first call, no escalation second call",
			rules: []v1.PolicyRule{adminRule},
			states: []stateSnapshot{
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						k8Fake := &k8testing.Fake{}
						fakeAuth := &k8fake.FakeAuthorizationV1{Fake: k8Fake}
						fakeSAR := fakeAuth.SubjectAccessReviews()
						k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (bool, runtime.Object, error) {
							createAction := action.(k8testing.CreateActionImpl)
							review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
							review.Status.Allowed = false
							return true, review, nil
						})
						return fakeSAR
					},
					resolver:           testRuleResolver{},
					wantError:          true,
					hasVerbBeenChecked: true,
					hasVerb:            false,
				},
				{
					sar: func() v1Authorization.SubjectAccessReviewInterface {
						return nil
					},
					resolver:           testRuleResolver{returnRules: []v1.PolicyRule{adminRule}},
					wantError:          false,
					hasVerbBeenChecked: true, // the verb being checked persists
					hasVerb:            false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verbChecker := NewCachedVerbChecker(request, "admin-role", nil, gvr, "verb")
			for _, ss := range tt.states {
				verbChecker.sar = ss.sar()
				err := verbChecker.IsRulesAllowed(tt.rules, ss.resolver, "ns1")
				if ss.wantError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, ss.hasVerb, verbChecker.hasVerb)
				require.Equal(t, ss.hasVerbBeenChecked, verbChecker.hasVerbBeenChecked)
			}
		})
	}
}

func TestOldAndNewFromRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         *admissionv1.AdmissionRequest
		expected    *provv1.Cluster
		expectedOld *provv1.Cluster
		expectedErr bool
	}{
		{
			name:        "nil request",
			req:         nil,
			expectedErr: true,
		},
		{
			name: "create",
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: []byte(`{"metadata":{"namespace":"test","name":"test"}}`),
				},
			},
			expected: &provv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
			},
			expectedOld: &provv1.Cluster{},
		},
		{
			name: "create error",
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: []byte(``),
				},
			},
			expectedErr: true,
		},
		{
			name: "update",
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				Object: runtime.RawExtension{
					Raw: []byte(`{"metadata":{"namespace":"test","name":"test","resourceVersion":"1"}}`),
				},
				OldObject: runtime.RawExtension{
					Raw: []byte(`{"metadata":{"namespace":"test","name":"test"}}`),
				},
			},
			expected: &provv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "test",
					Name:            "test",
					ResourceVersion: "1",
				},
			},
			expectedOld: &provv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
			},
		},
		{
			name: "update error",
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				Object: runtime.RawExtension{
					Raw: []byte(``),
				},
				OldObject: runtime.RawExtension{
					Raw: []byte(`{"metadata":{"namespace":"test","name":"test"}}`),
				},
			},
			expectedErr: true,
		},
		{
			name: "update error old object",
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				Object: runtime.RawExtension{
					Raw: []byte(`{"metadata":{"namespace":"test","name":"test"}}`),
				},
				OldObject: runtime.RawExtension{
					Raw: []byte(``),
				},
			},
			expectedErr: true,
		},
		{
			name: "delete",
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Delete,
				OldObject: runtime.RawExtension{
					Raw: []byte(`{"metadata":{"namespace":"test","name":"test"}}`),
				},
			},
			expected: &provv1.Cluster{},
			expectedOld: &provv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
			},
		},
		{
			name: "delete error",
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Delete,
				OldObject: runtime.RawExtension{
					Raw: []byte(``),
				},
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			old, obj, err := OldAndNewFromRequest[provv1.Cluster](tt.req)
			if tt.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedOld, old)
				require.Equal(t, tt.expected, obj)
			}
		})
	}
}
