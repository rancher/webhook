package userattribute_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/userattribute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
)

type RetentionFieldsSuite struct {
	suite.Suite
}

func TestRetentionFieldsValidation(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(RetentionFieldsSuite))
}

var (
	gvk = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "UserAttribute"}
	gvr = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "userattributes"}
)

type retentionFieldsTest struct {
	lastLogin    *string
	disableAfter *string
	deleteAfter  *string
	allowed      bool
}

func (t *retentionFieldsTest) name() string {
	return pointer.StringDeref(t.lastLogin, "nil") + "_" +
		pointer.StringDeref(t.disableAfter, "nil") + "_" +
		pointer.StringDeref(t.deleteAfter, "nil")
}

func (t *retentionFieldsTest) toUserAttribute() ([]byte, error) {
	return json.Marshal(userattribute.PartialUserAttribute{
		LastLogin:    t.lastLogin,
		DisableAfter: t.disableAfter,
		DeleteAfter:  t.deleteAfter,
	})
}

var retentionFieldsTests = []retentionFieldsTest{
	{
		allowed: true,
	},
	{
		disableAfter: pointer.String("0"),
		allowed:      true,
	},
	{
		deleteAfter: pointer.String("0"),
		allowed:     true,
	},
	{
		disableAfter: pointer.String("1h2m3s"),
		allowed:      true,
	},
	{
		deleteAfter: pointer.String("1h2m3s"),
		allowed:     true,
	},
	{
		lastLogin: pointer.String(time.Now().Format(time.RFC3339)),
		allowed:   true,
	},
	{
		disableAfter: pointer.String("1w"),
	},
	{
		deleteAfter: pointer.String("1w"),
	},
	{
		disableAfter: pointer.String("1d"),
	},
	{
		deleteAfter: pointer.String("1d"),
	},
	{
		disableAfter: pointer.String(""),
	},
	{
		deleteAfter: pointer.String(""),
	},
	{
		disableAfter: pointer.String("-1h"),
	},
	{
		deleteAfter: pointer.String("-1h"),
	},
	{
		lastLogin: pointer.String("2024-03-25T21:2:45Z"), // Not a valid RFC3339 time.
	},
	{
		lastLogin: pointer.String(""),
	},
}

func (s *RetentionFieldsSuite) TestValidateOnUpdate() {
	s.validate(v1.Update)
}

func (s *RetentionFieldsSuite) TestValidateOnCreate() {
	s.validate(v1.Create)
}

func (s *RetentionFieldsSuite) TestDontValidateOnDelete() {
	// Make sure that UserAttribute can be deleted without enforcing validation of user retention fields.
	alwaysAllow := true
	s.validate(v1.Delete, alwaysAllow)
}

func (s *RetentionFieldsSuite) validate(op v1.Operation, allowed ...bool) {
	admitter := s.setup()

	for _, test := range retentionFieldsTests {
		test := test
		s.Run(test.name(), func() {
			t := s.T()
			t.Parallel()

			objRaw, err := test.toUserAttribute()
			assert.NoError(t, err, "failed to marshal PartialUserAttribute")

			resp, err := admitter.Admit(newRequest(op, objRaw))
			if assert.NoError(t, err, "Admit failed") {
				wantAllowed := test.allowed
				if len(allowed) > 0 {
					wantAllowed = allowed[0] // Apply the override.
				}

				assert.Equalf(t, wantAllowed, resp.Allowed, "expected allowed %v got %v message=%v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (s *RetentionFieldsSuite) setup() admission.Admitter {
	validator := userattribute.NewValidator()
	s.Len(validator.Admitters(), 1, "expected 1 admitter")

	return validator.Admitters()[0]
}

func newRequest(op v1.Operation, obj []byte) *admission.Request {
	return &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       op,
			UserInfo:        authenticationv1.UserInfo{Username: "foo", UID: ""},
			Object:          runtime.RawExtension{Raw: obj},
			OldObject:       runtime.RawExtension{Raw: []byte("{}")},
		},
		Context: context.Background(),
	}
}
