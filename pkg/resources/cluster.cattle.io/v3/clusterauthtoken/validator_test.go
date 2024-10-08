package clusterauthtoken_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/cluster.cattle.io/v3/clusterauthtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
)

type ClusterAuthTokenFieldsSuite struct {
	suite.Suite
}

func TestTokenFieldsValidation(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(ClusterAuthTokenFieldsSuite))
}

var (
	gvk = metav1.GroupVersionKind{Group: "cluster.cattle.io", Version: "v3", Kind: "ClusterAuthToken"}
	gvr = metav1.GroupVersionResource{Group: "cluster.cattle.io", Version: "v3", Resource: "clusterauthtokens"}
)

type tokenFieldsTest struct {
	lastUsedAt *string
	allowed    bool
}

func (t *tokenFieldsTest) name() string {
	return pointer.StringDeref(t.lastUsedAt, "nil")
}

func (t *tokenFieldsTest) toToken() ([]byte, error) {
	return json.Marshal(clusterauthtoken.PartialClusterAuthToken{
		LastUsedAt: t.lastUsedAt,
	})
}

var tokenFieldsTests = []tokenFieldsTest{
	{
		allowed: true,
	},
	{
		lastUsedAt: pointer.String(time.Now().Format(time.RFC3339)),
		allowed:    true,
	},
	{
		lastUsedAt: pointer.String("2024-03-25T21:2:45Z"), // Not a valid RFC3339 time.
	},
	{
		lastUsedAt: pointer.String("1w"),
	},
	{
		lastUsedAt: pointer.String("1d"),
	},
	{
		lastUsedAt: pointer.String("-1h"),
	},
	{
		lastUsedAt: pointer.String(""),
	},
}

func (s *ClusterAuthTokenFieldsSuite) TestValidateOnUpdate() {
	s.validate(v1.Update)
}

func (s *ClusterAuthTokenFieldsSuite) TestValidateOnCreate() {
	s.validate(v1.Create)
}

func (s *ClusterAuthTokenFieldsSuite) TestDontValidateOnDelete() {
	// Make sure that Token can be deleted without enforcing validation of user token fields.
	alwaysAllow := true
	s.validate(v1.Delete, alwaysAllow)
}

func (s *ClusterAuthTokenFieldsSuite) validate(op v1.Operation, allowed ...bool) {
	admitter := s.setup()

	for _, test := range tokenFieldsTests {
		test := test
		s.Run(test.name(), func() {
			t := s.T()
			t.Parallel()

			objRaw, err := test.toToken()
			assert.NoError(t, err, "failed to marshal PartialToken")

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

func (s *ClusterAuthTokenFieldsSuite) setup() admission.Admitter {
	validator := clusterauthtoken.NewValidator()
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
