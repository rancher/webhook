package token_test

import (
	"context"
	"encoding/json"
	"testing"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type TokenSuite struct {
	suite.Suite
}

func TestTokens(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(TokenSuite))
}

func (t *TokenSuite) Test_UpdateValidation() {
	validator := token.NewValidator()

	type args struct {
		oldToken func() *apisv3.Token
		newToken func() *apisv3.Token
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		allowed bool
	}{
		{
			name: "base test valid Token",
			args: args{
				oldToken: func() *apisv3.Token {
					baseToken := newDefaultToken()
					return baseToken
				},
				newToken: func() *apisv3.Token {
					baseToken := newDefaultToken()
					return baseToken
				},
			},
			allowed: true,
		},
		{
			name: "attempting to update token",
			args: args{
				oldToken: func() *apisv3.Token {
					return newDefaultToken()
				},
				newToken: func() *apisv3.Token {
					baseToken := newDefaultToken()
					baseToken.Token = "xyz"
					return baseToken
				},
			},
			allowed: false,
		},
		{
			name: "attempting to update cluster name",
			args: args{
				oldToken: func() *apisv3.Token {
					baseToken := newDefaultToken()
					return baseToken
				},
				newToken: func() *apisv3.Token {
					baseToken := newDefaultToken()
					baseToken.ClusterName = ""
					return baseToken
				},
			},
			allowed: false,
		},
		{
			name: "non update requests pass",
			args: args{
				oldToken: func() *apisv3.Token { return nil },
				newToken: func() *apisv3.Token {
					return newDefaultToken()
				},
			},
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func() {
			req := createTokenRequest(t.T(), tt.args.oldToken(), tt.args.newToken())
			resp, err := validator.Admit(req)
			t.NoError(err, "Admit failed")
			assert.Equal(t.T(), resp.Allowed, tt.allowed, "Response was incorrectly validated. Wanted response.Allowed = '%v' got '%v': result='%+v", tt.allowed, resp.Allowed, resp.Result)
		})
	}
}

func createTokenRequest(t *testing.T, oldToken, newToken *apisv3.Token) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Token"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "token"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            newToken.Name,
			Namespace:       newToken.Namespace,
			Operation:       v1.Create,
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	req.Object.Raw, err = json.Marshal(newToken)
	assert.NoError(t, err, "Failed to marshal Token while creating request")
	if oldToken != nil {
		req.Operation = v1.Update
		req.OldObject.Raw, err = json.Marshal(oldToken)
		assert.NoError(t, err, "Failed to marshal old Token while creating request")
	}
	return req
}

func newDefaultToken() *apisv3.Token {
	return &apisv3.Token{
		Token:       "abc",
		ClusterName: "t-namespace",
	}
}
