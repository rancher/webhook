package setting_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type SettingSuite struct {
	suite.Suite
}

func TestRetentionFieldsValidation(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(SettingSuite))
}

var (
	gvk = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Setting"}
	gvr = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "settings"}
)

type retentionTest struct {
	setting string
	value   string
	allowed bool
}

func (t *retentionTest) name() string {
	return t.setting + "_" + t.value
}

func (t *retentionTest) toSetting() ([]byte, error) {
	return json.Marshal(v3.Setting{
		ObjectMeta: metav1.ObjectMeta{
			Name: t.setting,
		},
		Value: t.value,
	})
}
func (t *retentionTest) toOldSetting() ([]byte, error) {
	return json.Marshal(v3.Setting{
		ObjectMeta: metav1.ObjectMeta{
			Name: t.setting,
		},
	})
}

var retentionTests = []retentionTest{
	{
		setting: "disable-inactive-user-after",
		value:   "",
		allowed: true,
	},
	{
		setting: "delete-inactive-user-after",
		value:   "",
		allowed: true,
	},
	{
		setting: "user-last-login-default",
		value:   "",
		allowed: true,
	},
	{
		setting: "user-retention-cron",
		value:   "",
		allowed: true,
	},
	{
		setting: "disable-inactive-user-after",
		value:   "2h30m",
		allowed: true,
	},
	{
		setting: "delete-inactive-user-after",
		value:   setting.MinDeleteInactiveUserAfter.String(),
		allowed: true,
	},
	{
		setting: "user-last-login-default",
		value:   "2024-01-08T00:00:00Z",
		allowed: true,
	},
	{
		setting: "user-retention-cron",
		value:   "* * * * *",
		allowed: true,
	},
	{
		setting: "disable-inactive-user-after",
		value:   "1w",
	},
	{
		setting: "delete-inactive-user-after",
		value:   "2d",
	},
	{
		setting: "user-last-login-default",
		value:   "foo",
	},
	{
		setting: "user-retention-cron",
		value:   "* * * * * *",
	},
	{
		setting: "disable-inactive-user-after",
		value:   "-1h",
	},
	{
		setting: "delete-inactive-user-after",
		value:   "-1h",
	},
	{
		setting: "delete-inactive-user-after",
		value:   (setting.MinDeleteInactiveUserAfter - time.Second).String(),
	},
}

func (s *SettingSuite) TestValidateRetentionSettingsOnUpdate() {
	s.validate(v1.Update)
}

func (s *SettingSuite) TestValidateRetentionSettingsOnCreate() {
	s.validate(v1.Create)
}

func (s *SettingSuite) validate(op v1.Operation) {
	admitter := s.setup()

	for _, test := range retentionTests {
		test := test
		s.Run(test.name(), func() {
			t := s.T()
			t.Parallel()

			oldObjRaw, err := test.toOldSetting()
			assert.NoError(t, err, "failed to marshal old Setting")

			objRaw, err := test.toSetting()
			assert.NoError(t, err, "failed to marshal Setting")

			resp, err := admitter.Admit(newRequest(op, objRaw, oldObjRaw))
			if assert.NoError(t, err, "Admit failed") {
				assert.Equalf(t, test.allowed, resp.Allowed, "expected allowed %v got %v message=%v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (s *SettingSuite) setup() admission.Admitter {
	validator := setting.NewValidator()
	s.Len(validator.Admitters(), 1, "expected 1 admitter")

	return validator.Admitters()[0]
}

func newRequest(op v1.Operation, obj, oldObj []byte) *admission.Request {
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
			OldObject:       runtime.RawExtension{Raw: oldObj},
		},
		Context: context.Background(),
	}
}
