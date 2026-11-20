package common

import (
	"errors"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestIsFeatureEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		feature    *v3.Feature
		cacheErr   error
		want       bool
		wantErr    bool
		errMessage string
	}{
		{
			name:     "returns false when feature is not found",
			cacheErr: apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "features"}, "test-feature"),
			want:     false,
		},
		{
			name: "uses default value when override is absent",
			feature: &v3.Feature{
				Status: v3.FeatureStatus{Default: true},
			},
			want: true,
		},
		{
			name: "uses override value when present",
			feature: &v3.Feature{
				Spec:   v3.FeatureSpec{Value: new(false)},
				Status: v3.FeatureStatus{Default: true},
			},
			want: false,
		},
		{
			name:       "returns cache error",
			cacheErr:   errors.New("boom"),
			want:       false,
			wantErr:    true,
			errMessage: "failed to determine status of 'test-feature' feature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsFeatureEnabled(featureCacheStub{feature: tt.feature, err: tt.cacheErr}, "test-feature")
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errMessage)
				require.False(t, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

type featureCacheStub struct {
	feature *v3.Feature
	err     error
}

func (f featureCacheStub) Get(_ string) (*v3.Feature, error) {
	return f.feature, f.err
}

type fakeSettingCache struct {
	setting *v3.Setting
	err     error
}

func (f fakeSettingCache) Get(string) (*v3.Setting, error) { return f.setting, f.err }

func TestIsPrime(t *testing.T) {
	t.Parallel()

	notFound := apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "settings"}, ServerVersionTypeSetting)

	tests := []struct {
		name    string
		cache   fakeSettingCache
		want    bool
		wantErr bool
	}{
		{name: "prime value", cache: fakeSettingCache{setting: &v3.Setting{Value: "prime", Default: "dev"}}, want: true},
		{name: "prime default with no value", cache: fakeSettingCache{setting: &v3.Setting{Default: "prime"}}, want: true},
		{name: "community default with no value", cache: fakeSettingCache{setting: &v3.Setting{Default: "dev"}}, want: false},
		{name: "value overrides default", cache: fakeSettingCache{setting: &v3.Setting{Value: "dev", Default: "prime"}}, want: false},
		{name: "setting not found", cache: fakeSettingCache{err: notFound}, want: false},
		{name: "cache error", cache: fakeSettingCache{err: errors.New("boom")}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := IsPrime(tt.cache)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
