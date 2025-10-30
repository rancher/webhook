package server

import (
	"errors"
	"testing"

	"github.com/rancher/webhook/pkg/health"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestSecretHandlerEnsureWebhookConfigurationCreate(t *testing.T) {
	configName := "rancher.cattle.io"

	var (
		storedValidatingConfig *v1.ValidatingWebhookConfiguration
		storedMutatingConfig   *v1.MutatingWebhookConfiguration
	)

	ctrl := gomock.NewController(t)
	validatingController := fake.NewMockNonNamespacedClientInterface[*v1.ValidatingWebhookConfiguration, *v1.ValidatingWebhookConfigurationList](ctrl)
	validatingController.EXPECT().Get(configName, gomock.Any()).Return(nil, apierrors.NewNotFound(schema.GroupResource{Group: v1.GroupName, Resource: "validatingwebhookconfiguration"}, configName)).Times(1)
	validatingController.EXPECT().Create(gomock.Any()).DoAndReturn(func(obj *v1.ValidatingWebhookConfiguration) (*v1.ValidatingWebhookConfiguration, error) {
		storedValidatingConfig = obj.DeepCopy()
		return obj, nil
	}).Times(1)

	mutatingController := fake.NewMockNonNamespacedClientInterface[*v1.MutatingWebhookConfiguration, *v1.MutatingWebhookConfigurationList](ctrl)
	mutatingController.EXPECT().Get(configName, gomock.Any()).Return(nil, apierrors.NewNotFound(schema.GroupResource{Group: v1.GroupName, Resource: "mutatingwebhookconfiguration"}, configName)).Times(1)
	mutatingController.EXPECT().Create(gomock.Any()).DoAndReturn(func(obj *v1.MutatingWebhookConfiguration) (*v1.MutatingWebhookConfiguration, error) {
		storedMutatingConfig = obj.DeepCopy()
		return obj, nil
	}).Times(1)

	handler := &secretHandler{
		validatingController: validatingController,
		mutatingController:   mutatingController,
	}

	validatingConfig := &v1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: configName,
		},
		Webhooks: []v1.ValidatingWebhook{
			{
				Name: "rancher.cattle.io.features.management.cattle.io",
			},
		},
	}
	mutatingConfig := &v1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: configName,
		},
		Webhooks: []v1.MutatingWebhook{
			{
				Name: "rancher.cattle.io.clusters.provisioning.cattle.io",
			},
		},
	}

	err := handler.ensureWebhookConfiguration(validatingConfig, mutatingConfig)
	require.NoError(t, err)

	require.NotNil(t, storedValidatingConfig)
	require.Len(t, storedValidatingConfig.Webhooks, 1)
	assert.Equal(t, validatingConfig.Webhooks[0].Name, storedValidatingConfig.Webhooks[0].Name)

	require.NotNil(t, storedMutatingConfig)
	require.Len(t, storedMutatingConfig.Webhooks, 1)
	assert.Equal(t, mutatingConfig.Webhooks[0].Name, storedMutatingConfig.Webhooks[0].Name)
}

// TestSyncLeaderLogic tests the logic within the sync function related to leader election.
func TestSyncLeaderLogic(t *testing.T) {
	t.Parallel()
	configName := "rancher.cattle.io"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      caName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey: []byte("cert-data"),
		},
	}
	testErr := errors.New("test error")

	tests := []struct {
		name                 string
		isLeader             bool
		getMutatingErr       error
		getValidatingErr     error
		createMutatingErr    error
		createValidatingErr  error
		expectedErr          error
		expectControllersRun bool
	}{
		{
			name:        "follower becomes healthy",
			isLeader:    false,
			expectedErr: nil,
		},
		{
			name:                 "leader becomes healthy on create",
			isLeader:             true,
			getMutatingErr:       apierrors.NewNotFound(schema.GroupResource{}, ""),
			getValidatingErr:     apierrors.NewNotFound(schema.GroupResource{}, ""),
			expectedErr:          nil,
			expectControllersRun: true,
		},
		{
			name:                 "leader becomes unhealthy on create error",
			isLeader:             true,
			getValidatingErr:     apierrors.NewNotFound(schema.GroupResource{}, ""),
			createValidatingErr:  testErr,
			expectedErr:          testErr,
			expectControllersRun: true,
		},
		{
			name:                 "leader becomes healthy on update",
			isLeader:             true,
			expectedErr:          nil,
			expectControllersRun: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			validatingController := fake.NewMockNonNamespacedClientInterface[*v1.ValidatingWebhookConfiguration, *v1.ValidatingWebhookConfigurationList](ctrl)
			mutatingController := fake.NewMockNonNamespacedClientInterface[*v1.MutatingWebhookConfiguration, *v1.MutatingWebhookConfigurationList](ctrl)
			errChecker := health.NewErrorChecker("test")
			errChecker.Store(errors.New("initial error"))

			handler := &secretHandler{
				validatingController: validatingController,
				mutatingController:   mutatingController,
				errChecker:           errChecker,
			}

			leaderFlag.Store(tt.isLeader)

			if tt.expectControllersRun {
				validatingController.EXPECT().Get(configName, gomock.Any()).Return(&v1.ValidatingWebhookConfiguration{}, tt.getValidatingErr).Times(1)
				if apierrors.IsNotFound(tt.getValidatingErr) {
					validatingController.EXPECT().Create(gomock.Any()).Return(&v1.ValidatingWebhookConfiguration{}, tt.createValidatingErr).Times(1)
				} else if tt.getValidatingErr == nil {
					validatingController.EXPECT().Update(gomock.Any()).Return(&v1.ValidatingWebhookConfiguration{}, nil).Times(1)
				}

				// Only expect calls to the mutating controller if the validating part is expected to succeed.
				if (tt.getValidatingErr == nil || apierrors.IsNotFound(tt.getValidatingErr)) && tt.createValidatingErr == nil {
					mutatingController.EXPECT().Get(configName, gomock.Any()).Return(&v1.MutatingWebhookConfiguration{}, tt.getMutatingErr).Times(1)
					if apierrors.IsNotFound(tt.getMutatingErr) {
						mutatingController.EXPECT().Create(gomock.Any()).Return(&v1.MutatingWebhookConfiguration{}, tt.createMutatingErr).Times(1)
					} else if tt.getMutatingErr == nil {
						mutatingController.EXPECT().Update(gomock.Any()).Return(&v1.MutatingWebhookConfiguration{}, nil).Times(1)
					}
				}
			}

			_, err := handler.sync("test-sync", secret)

			// The only error we might get is a transient one from ensureWebhookConfiguration.
			if tt.expectedErr != nil {
				assert.ErrorContains(t, err, tt.expectedErr.Error(), "expected an error when ensuring webhook config")
			} else {
				require.NoError(t, err)
			}

			healthErr := errChecker.Check(nil)
			if tt.expectedErr == nil {
				assert.NoError(t, healthErr, "expected pod to be healthy")
			} else {
				assert.Error(t, healthErr, "expected pod to be unhealthy")
			}
		})
	}
}
