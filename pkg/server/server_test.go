package server

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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
	validatingController.EXPECT().Get(configName, gomock.Any()).Return(nil, errors.NewNotFound(schema.GroupResource{Group: v1.GroupName, Resource: "validatingwebhookconfiguration"}, configName)).Times(1)
	validatingController.EXPECT().Create(gomock.Any()).DoAndReturn(func(obj *v1.ValidatingWebhookConfiguration) (*v1.ValidatingWebhookConfiguration, error) {
		storedValidatingConfig = obj.DeepCopy()
		return obj, nil
	}).Times(1)

	mutatingController := fake.NewMockNonNamespacedClientInterface[*v1.MutatingWebhookConfiguration, *v1.MutatingWebhookConfigurationList](ctrl)
	mutatingController.EXPECT().Get(configName, gomock.Any()).Return(nil, errors.NewNotFound(schema.GroupResource{Group: v1.GroupName, Resource: "mutatingwebhookconfiguration"}, configName)).Times(1)
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
