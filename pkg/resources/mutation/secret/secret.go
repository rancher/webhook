package secret

import (
	"time"

	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/trace"
)

func NewMutator(client *clients.Clients) webhook.Handler {
	return &mutator{}
}

type mutator struct{}

func (m *mutator) Admit(response *webhook.Response, request *webhook.Request) error {
	if request.DryRun != nil && *request.DryRun {
		response.Allowed = true
		return nil
	}

	listTrace := trace.New("secret Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	secret, err := secretObject(request)
	if err != nil {
		return err
	}

	if secret.Type != "provisioning.cattle.io/cloud-credential" {
		response.Allowed = true
		return nil
	}

	logrus.Debugf("[secret-mutation] adding creatorID %v to secret: %v", request.UserInfo.Username, secret.Name)
	newSecret := secret.DeepCopy()

	if newSecret.Annotations == nil {
		newSecret.Annotations = make(map[string]string)
	}

	newSecret.Annotations[auth.CreatorIDAnn] = request.UserInfo.Username

	return patch.CreatePatch(secret, newSecret, response)
}

func secretObject(request *webhook.Request) (*v1.Secret, error) {
	var secret runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		secret, err = request.DecodeOldObject()
	} else {
		secret, err = request.DecodeObject()
	}
	return secret.(*v1.Secret), err
}
