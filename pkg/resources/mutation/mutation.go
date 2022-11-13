package mutation

import (
	"fmt"

	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/wrangler/pkg/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// SetCreatorIDAnnotation sets the creatorID Annotation on the newObj based  on the user specified in the request.
func SetCreatorIDAnnotation(request *webhook.Request, response *webhook.Response, obj runtime.RawExtension, newObj metav1.Object) error {
	annotations := newObj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[auth.CreatorIDAnn] = request.UserInfo.Username
	newObj.SetAnnotations(annotations)
	if err := patch.CreatePatch(obj.Raw, newObj, response); err != nil {
		return fmt.Errorf("failed to create patch: %w", err)
	}
	return nil
}
