package mutation

import (
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/wrangler/pkg/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func SetCreatorIDAnnotation(request *webhook.Request, response *webhook.Response, obj runtime.Object, newObj metav1.Object) error {
	annotations := newObj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[auth.CreatorIDAnn] = request.UserInfo.Username
	newObj.SetAnnotations(annotations)

	return patch.CreatePatch(obj, newObj, response)
}
