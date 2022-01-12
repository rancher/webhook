package patch

import (
	"encoding/json"

	"github.com/rancher/wrangler/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// CreatePatch accepts an old and a new object and creates a patch of the differences as
// specified in http://jsonpatch.com/ and updates the response accordingly.
func CreatePatch(old, new interface{}, response *webhook.Response) error {
	oldJSON, err := json.Marshal(old)
	if err != nil {
		return err
	}
	newJSON, err := json.Marshal(new)
	if err != nil {
		return err
	}

	patch := admission.PatchResponseFromRaw(oldJSON, newJSON)

	patchJSON, err := json.Marshal(patch.Patches)
	if err != nil {
		return err
	}

	response.Patch = patchJSON
	response.PatchType = patch.PatchType
	response.Allowed = patch.Allowed
	return nil
}
