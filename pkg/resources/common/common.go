package common

import (
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
)

// ConvertAuthnExtras converts authnv1 type extras to authzv1 extras. Technically these are both
// type alias to string, so the conversion is straightforward
func ConvertAuthnExtras(extra map[string]authnv1.ExtraValue) map[string]authzv1.ExtraValue {
	result := map[string]authzv1.ExtraValue{}
	for k, v := range extra {
		result[k] = authzv1.ExtraValue(v)
	}
	return result
}
