package resolvers_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

var errNotFound = errors.New("notFound")

const invalidName = "invalidName"

type Rules []rbacv1.PolicyRule

func (r Rules) Len() int      { return len(r) }
func (r Rules) Swap(i, j int) { r[i], r[j] = r[j], r[i] }
func (r Rules) Less(i, j int) bool {
	iData, _ := json.Marshal(r[i])
	jData, _ := json.Marshal(r[j])
	return string(iData) < string(jData)
}

// Equal check if to list of policy rules are equal ignoring rule order, but not duplicates.
func (r Rules) Equal(r2 Rules) bool {
	if (r == nil || r.Len() == 0) && (r2 == nil || r2.Len() == 0) {
		return true
	}
	if r == nil || r2 == nil {
		return false
	}
	if r.Len() != r2.Len() {
		return false
	}
	// sort the list since we don't care about rule order
	sort.Stable(r)
	sort.Stable(r2)

	for i := range r {
		if !reflect.DeepEqual(r[i], r2[i]) {
			return false
		}
	}
	return true
}
func NewUserInfo(username string) *user.DefaultInfo {
	return &user.DefaultInfo{
		Name: username,
	}
}
