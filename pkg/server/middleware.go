package server

import (
	"strings"

	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/sirupsen/logrus"
)

func access(next webhook.Handler) webhook.Handler {
	return webhook.HandlerFunc(func(res *webhook.Response, req *webhook.Request) error {
		var resource string
		if req.Namespace != "" {
			resource = strings.Join([]string{req.Namespace, req.Name}, "/")
		} else {
			resource = req.Name
		}
		gvk := req.Kind.Group + "/" + req.Kind.Version + "." + req.Kind.Kind
		err := next.Admit(res, req)
		logrus.Debugf("%s %s %s user=%s allowed=%v", req.Operation, gvk, resource, req.UserInfo.Username, res.Allowed)
		return err
	})
}
