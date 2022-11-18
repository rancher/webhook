// Package health handles health checking for the webhook
package health

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"k8s.io/apiserver/pkg/server/healthz"
)

var errNotReady = fmt.Errorf("not ready")

// RegisterHealthCheckers adds the healthz endpoint to the webhook.
func RegisterHealthCheckers(router *mux.Router, checkers ...healthz.HealthChecker) {
	healthz.InstallHandler(&muxWrapper{router}, checkers...)
}

// NewErrorChecker returns a new error checker initialized with a "not ready" error
func NewErrorChecker(name string) *ErrorChecker {
	return &ErrorChecker{
		name:      name,
		lastError: errNotReady,
	}
}

// ErrorChecker is a HealthChecker that returns the  last stored error.
type ErrorChecker struct {
	name      string
	lastError error
	mutex     sync.RWMutex
}

// Name returns the Name of the checker.
func (e *ErrorChecker) Name() string { return e.name }

// Check returns the last error stored.
func (e *ErrorChecker) Check(_ *http.Request) error {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	retError := e.lastError
	return retError
}

// Store the given error as the last seen error
func (e *ErrorChecker) Store(err error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.lastError = err
}

type muxWrapper struct {
	*mux.Router
}

// Handle is a wrapper for mux.Handle that has no return.
func (m *muxWrapper) Handle(path string, handler http.Handler) {
	m.Router.Handle(path, handler)
}
