// Package health handles health checking for the webhook
package health

import (
	"fmt"
	"net/http"
	"sync"

	"k8s.io/apiserver/pkg/server/healthz"
)

var errNotReady = fmt.Errorf("not ready")

// RegisterHealthCheckers adds the healthz endpoint to the webhook.
func RegisterHealthCheckers(router *http.ServeMux, checkers ...healthz.HealthChecker) {
	healthz.InstallHandler(router, checkers...)
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
	return e.lastError
}

// Store the given error as the last seen error
func (e *ErrorChecker) Store(err error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.lastError = err
}
