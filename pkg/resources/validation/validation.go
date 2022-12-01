package validation

import (
	"fmt"
)

// ErrInvalidRequest error returned when the requested operation with the requested fields are invalid.
var ErrInvalidRequest = fmt.Errorf("invalid request")
