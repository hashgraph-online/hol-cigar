package cigar

import "fmt"

// RetryClass is frozen server retry guidance.
type RetryClass string

const (
	RetryNever                RetryClass = "never"
	RetrySafe                 RetryClass = "safe"
	RetryAfterBackoff         RetryClass = "after_backoff"
	RetryAfterReauthorization RetryClass = "after_reauthorization"
	RetryAfterReconciliation  RetryClass = "after_reconciliation"
)

// ErrorDefinition is one generated stable catalog entry.
type ErrorDefinition struct {
	NumericCode uint32
	HTTPStatus  int
	GRPCStatus  string
	Retry       string
	Message     string
	Remediation string
}

// ValidationError reports a caller value rejected before I/O.
type ValidationError struct{ Message string }

func (err *ValidationError) Error() string { return "cigar validation: " + err.Message }

// TransportError reports an HTTP or wire-integrity failure.
type TransportError struct {
	Message string
	Cause   error
}

func (err *TransportError) Error() string { return "cigar transport: " + err.Message }
func (err *TransportError) Unwrap() error { return err.Cause }

// CompatibilityError reports an incompatible API version.
type CompatibilityError struct{ ServerVersion string }

func (err *CompatibilityError) Error() string {
	return fmt.Sprintf("cigar API version %s is incompatible with 1", err.ServerVersion)
}

// TimeoutError reports a bounded deadline.
type TimeoutError struct{ Cause error }

func (err *TimeoutError) Error() string { return "cigar request deadline elapsed" }
func (err *TimeoutError) Unwrap() error { return err.Cause }

// APIError is an exact validated cigar.problem.v1 response.
type APIError struct {
	Status        int
	Code          string
	NumericCode   uint32
	Retry         RetryClass
	Message       string
	Remediation   string
	CorrelationID string
	details       map[string]any
}

func (err *APIError) Error() string { return fmt.Sprintf("%s (CIGAR %s)", err.Message, err.Code) }

// Details returns a deep caller-owned copy of the validated JSON details.
func (err *APIError) Details() map[string]any {
	result, cloneErr := cloneJSONMap(err.details)
	if cloneErr != nil {
		panic("cigar: validated problem details failed internal copy: " + cloneErr.Error())
	}
	return result
}
