package errors

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PolicyConstraint represents known GCP IAM organization policy constraints.
type PolicyConstraint string

const (
	ConstraintDisableKeyCreation PolicyConstraint = "constraints/iam.disableServiceAccountKeyCreation"
	ConstraintDisableKeyUpload   PolicyConstraint = "constraints/iam.disableServiceAccountKeyUpload"
	ConstraintKeyExpiryHours     PolicyConstraint = "constraints/iam.serviceAccountKeyExpiryHours"
)

// PolicyViolationError represents an error caused by a GCP organization policy restriction.
type PolicyViolationError struct {
	Constraint  PolicyConstraint
	Message     string
	Remediation string
	Err         error
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("GCP Organization Policy Restriction [%s]: %s\nRemediation: %s",
		e.Constraint, e.Message, e.Remediation)
}

func (e *PolicyViolationError) Unwrap() error {
	return e.Err
}

// IAMError represents an enriched GCP IAM API error.
type IAMError struct {
	Code        codes.Code
	Message     string
	Remediation string
	Err         error
}

func (e *IAMError) Error() string {
	if e.Remediation != "" {
		return fmt.Sprintf("GCP IAM Error (%s): %s\nRemediation: %s", e.Code, e.Message, e.Remediation)
	}
	return fmt.Sprintf("GCP IAM Error (%s): %s", e.Code, e.Message)
}

func (e *IAMError) Unwrap() error {
	return e.Err
}

// WrapGCPError analyzes an error returned from GCP IAM API calls and produces a human-friendly error.
func WrapGCPError(err error) error {
	if err == nil {
		return nil
	}

	// Check gRPC status
	st, ok := status.FromError(err)
	if !ok {
		// Plain error or HTTP error
		return inspectPlainError(err)
	}

	msg := st.Message()
	code := st.Code()

	// Check for organization policy violations in status message
	if violation := detectPolicyViolation(msg, err); violation != nil {
		return violation
	}

	switch code {
	case codes.FailedPrecondition:
		return &IAMError{
			Code:        code,
			Message:     msg,
			Remediation: "A prerequisite check failed in GCP. Verify that organization policies or service account state allow this operation.",
			Err:         err,
		}

	case codes.PermissionDenied:
		return &IAMError{
			Code:        code,
			Message:     msg,
			Remediation: "Ensure your authenticated identity (ADC) has the 'roles/iam.serviceAccountKeyAdmin' role or equivalent permissions on the target service account.",
			Err:         err,
		}

	case codes.NotFound:
		return &IAMError{
			Code:        code,
			Message:     msg,
			Remediation: "Verify the service account email and key ID are correct and exist in the specified project.",
			Err:         err,
		}

	case codes.Unauthenticated:
		return &IAMError{
			Code:        code,
			Message:     msg,
			Remediation: "Google Cloud Application Default Credentials (ADC) are missing or expired. Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.",
			Err:         err,
		}

	case codes.InvalidArgument:
		return &IAMError{
			Code:        code,
			Message:     msg,
			Remediation: "Check that input parameters (key format, certificate data, expiration time, or service account email) match GCP requirements.",
			Err:         err,
		}

	case codes.AlreadyExists:
		return &IAMError{
			Code:        code,
			Message:     msg,
			Remediation: "The specified key or resource already exists.",
			Err:         err,
		}

	default:
		return &IAMError{
			Code:    code,
			Message: msg,
			Err:     err,
		}
	}
}

func inspectPlainError(err error) error {
	msg := err.Error()
	if violation := detectPolicyViolation(msg, err); violation != nil {
		return violation
	}

	if strings.Contains(msg, "could not find default credentials") || (strings.Contains(msg, "credentials") && strings.Contains(msg, "missing")) {
		return &IAMError{
			Code:        codes.Unauthenticated,
			Message:     msg,
			Remediation: "Google Cloud Application Default Credentials (ADC) were not found. Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.",
			Err:         err,
		}
	}

	return err
}

func detectPolicyViolation(msg string, err error) *PolicyViolationError {
	lowerMsg := strings.ToLower(msg)

	// Check key creation constraint
	if strings.Contains(msg, string(ConstraintDisableKeyCreation)) ||
		(strings.Contains(lowerMsg, "disable") && strings.Contains(lowerMsg, "key creation")) ||
		strings.Contains(lowerMsg, "key creation is not allowed") ||
		strings.Contains(lowerMsg, "key creation is disabled by organization policy") {
		return &PolicyViolationError{
			Constraint:  ConstraintDisableKeyCreation,
			Message:     "GCP-managed key creation is blocked by organization policy 'constraints/iam.disableServiceAccountKeyCreation'.",
			Remediation: "Use local key generation ('generate' command) to upload a user-managed public key, or request an organization policy exemption.",
			Err:         err,
		}
	}

	// Check key upload constraint
	if strings.Contains(msg, string(ConstraintDisableKeyUpload)) ||
		(strings.Contains(lowerMsg, "disable") && strings.Contains(lowerMsg, "key upload")) ||
		strings.Contains(lowerMsg, "key upload is disabled by organization policy") {
		return &PolicyViolationError{
			Constraint:  ConstraintDisableKeyUpload,
			Message:     "User-managed key upload is blocked by organization policy 'constraints/iam.disableServiceAccountKeyUpload'.",
			Remediation: "Use GCP-managed key creation ('create' command) if allowed, or consider using Workload Identity Federation instead of static keys.",
			Err:         err,
		}
	}

	// Check key expiry hours constraint
	if strings.Contains(msg, string(ConstraintKeyExpiryHours)) ||
		strings.Contains(lowerMsg, "keyexpiryhours") ||
		strings.Contains(lowerMsg, "expiration time exceeds the maximum allowed duration") ||
		strings.Contains(lowerMsg, "longer than the max allowed lifetime") ||
		strings.Contains(lowerMsg, "key validity exceeds") {
		return &PolicyViolationError{
			Constraint:  ConstraintKeyExpiryHours,
			Message:     "The requested key expiration duration exceeds the organization policy 'constraints/iam.serviceAccountKeyExpiryHours'.",
			Remediation: "Specify a shorter validity period using '--validity' (e.g. '--validity 24h' or '--validity 168h') to comply with your organization's policy.",
			Err:         err,
		}
	}

	return nil
}

// IsPolicyViolation returns true if the error is or wraps a PolicyViolationError.
func IsPolicyViolation(err error) bool {
	var pve *PolicyViolationError
	return errors.As(err, &pve)
}
