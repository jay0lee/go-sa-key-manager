package errors

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPolicyViolationError(t *testing.T) {
	origErr := errors.New("underlying error")
	pve := &PolicyViolationError{
		Constraint:  ConstraintDisableKeyCreation,
		Message:     "Key creation disabled",
		Remediation: "Use local generation",
		Err:         origErr,
	}

	expectedStr := fmt.Sprintf("GCP Organization Policy Restriction [%s]: %s\nRemediation: %s",
		ConstraintDisableKeyCreation, "Key creation disabled", "Use local generation")

	if pve.Error() != expectedStr {
		t.Fatalf("expected error string %q, got %q", expectedStr, pve.Error())
	}

	if !errors.Is(pve, origErr) {
		t.Fatalf("expected errors.Is to match unwrapped underlying error")
	}

	if !IsPolicyViolation(pve) {
		t.Fatalf("expected IsPolicyViolation to return true")
	}

	if IsPolicyViolation(errors.New("generic error")) {
		t.Fatalf("expected IsPolicyViolation to return false for generic error")
	}
}

func TestIAMError(t *testing.T) {
	origErr := errors.New("underlying error")
	ieWithRem := &IAMError{
		Code:        codes.PermissionDenied,
		Message:     "permission denied",
		Remediation: "request role",
		Err:         origErr,
	}

	expectedWithRem := "GCP IAM Error (PermissionDenied): permission denied\nRemediation: request role"
	if ieWithRem.Error() != expectedWithRem {
		t.Fatalf("expected %q, got %q", expectedWithRem, ieWithRem.Error())
	}

	if !errors.Is(ieWithRem, origErr) {
		t.Fatalf("expected errors.Is to match unwrapped error")
	}

	ieNoRem := &IAMError{
		Code:    codes.Internal,
		Message: "internal server error",
		Err:     origErr,
	}
	expectedNoRem := "GCP IAM Error (Internal): internal server error"
	if ieNoRem.Error() != expectedNoRem {
		t.Fatalf("expected %q, got %q", expectedNoRem, ieNoRem.Error())
	}
}

func TestWrapGCPError_Nil(t *testing.T) {
	if WrapGCPError(nil) != nil {
		t.Fatalf("expected nil for nil error")
	}
}

func TestWrapGCPError_GRPCStatus(t *testing.T) {
	tests := []struct {
		name                 string
		st                   *status.Status
		expectedCode         codes.Code
		isPolicyViolation    bool
		expectedConstraint   PolicyConstraint
		expectedRemediation  string
		checkRemediationText bool
	}{
		{
			name:                "Policy violation - disable key creation constraint string",
			st:                  status.New(codes.FailedPrecondition, "operation violates constraints/iam.disableServiceAccountKeyCreation"),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintDisableKeyCreation,
			expectedRemediation: "Use local key generation",
		},
		{
			name:                "Policy violation - disable key creation wording",
			st:                  status.New(codes.FailedPrecondition, "Key creation is disabled by organization policy"),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintDisableKeyCreation,
			expectedRemediation: "Use local key generation",
		},
		{
			name:                "Policy violation - key creation is not allowed",
			st:                  status.New(codes.FailedPrecondition, "Key creation is not allowed on this service account."),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintDisableKeyCreation,
			expectedRemediation: "Use local key generation",
		},
		{
			name:                "Policy violation - disable key upload constraint string",
			st:                  status.New(codes.FailedPrecondition, "operation violates constraints/iam.disableServiceAccountKeyUpload"),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintDisableKeyUpload,
			expectedRemediation: "Use GCP-managed key creation",
		},
		{
			name:                "Policy violation - disable key upload wording",
			st:                  status.New(codes.FailedPrecondition, "Key upload is disabled by organization policy"),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintDisableKeyUpload,
			expectedRemediation: "Use GCP-managed key creation",
		},
		{
			name:                "Policy violation - key expiry hours constraint string",
			st:                  status.New(codes.InvalidArgument, "violates constraints/iam.serviceAccountKeyExpiryHours"),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintKeyExpiryHours,
			expectedRemediation: "Specify a shorter validity period",
		},
		{
			name:                "Policy violation - key expiry hours wording",
			st:                  status.New(codes.InvalidArgument, "Expiration time exceeds the maximum allowed duration"),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintKeyExpiryHours,
			expectedRemediation: "Specify a shorter validity period",
		},
		{
			name:                "Policy violation - key validity exceeds wording",
			st:                  status.New(codes.InvalidArgument, "key validity exceeds maximum limit"),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintKeyExpiryHours,
			expectedRemediation: "Specify a shorter validity period",
		},
		{
			name:                "Policy violation - longer than max allowed lifetime wording",
			st:                  status.New(codes.InvalidArgument, "The given public key has a lifetime of 2,592,000 seconds, which is longer than the max allowed lifetime of 86,400 seconds as specified in resource settings or in organization policy."),
			isPolicyViolation:   true,
			expectedConstraint:  ConstraintKeyExpiryHours,
			expectedRemediation: "Specify a shorter validity period",
		},
		{
			name:                 "FailedPrecondition generic",
			st:                   status.New(codes.FailedPrecondition, "general precondition failed"),
			expectedCode:         codes.FailedPrecondition,
			checkRemediationText: true,
			expectedRemediation:  "A prerequisite check failed in GCP",
		},
		{
			name:                 "PermissionDenied",
			st:                   status.New(codes.PermissionDenied, "permission denied on resource"),
			expectedCode:         codes.PermissionDenied,
			checkRemediationText: true,
			expectedRemediation:  "roles/iam.serviceAccountKeyAdmin",
		},
		{
			name:                 "NotFound",
			st:                   status.New(codes.NotFound, "service account not found"),
			expectedCode:         codes.NotFound,
			checkRemediationText: true,
			expectedRemediation:  "Verify the service account email",
		},
		{
			name:                 "Unauthenticated",
			st:                   status.New(codes.Unauthenticated, "unauthenticated"),
			expectedCode:         codes.Unauthenticated,
			checkRemediationText: true,
			expectedRemediation:  "Application Default Credentials",
		},
		{
			name:                 "InvalidArgument",
			st:                   status.New(codes.InvalidArgument, "bad request parameter"),
			expectedCode:         codes.InvalidArgument,
			checkRemediationText: true,
			expectedRemediation:  "Check that input parameters",
		},
		{
			name:                 "AlreadyExists",
			st:                   status.New(codes.AlreadyExists, "key exists"),
			expectedCode:         codes.AlreadyExists,
			checkRemediationText: true,
			expectedRemediation:  "already exists",
		},
		{
			name:         "Other code (Internal)",
			st:           status.New(codes.Internal, "backend crashed"),
			expectedCode: codes.Internal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := WrapGCPError(tc.st.Err())
			if tc.isPolicyViolation {
				var pve *PolicyViolationError
				if !errors.As(err, &pve) {
					t.Fatalf("expected PolicyViolationError, got %T: %v", err, err)
				}
				if pve.Constraint != tc.expectedConstraint {
					t.Fatalf("expected constraint %v, got %v", tc.expectedConstraint, pve.Constraint)
				}
				if !strings.Contains(pve.Remediation, tc.expectedRemediation) {
					t.Fatalf("expected remediation to contain %q, got %q", tc.expectedRemediation, pve.Remediation)
				}
			} else {
				var ie *IAMError
				if !errors.As(err, &ie) {
					t.Fatalf("expected IAMError, got %T: %v", err, err)
				}
				if ie.Code != tc.expectedCode {
					t.Fatalf("expected code %v, got %v", tc.expectedCode, ie.Code)
				}
				if tc.checkRemediationText && !strings.Contains(ie.Remediation, tc.expectedRemediation) {
					t.Fatalf("expected remediation to contain %q, got %q", tc.expectedRemediation, ie.Remediation)
				}
			}
		})
	}
}

func TestWrapGCPError_PlainErrors(t *testing.T) {
	// Policy violation plain error
	err1 := errors.New("constraints/iam.disableServiceAccountKeyCreation error")
	wrapped1 := WrapGCPError(err1)
	if !IsPolicyViolation(wrapped1) {
		t.Fatalf("expected plain policy violation to be detected")
	}

	// ADC missing credentials plain error
	err2 := errors.New("could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information")
	wrapped2 := WrapGCPError(err2)
	var ie *IAMError
	if !errors.As(wrapped2, &ie) || ie.Code != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated IAMError for missing ADC credentials, got: %v", wrapped2)
	}

	// ADC credentials missing alternative phrasing
	err2b := errors.New("credentials are missing from environment")
	wrapped2b := WrapGCPError(err2b)
	if !errors.As(wrapped2b, &ie) || ie.Code != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated IAMError, got: %v", wrapped2b)
	}

	// Unrelated plain error
	err3 := errors.New("plain file not found error")
	wrapped3 := WrapGCPError(err3)
	if wrapped3 != err3 {
		t.Fatalf("expected original plain error to be returned unchanged, got: %v", wrapped3)
	}
}

func TestWrapGCPError_GoogleAPIError(t *testing.T) {
	// 1. Policy violation in Message or Body
	gErrPolicy := &googleapi.Error{
		Code:    412,
		Message: "Key creation is disabled by organization policy",
		Body:    `{"error": {"message": "constraints/iam.disableServiceAccountKeyCreation"}}`,
	}
	wrappedPolicy := WrapGCPError(gErrPolicy)
	if !IsPolicyViolation(wrappedPolicy) {
		t.Fatalf("expected policy violation for googleapi error")
	}

	// 2. HTTP codes mapping to IAMError
	codesMap := []struct {
		httpCode int
		expected codes.Code
	}{
		{400, codes.InvalidArgument},
		{401, codes.Unauthenticated},
		{403, codes.PermissionDenied},
		{404, codes.NotFound},
		{409, codes.AlreadyExists},
		{412, codes.FailedPrecondition},
		{429, codes.ResourceExhausted},
		{503, codes.Unavailable},
		{500, codes.Code(500)},
	}

	for _, tc := range codesMap {
		gErr := &googleapi.Error{
			Code:    tc.httpCode,
			Message: fmt.Sprintf("HTTP %d error", tc.httpCode),
		}
		wrapped := WrapGCPError(gErr)
		var ie *IAMError
		if !errors.As(wrapped, &ie) {
			t.Fatalf("expected IAMError for HTTP %d, got %T", tc.httpCode, wrapped)
		}
		if ie.Code != tc.expected {
			t.Fatalf("expected code %v for HTTP %d, got %v", tc.expected, tc.httpCode, ie.Code)
		}
	}
}

