package client

import (
	"context"
	"strings"
	"time"
)

// KeyType represents the type of GCP service account key.
type KeyType string

const (
	KeyTypeUnspecified   KeyType = "KEY_TYPE_UNSPECIFIED"
	KeyTypeUserManaged   KeyType = "USER_MANAGED"
	KeyTypeSystemManaged KeyType = "SYSTEM_MANAGED"
)

// KeyInfo encapsulates details about a GCP Service Account key.
type KeyInfo struct {
	ID              string    `json:"id" yaml:"id"`
	Name            string    `json:"name" yaml:"name"`
	KeyType         KeyType   `json:"key_type" yaml:"key_type"`
	KeyAlgorithm    string    `json:"key_algorithm" yaml:"key_algorithm"`
	ValidAfterTime  time.Time `json:"valid_after_time" yaml:"valid_after_time"`
	ValidBeforeTime time.Time `json:"valid_before_time" yaml:"valid_before_time"`
	Disabled        bool      `json:"disabled" yaml:"disabled"`
	PrivateKeyData  []byte    `json:"private_key_data,omitempty" yaml:"private_key_data,omitempty"`
	PublicKeyData   []byte    `json:"public_key_data,omitempty" yaml:"public_key_data,omitempty"`
}

// IAMClient defines operations supported on GCP Service Account keys.
type IAMClient interface {
	ListKeys(ctx context.Context, saEmail string, keyTypes []KeyType) ([]*KeyInfo, error)
	GetKey(ctx context.Context, saEmail, keyID string) (*KeyInfo, error)
	CreateKey(ctx context.Context, saEmail string) (*KeyInfo, error)
	UploadKey(ctx context.Context, saEmail string, publicKeyCertPEM []byte) (*KeyInfo, error)
	DeleteKey(ctx context.Context, saEmail, keyID string) error
	DisableKey(ctx context.Context, saEmail, keyID string) error
	EnableKey(ctx context.Context, saEmail, keyID string) error
	Close() error
}

// FormatServiceAccountResourceName formats the resource name for a service account.
func FormatServiceAccountResourceName(saEmail string) string {
	return "projects/-/serviceAccounts/" + saEmail
}

// FormatKeyResourceName formats the resource name for a service account key.
func FormatKeyResourceName(saEmail, keyID string) string {
	return "projects/-/serviceAccounts/" + saEmail + "/keys/" + keyID
}

// ExtractKeyID extracts the key ID from a GCP resource name.
// E.g.: "projects/my-proj/serviceAccounts/sa@.../keys/12345" -> "12345"
func ExtractKeyID(resourceName string) string {
	idx := strings.LastIndex(resourceName, "/keys/")
	if idx != -1 {
		return resourceName[idx+len("/keys/"):]
	}
	parts := strings.Split(resourceName, "/")
	return parts[len(parts)-1]
}
