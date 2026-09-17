package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jay0lee/go-sa-key-manager/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MockIAMClient provides an in-memory implementation of IAMClient for unit tests.
type MockIAMClient struct {
	mu   sync.Mutex
	Keys map[string]map[string]*KeyInfo // saEmail -> keyID -> KeyInfo

	ListKeysErr   error
	GetKeyErr     error
	CreateKeyErr  error
	UploadKeyErr  error
	DeleteKeyErr  error
	DisableKeyErr error
	EnableKeyErr  error
	CloseErr      error
}

// NewMockIAMClient creates a new thread-safe MockIAMClient.
func NewMockIAMClient() *MockIAMClient {
	return &MockIAMClient{
		Keys: make(map[string]map[string]*KeyInfo),
	}
}

// AddKey adds a key directly to the mock store.
func (m *MockIAMClient) AddKey(saEmail string, key *KeyInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.Keys[saEmail]; !ok {
		m.Keys[saEmail] = make(map[string]*KeyInfo)
	}
	m.Keys[saEmail][key.ID] = key
}

// ListKeys returns keys for the service account.
func (m *MockIAMClient) ListKeys(ctx context.Context, saEmail string, keyTypes []KeyType) ([]*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ListKeysErr != nil {
		return nil, errors.WrapGCPError(m.ListKeysErr)
	}

	saKeys, ok := m.Keys[saEmail]
	if !ok {
		return []*KeyInfo{}, nil
	}

	var results []*KeyInfo
	for _, k := range saKeys {
		if len(keyTypes) == 0 {
			results = append(results, k)
			continue
		}
		match := false
		for _, kt := range keyTypes {
			if k.KeyType == kt {
				match = true
				break
			}
		}
		if match {
			results = append(results, k)
		}
	}
	return results, nil
}

// GetKey retrieves a specific key.
func (m *MockIAMClient) GetKey(ctx context.Context, saEmail, keyID string) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.GetKeyErr != nil {
		return nil, errors.WrapGCPError(m.GetKeyErr)
	}

	saKeys, ok := m.Keys[saEmail]
	if !ok {
		return nil, errors.WrapGCPError(status.Errorf(codes.NotFound, "service account %q not found", saEmail))
	}

	k, ok := saKeys[keyID]
	if !ok {
		return nil, errors.WrapGCPError(status.Errorf(codes.NotFound, "key %q not found", keyID))
	}

	return k, nil
}

// CreateKey simulates creating a GCP-managed key pair.
func (m *MockIAMClient) CreateKey(ctx context.Context, saEmail string) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.CreateKeyErr != nil {
		return nil, errors.WrapGCPError(m.CreateKeyErr)
	}

	keyID := fmt.Sprintf("mock-key-%d", time.Now().UnixNano())
	k := &KeyInfo{
		ID:              keyID,
		Name:            FormatKeyResourceName(saEmail, keyID),
		KeyType:         KeyTypeUserManaged,
		KeyAlgorithm:    "KEY_ALG_RSA_2048",
		ValidAfterTime:  time.Now(),
		ValidBeforeTime: time.Now().Add(87600 * time.Hour), // 10 years
		Disabled:        false,
		PrivateKeyData:  []byte(fmt.Sprintf(`{"type":"service_account","private_key_id":%q,"client_email":%q}`, keyID, saEmail)),
	}

	if _, ok := m.Keys[saEmail]; !ok {
		m.Keys[saEmail] = make(map[string]*KeyInfo)
	}
	m.Keys[saEmail][keyID] = k

	return k, nil
}

// UploadKey simulates uploading a public key certificate.
func (m *MockIAMClient) UploadKey(ctx context.Context, saEmail string, publicKeyCertPEM []byte) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.UploadKeyErr != nil {
		return nil, errors.WrapGCPError(m.UploadKeyErr)
	}

	keyID := fmt.Sprintf("upload-key-%d", time.Now().UnixNano())
	k := &KeyInfo{
		ID:              keyID,
		Name:            FormatKeyResourceName(saEmail, keyID),
		KeyType:         KeyTypeUserManaged,
		KeyAlgorithm:    "KEY_ALG_RSA_2048",
		ValidAfterTime:  time.Now(),
		ValidBeforeTime: time.Now().Add(2160 * time.Hour),
		Disabled:        false,
		PublicKeyData:   publicKeyCertPEM,
	}

	if _, ok := m.Keys[saEmail]; !ok {
		m.Keys[saEmail] = make(map[string]*KeyInfo)
	}
	m.Keys[saEmail][keyID] = k

	return k, nil
}

// DeleteKey simulates permanently deleting a key.
func (m *MockIAMClient) DeleteKey(ctx context.Context, saEmail, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.DeleteKeyErr != nil {
		return errors.WrapGCPError(m.DeleteKeyErr)
	}

	saKeys, ok := m.Keys[saEmail]
	if !ok {
		return errors.WrapGCPError(status.Errorf(codes.NotFound, "service account %q not found", saEmail))
	}

	if _, ok := saKeys[keyID]; !ok {
		return errors.WrapGCPError(status.Errorf(codes.NotFound, "key %q not found", keyID))
	}

	delete(saKeys, keyID)
	return nil
}

// DisableKey disables a key.
func (m *MockIAMClient) DisableKey(ctx context.Context, saEmail, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.DisableKeyErr != nil {
		return errors.WrapGCPError(m.DisableKeyErr)
	}

	saKeys, ok := m.Keys[saEmail]
	if !ok {
		return errors.WrapGCPError(status.Errorf(codes.NotFound, "service account %q not found", saEmail))
	}

	k, ok := saKeys[keyID]
	if !ok {
		return errors.WrapGCPError(status.Errorf(codes.NotFound, "key %q not found", keyID))
	}

	k.Disabled = true
	return nil
}

// EnableKey enables a key.
func (m *MockIAMClient) EnableKey(ctx context.Context, saEmail, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.EnableKeyErr != nil {
		return errors.WrapGCPError(m.EnableKeyErr)
	}

	saKeys, ok := m.Keys[saEmail]
	if !ok {
		return errors.WrapGCPError(status.Errorf(codes.NotFound, "service account %q not found", saEmail))
	}

	k, ok := saKeys[keyID]
	if !ok {
		return errors.WrapGCPError(status.Errorf(codes.NotFound, "key %q not found", keyID))
	}

	k.Disabled = false
	return nil
}

// Close simulates closing the client.
func (m *MockIAMClient) Close() error {
	return m.CloseErr
}
