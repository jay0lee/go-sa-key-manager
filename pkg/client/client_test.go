package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

func TestResourceNameHelpers(t *testing.T) {
	sa := "my-sa@proj.iam.gserviceaccount.com"
	keyID := "123456789"

	saName := FormatServiceAccountResourceName(sa)
	if saName != "projects/-/serviceAccounts/my-sa@proj.iam.gserviceaccount.com" {
		t.Fatalf("unexpected sa name: %s", saName)
	}

	keyName := FormatKeyResourceName(sa, keyID)
	if keyName != "projects/-/serviceAccounts/my-sa@proj.iam.gserviceaccount.com/keys/123456789" {
		t.Fatalf("unexpected key name: %s", keyName)
	}

	extracted := ExtractKeyID(keyName)
	if extracted != keyID {
		t.Fatalf("unexpected extracted key ID: %s", extracted)
	}

	rawID := ExtractKeyID(keyID)
	if rawID != keyID {
		t.Fatalf("unexpected raw key ID: %s", rawID)
	}
}

func TestMockIAMClient(t *testing.T) {
	ctx := context.Background()
	mock := NewMockIAMClient()
	sa := "test-sa@project.iam.gserviceaccount.com"
	now := time.Now()

	// 0. Nonexistent SA ListKeys
	nonexistentKeys, err := mock.ListKeys(ctx, "nonexistent@sa.com", nil)
	if err != nil || len(nonexistentKeys) != 0 {
		t.Fatalf("expected empty slice for nonexistent SA, got %v, err=%v", nonexistentKeys, err)
	}

	// 1. UploadKey on fresh SA (map initialization)
	freshMock := NewMockIAMClient()
	if _, err := freshMock.UploadKey(ctx, "fresh@sa.com", []byte("fake-cert")); err != nil {
		t.Fatalf("unexpected upload on fresh SA: %v", err)
	}

	// 1. CreateKey
	created, err := mock.CreateKey(ctx, sa)
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	keyID := created.ID

	// 2. UploadKey
	uploaded, err := mock.UploadKey(ctx, sa, []byte("fake-cert"))
	if err != nil {
		t.Fatalf("unexpected upload error: %v", err)
	}

	// 3. Add system key manually
	mock.AddKey(sa, &KeyInfo{
		ID:              "sys-key-1",
		KeyType:         KeyTypeSystemManaged,
		ValidBeforeTime: now.Add(24 * time.Hour),
	})

	// 4. ListKeys all
	keys, err := mock.ListKeys(ctx, sa, []KeyType{KeyTypeUserManaged, KeyTypeSystemManaged})
	if err != nil || len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d (err: %v)", len(keys), err)
	}

	// 5. ListKeys filtered
	userKeys, err := mock.ListKeys(ctx, sa, []KeyType{KeyTypeUserManaged})
	if err != nil || len(userKeys) != 2 {
		t.Fatalf("expected 2 user keys, got %d", len(userKeys))
	}

	sysKeys, err := mock.ListKeys(ctx, sa, []KeyType{KeyTypeSystemManaged})
	if err != nil || len(sysKeys) != 1 {
		t.Fatalf("expected 1 system key, got %d", len(sysKeys))
	}

	allKeys, err := mock.ListKeys(ctx, sa, nil)
	if err != nil || len(allKeys) != 3 {
		t.Fatalf("expected 3 total keys, got %d", len(allKeys))
	}

	// 6. GetKey
	got, err := mock.GetKey(ctx, sa, keyID)
	if err != nil || got.ID != keyID {
		t.Fatalf("expected key %s, got: %v, err: %v", keyID, got, err)
	}

	// 7. GetKey Not Found
	if _, err := mock.GetKey(ctx, "nonexistent@sa.com", keyID); err == nil {
		t.Fatalf("expected error for nonexistent SA")
	}
	if _, err := mock.GetKey(ctx, sa, "bad-key-id"); err == nil {
		t.Fatalf("expected error for nonexistent key ID")
	}

	// 8. DisableKey & EnableKey
	if err := mock.DisableKey(ctx, sa, keyID); err != nil {
		t.Fatalf("unexpected disable error: %v", err)
	}
	if got, _ := mock.GetKey(ctx, sa, keyID); !got.Disabled {
		t.Fatalf("expected key to be disabled")
	}
	if err := mock.EnableKey(ctx, sa, keyID); err != nil {
		t.Fatalf("unexpected enable error: %v", err)
	}
	if got, _ := mock.GetKey(ctx, sa, keyID); got.Disabled {
		t.Fatalf("expected key to be enabled")
	}

	// Disable/Enable error checks
	if err := mock.DisableKey(ctx, "nonexistent@sa.com", keyID); err == nil {
		t.Fatalf("expected error disabling nonexistent SA")
	}
	if err := mock.DisableKey(ctx, sa, "bad-id"); err == nil {
		t.Fatalf("expected error disabling nonexistent key ID")
	}
	if err := mock.EnableKey(ctx, "nonexistent@sa.com", keyID); err == nil {
		t.Fatalf("expected error enabling nonexistent SA")
	}
	if err := mock.EnableKey(ctx, sa, "bad-id"); err == nil {
		t.Fatalf("expected error enabling nonexistent key ID")
	}

	// 9. DeleteKey
	if err := mock.DeleteKey(ctx, sa, keyID); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}
	if err := mock.DeleteKey(ctx, "nonexistent@sa.com", keyID); err == nil {
		t.Fatalf("expected error deleting nonexistent SA")
	}
	if err := mock.DeleteKey(ctx, sa, "bad-id"); err == nil {
		t.Fatalf("expected error deleting nonexistent key")
	}

	// 10. Close
	if err := mock.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	// 11. Injected errors
	simErr := errors.New("simulated error")
	mock.ListKeysErr = simErr
	if _, err := mock.ListKeys(ctx, sa, nil); err == nil {
		t.Fatalf("expected injected ListKeysErr")
	}

	mock.GetKeyErr = simErr
	if _, err := mock.GetKey(ctx, sa, "id"); err == nil {
		t.Fatalf("expected injected GetKeyErr")
	}

	mock.CreateKeyErr = simErr
	if _, err := mock.CreateKey(ctx, sa); err == nil {
		t.Fatalf("expected injected CreateKeyErr")
	}

	mock.UploadKeyErr = simErr
	if _, err := mock.UploadKey(ctx, sa, nil); err == nil {
		t.Fatalf("expected injected UploadKeyErr")
	}

	mock.DeleteKeyErr = simErr
	if err := mock.DeleteKey(ctx, sa, "id"); err == nil {
		t.Fatalf("expected injected DeleteKeyErr")
	}

	mock.DisableKeyErr = simErr
	if err := mock.DisableKey(ctx, sa, "id"); err == nil {
		t.Fatalf("expected injected DisableKeyErr")
	}

	mock.EnableKeyErr = simErr
	if err := mock.EnableKey(ctx, sa, "id"); err == nil {
		t.Fatalf("expected injected EnableKeyErr")
	}

	mock.CloseErr = simErr
	if err := mock.Close(); err == nil {
		t.Fatalf("expected injected CloseErr")
	}
	_ = uploaded
}

// fakeAdminAPI mocks the underlying iamAdminAPI for GCPClient tests
type fakeAdminAPI struct {
	listResp   []*iam.ServiceAccountKey
	listErr    error
	getResp    *iam.ServiceAccountKey
	getErr     error
	createResp *iam.ServiceAccountKey
	createErr  error
	uploadResp *iam.ServiceAccountKey
	uploadErr  error
	deleteErr  error
	disableErr error
	enableErr  error
	closeErr   error
}

func (f *fakeAdminAPI) ListServiceAccountKeys(ctx context.Context, parent string, keyTypes []string) ([]*iam.ServiceAccountKey, error) {
	return f.listResp, f.listErr
}
func (f *fakeAdminAPI) GetServiceAccountKey(ctx context.Context, name string) (*iam.ServiceAccountKey, error) {
	return f.getResp, f.getErr
}
func (f *fakeAdminAPI) CreateServiceAccountKey(ctx context.Context, parent string, req *iam.CreateServiceAccountKeyRequest) (*iam.ServiceAccountKey, error) {
	return f.createResp, f.createErr
}
func (f *fakeAdminAPI) UploadServiceAccountKey(ctx context.Context, parent string, req *iam.UploadServiceAccountKeyRequest) (*iam.ServiceAccountKey, error) {
	return f.uploadResp, f.uploadErr
}
func (f *fakeAdminAPI) DeleteServiceAccountKey(ctx context.Context, name string) error {
	return f.deleteErr
}
func (f *fakeAdminAPI) DisableServiceAccountKey(ctx context.Context, name string) error {
	return f.disableErr
}
func (f *fakeAdminAPI) EnableServiceAccountKey(ctx context.Context, name string) error {
	return f.enableErr
}
func (f *fakeAdminAPI) Close() error {
	return f.closeErr
}

func TestGCPClient_Operations(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	nowStr := now.Format(time.RFC3339)

	key1 := &iam.ServiceAccountKey{
		Name:            "projects/-/serviceAccounts/sa@proj.com/keys/k1",
		PrivateKeyType:  "TYPE_GOOGLE_CREDENTIALS_FILE",
		KeyAlgorithm:    "KEY_ALG_RSA_2048",
		KeyType:         "USER_MANAGED",
		ValidAfterTime:  nowStr,
		ValidBeforeTime: nowStr,
		Disabled:        false,
		PrivateKeyData:  base64.StdEncoding.EncodeToString([]byte("priv-data")),
		PublicKeyData:   base64.StdEncoding.EncodeToString([]byte("pub-data")),
	}

	key2 := &iam.ServiceAccountKey{
		Name:            "projects/-/serviceAccounts/sa@proj.com/keys/k2",
		KeyType:         "SYSTEM_MANAGED",
		ValidAfterTime:  nowStr,
		ValidBeforeTime: nowStr,
		Disabled:        true,
		PublicKeyData:   "raw-pem-data",
	}

	key3 := &iam.ServiceAccountKey{
		Name:            "projects/-/serviceAccounts/sa@proj.com/keys/k3",
		KeyType:         "KEY_TYPE_UNSPECIFIED",
		ValidAfterTime:  "",
		ValidBeforeTime: "",
	}

	fake := &fakeAdminAPI{
		listResp:   []*iam.ServiceAccountKey{key1, key2, key3},
		getResp:    key1,
		createResp: key1,
		uploadResp: key1,
	}

	client := &GCPClient{api: fake}

	// 1. ListKeys
	keys, err := client.ListKeys(ctx, "sa@proj.com", []KeyType{KeyTypeUserManaged, KeyTypeSystemManaged, KeyTypeUnspecified})
	if err != nil || len(keys) != 3 {
		t.Fatalf("unexpected list keys result: %d, err=%v", len(keys), err)
	}
	if keys[0].ID != "k1" || keys[0].KeyType != KeyTypeUserManaged {
		t.Fatalf("unexpected key[0] data: %+v", keys[0])
	}
	if keys[1].ID != "k2" || keys[1].KeyType != KeyTypeSystemManaged {
		t.Fatalf("unexpected key[1] data: %+v", keys[1])
	}
	if keys[2].ID != "k3" || keys[2].KeyType != KeyTypeUnspecified {
		t.Fatalf("unexpected key[2] data: %+v", keys[2])
	}

	fake.listErr = errors.New("list failed")
	if _, err := client.ListKeys(ctx, "sa@proj.com", nil); err == nil {
		t.Fatalf("expected list keys error")
	}

	// 2. GetKey
	got, err := client.GetKey(ctx, "sa@proj.com", "k1")
	if err != nil || got.ID != "k1" {
		t.Fatalf("unexpected get key result: %+v, err=%v", got, err)
	}
	fake.getErr = errors.New("get failed")
	if _, err := client.GetKey(ctx, "sa@proj.com", "k1"); err == nil {
		t.Fatalf("expected get key error")
	}

	// 3. CreateKey
	created, err := client.CreateKey(ctx, "sa@proj.com")
	if err != nil || created.ID != "k1" {
		t.Fatalf("unexpected create key result: %+v, err=%v", created, err)
	}
	fake.createErr = errors.New("create failed")
	if _, err := client.CreateKey(ctx, "sa@proj.com"); err == nil {
		t.Fatalf("expected create key error")
	}

	// 4. UploadKey
	uploaded, err := client.UploadKey(ctx, "sa@proj.com", []byte("pem"))
	if err != nil || uploaded.ID != "k1" {
		t.Fatalf("unexpected upload key result: %+v, err=%v", uploaded, err)
	}
	fake.uploadErr = errors.New("upload failed")
	if _, err := client.UploadKey(ctx, "sa@proj.com", []byte("pem")); err == nil {
		t.Fatalf("expected upload key error")
	}

	// 5. DeleteKey
	if err := client.DeleteKey(ctx, "sa@proj.com", "k1"); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}
	fake.deleteErr = errors.New("delete failed")
	if err := client.DeleteKey(ctx, "sa@proj.com", "k1"); err == nil {
		t.Fatalf("expected delete key error")
	}

	// 6. DisableKey
	if err := client.DisableKey(ctx, "sa@proj.com", "k1"); err != nil {
		t.Fatalf("unexpected disable error: %v", err)
	}
	fake.disableErr = errors.New("disable failed")
	if err := client.DisableKey(ctx, "sa@proj.com", "k1"); err == nil {
		t.Fatalf("expected disable key error")
	}

	// 7. EnableKey
	if err := client.EnableKey(ctx, "sa@proj.com", "k1"); err != nil {
		t.Fatalf("unexpected enable error: %v", err)
	}
	fake.enableErr = errors.New("enable failed")
	if err := client.EnableKey(ctx, "sa@proj.com", "k1"); err == nil {
		t.Fatalf("expected enable key error")
	}

	// 8. Close
	if err := client.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	// 9. iamToKeyInfo nil
	if iamToKeyInfo(nil) != nil {
		t.Fatalf("expected nil for iamToKeyInfo(nil)")
	}
}

func TestNewGCPClient(t *testing.T) {
	ctx := context.Background()

	origFactory := defaultClientFactory
	defer func() { defaultClientFactory = origFactory }()

	var passedOpts GCPClientOptions
	defaultClientFactory = func(ctx context.Context, opts GCPClientOptions) (iamAdminAPI, error) {
		passedOpts = opts
		return &fakeAdminAPI{}, nil
	}

	// 1. Success with debug options
	client1, err := NewGCPClient(ctx, GCPClientOptions{DebugHTTP: true, MaskTokens: true})
	if err != nil || client1 == nil {
		t.Fatalf("unexpected error creating GCPClient: %v", err)
	}
	if !passedOpts.DebugHTTP || !passedOpts.MaskTokens {
		t.Fatalf("expected DebugHTTP and MaskTokens to be passed")
	}

	// 2. Success with credentials file
	client2, err := NewGCPClient(ctx, GCPClientOptions{CredentialsFile: "/path/to/creds.json"})
	if err != nil || client2 == nil {
		t.Fatalf("unexpected error creating GCPClient with creds: %v", err)
	}
	if passedOpts.CredentialsFile != "/path/to/creds.json" {
		t.Fatalf("expected credentials file to be passed")
	}

	// 3. Factory error
	defaultClientFactory = func(ctx context.Context, opts GCPClientOptions) (iamAdminAPI, error) {
		return nil, errors.New("factory failure")
	}
	if _, err := NewGCPClient(ctx, GCPClientOptions{}); err == nil {
		t.Fatalf("expected error from failing factory")
	}
}

func TestDefaultClientFactory(t *testing.T) {
	ctx := context.Background()
	// Test without debug
	client1, err := defaultClientFactory(ctx, GCPClientOptions{})
	if err == nil && client1 != nil {
		_ = client1.Close()
	}

	// Test with debug
	var buf bytes.Buffer
	client2, err := defaultClientFactory(ctx, GCPClientOptions{
		DebugHTTP:  true,
		MaskTokens: true,
		LogWriter:  &buf,
	})
	if err == nil && client2 != nil {
		_ = client2.Close()
	}
}

func TestIAMRESTAdapter(t *testing.T) {
	ctx := context.Background()
	mockRT := &testRoundTripper{}
	httpClient := &http.Client{Transport: mockRT}
	svc, err := iam.NewService(ctx, option.WithHTTPClient(httpClient), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("unexpected NewService err: %v", err)
	}

	adapter := &iamRESTAdapter{service: svc}

	// 1. List
	mockRT.resp = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"keys":[{"name":"projects/-/serviceAccounts/sa@p.com/keys/k1"}]}`)),
	}
	keys, err := adapter.ListServiceAccountKeys(ctx, "projects/-/serviceAccounts/sa@p.com", []string{"USER_MANAGED"})
	if err != nil || len(keys) != 1 {
		t.Fatalf("unexpected ListServiceAccountKeys: %v, %v", keys, err)
	}

	// List error
	mockRT.err = errors.New("list error")
	if _, err := adapter.ListServiceAccountKeys(ctx, "projects/-/serviceAccounts/sa@p.com", nil); err == nil {
		t.Fatalf("expected list error")
	}
	mockRT.err = nil

	// 2. Get
	mockRT.resp = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"name":"projects/-/serviceAccounts/sa@p.com/keys/k1"}`)),
	}
	key, err := adapter.GetServiceAccountKey(ctx, "projects/-/serviceAccounts/sa@p.com/keys/k1")
	if err != nil || key.Name != "projects/-/serviceAccounts/sa@p.com/keys/k1" {
		t.Fatalf("unexpected GetServiceAccountKey: %v, %v", key, err)
	}

	// 3. Create
	mockRT.resp = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"name":"projects/-/serviceAccounts/sa@p.com/keys/k1"}`)),
	}
	created, err := adapter.CreateServiceAccountKey(ctx, "projects/-/serviceAccounts/sa@p.com", &iam.CreateServiceAccountKeyRequest{})
	if err != nil || created.Name != "projects/-/serviceAccounts/sa@p.com/keys/k1" {
		t.Fatalf("unexpected CreateServiceAccountKey: %v, %v", created, err)
	}

	// 4. Upload
	mockRT.resp = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"name":"projects/-/serviceAccounts/sa@p.com/keys/k1"}`)),
	}
	uploaded, err := adapter.UploadServiceAccountKey(ctx, "projects/-/serviceAccounts/sa@p.com", &iam.UploadServiceAccountKeyRequest{})
	if err != nil || uploaded.Name != "projects/-/serviceAccounts/sa@p.com/keys/k1" {
		t.Fatalf("unexpected UploadServiceAccountKey: %v, %v", uploaded, err)
	}

	// 5. Delete
	mockRT.resp = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}
	if err := adapter.DeleteServiceAccountKey(ctx, "projects/-/serviceAccounts/sa@p.com/keys/k1"); err != nil {
		t.Fatalf("unexpected DeleteServiceAccountKey: %v", err)
	}

	// 6. Disable
	mockRT.resp = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}
	if err := adapter.DisableServiceAccountKey(ctx, "projects/-/serviceAccounts/sa@p.com/keys/k1"); err != nil {
		t.Fatalf("unexpected DisableServiceAccountKey: %v", err)
	}

	// 7. Enable
	mockRT.resp = &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}
	if err := adapter.EnableServiceAccountKey(ctx, "projects/-/serviceAccounts/sa@p.com/keys/k1"); err != nil {
		t.Fatalf("unexpected EnableServiceAccountKey: %v", err)
	}

	// 8. Close
	if err := adapter.Close(); err != nil {
		t.Fatalf("unexpected Close: %v", err)
	}
}
