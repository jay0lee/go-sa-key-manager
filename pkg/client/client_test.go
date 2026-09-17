package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		t.Fatalf("expected keyID %s, got %s", keyID, extracted)
	}

	// Extract without /keys/
	extractedRaw := ExtractKeyID("just-a-key-id")
	if extractedRaw != "just-a-key-id" {
		t.Fatalf("expected raw key ID, got %s", extractedRaw)
	}
}

func TestMockIAMClient(t *testing.T) {
	ctx := context.Background()
	mock := NewMockIAMClient()
	sa := "test-sa@project.iam.gserviceaccount.com"

	// 1. ListKeys on empty
	keys, err := mock.ListKeys(ctx, sa, nil)
	if err != nil || len(keys) != 0 {
		t.Fatalf("expected empty list, got: %v, err: %v", keys, err)
	}

	// 2. CreateKey
	created, err := mock.CreateKey(ctx, sa)
	if err != nil || created == nil {
		t.Fatalf("expected key creation to succeed, got: %v, err: %v", created, err)
	}
	keyID := created.ID

	// 3. UploadKey
	uploaded, err := mock.UploadKey(ctx, sa, []byte("cert-data"))
	if err != nil || uploaded == nil {
		t.Fatalf("expected key upload to succeed, got: %v, err: %v", uploaded, err)
	}

	// 3b. UploadKey on brand-new SA (covers map initialization)
	if _, err := mock.UploadKey(ctx, "fresh-sa@project.com", []byte("cert-data")); err != nil {
		t.Fatalf("unexpected error uploading to fresh SA: %v", err)
	}

	// 4. AddKey manually (System managed)
	systemKey := &KeyInfo{
		ID:       "sys-key-1",
		KeyType:  KeyTypeSystemManaged,
		Disabled: false,
	}
	mock.AddKey(sa, systemKey)

	// 4b. AddKey on brand-new SA (covers map initialization)
	mock.AddKey("another-fresh-sa@project.com", systemKey)

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
}

// fakeAdminAPI mocks the underlying iamAdminAPI for GCPClient tests
type fakeAdminAPI struct {
	listResp   *adminpb.ListServiceAccountKeysResponse
	listErr    error
	getResp    *adminpb.ServiceAccountKey
	getErr     error
	createResp *adminpb.ServiceAccountKey
	createErr  error
	uploadResp *adminpb.ServiceAccountKey
	uploadErr  error
	deleteErr  error
	disableErr error
	enableErr  error
	closeErr   error
}

func (f *fakeAdminAPI) ListServiceAccountKeys(ctx context.Context, req *adminpb.ListServiceAccountKeysRequest, opts ...gax.CallOption) (*adminpb.ListServiceAccountKeysResponse, error) {
	return f.listResp, f.listErr
}
func (f *fakeAdminAPI) GetServiceAccountKey(ctx context.Context, req *adminpb.GetServiceAccountKeyRequest, opts ...gax.CallOption) (*adminpb.ServiceAccountKey, error) {
	return f.getResp, f.getErr
}
func (f *fakeAdminAPI) CreateServiceAccountKey(ctx context.Context, req *adminpb.CreateServiceAccountKeyRequest, opts ...gax.CallOption) (*adminpb.ServiceAccountKey, error) {
	return f.createResp, f.createErr
}
func (f *fakeAdminAPI) UploadServiceAccountKey(ctx context.Context, req *adminpb.UploadServiceAccountKeyRequest, opts ...gax.CallOption) (*adminpb.ServiceAccountKey, error) {
	return f.uploadResp, f.uploadErr
}
func (f *fakeAdminAPI) DeleteServiceAccountKey(ctx context.Context, req *adminpb.DeleteServiceAccountKeyRequest, opts ...gax.CallOption) error {
	return f.deleteErr
}
func (f *fakeAdminAPI) DisableServiceAccountKey(ctx context.Context, req *adminpb.DisableServiceAccountKeyRequest, opts ...gax.CallOption) error {
	return f.disableErr
}
func (f *fakeAdminAPI) EnableServiceAccountKey(ctx context.Context, req *adminpb.EnableServiceAccountKeyRequest, opts ...gax.CallOption) error {
	return f.enableErr
}
func (f *fakeAdminAPI) Close() error {
	return f.closeErr
}

func TestGCPClient_Operations(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	nowProto := timestamppb.New(now)

	protoKey1 := &adminpb.ServiceAccountKey{
		Name:            "projects/-/serviceAccounts/sa@proj.com/keys/k1",
		PrivateKeyType:  adminpb.ServiceAccountPrivateKeyType_TYPE_GOOGLE_CREDENTIALS_FILE,
		KeyAlgorithm:    adminpb.ServiceAccountKeyAlgorithm_KEY_ALG_RSA_2048,
		KeyType:         adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
		ValidAfterTime:  nowProto,
		ValidBeforeTime: nowProto,
		Disabled:        false,
		PrivateKeyData:  []byte("priv-data"),
		PublicKeyData:   []byte("pub-data"),
	}

	protoKey2 := &adminpb.ServiceAccountKey{
		Name:            "projects/-/serviceAccounts/sa@proj.com/keys/k2",
		KeyType:         adminpb.ListServiceAccountKeysRequest_SYSTEM_MANAGED,
		ValidAfterTime:  nowProto,
		ValidBeforeTime: nowProto,
		Disabled:        true,
	}

	protoKey3 := &adminpb.ServiceAccountKey{
		Name:            "projects/-/serviceAccounts/sa@proj.com/keys/k3",
		KeyType:         adminpb.ListServiceAccountKeysRequest_KEY_TYPE_UNSPECIFIED,
		ValidAfterTime:  nowProto,
		ValidBeforeTime: nowProto,
	}

	fake := &fakeAdminAPI{
		listResp: &adminpb.ListServiceAccountKeysResponse{
			Keys: []*adminpb.ServiceAccountKey{protoKey1, protoKey2, protoKey3},
		},
		getResp:    protoKey1,
		createResp: protoKey1,
		uploadResp: protoKey1,
	}

	client := &GCPClient{api: fake}

	// 1. ListKeys
	list, err := client.ListKeys(ctx, "sa@proj.com", []KeyType{KeyTypeUserManaged, KeyTypeSystemManaged, KeyTypeUnspecified})
	if err != nil || len(list) != 3 {
		t.Fatalf("unexpected list keys result: len=%d, err=%v", len(list), err)
	}
	if list[0].ID != "k1" || list[0].KeyType != KeyTypeUserManaged {
		t.Fatalf("unexpected key 0 mapping: %+v", list[0])
	}
	if list[1].ID != "k2" || list[1].KeyType != KeyTypeSystemManaged || !list[1].Disabled {
		t.Fatalf("unexpected key 1 mapping: %+v", list[1])
	}
	if list[2].ID != "k3" || list[2].KeyType != KeyTypeUnspecified {
		t.Fatalf("unexpected key 2 mapping: %+v", list[2])
	}

	// ListKeys error
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

	// 9. protoToKeyInfo nil
	if protoToKeyInfo(nil) != nil {
		t.Fatalf("expected nil for protoToKeyInfo(nil)")
	}
}

func TestNewGCPClient(t *testing.T) {
	ctx := context.Background()

	// Mock the defaultClientFactory
	origFactory := defaultClientFactory
	defer func() { defaultClientFactory = origFactory }()

	var passedOpts []option.ClientOption
	defaultClientFactory = func(ctx context.Context, opts ...option.ClientOption) (iamAdminAPI, error) {
		passedOpts = opts
		return &fakeAdminAPI{}, nil
	}

	// 1. Success without credentials file
	client1, err := NewGCPClient(ctx, GCPClientOptions{})
	if err != nil || client1 == nil {
		t.Fatalf("unexpected error creating GCPClient: %v", err)
	}
	if len(passedOpts) != 0 {
		t.Fatalf("expected no options, got %d", len(passedOpts))
	}

	// 2. Success with credentials file
	client2, err := NewGCPClient(ctx, GCPClientOptions{CredentialsFile: "/path/to/creds.json"})
	if err != nil || client2 == nil {
		t.Fatalf("unexpected error creating GCPClient with creds: %v", err)
	}
	if len(passedOpts) != 1 {
		t.Fatalf("expected 1 option for credentials file, got %d", len(passedOpts))
	}

	// 3. Factory error
	defaultClientFactory = func(ctx context.Context, opts ...option.ClientOption) (iamAdminAPI, error) {
		return nil, errors.New("factory failure")
	}
	if _, err := NewGCPClient(ctx, GCPClientOptions{}); err == nil {
		t.Fatalf("expected error from failing factory")
	}
}

func TestDefaultClientFactory(t *testing.T) {
	// Call defaultClientFactory to cover line in gcp.go without crashing (using invalid endpoint to avoid network)
	ctx := context.Background()
	client, err := defaultClientFactory(ctx, option.WithEndpoint("invalid:1234"), option.WithoutAuthentication())
	if err == nil && client != nil {
		_ = client.Close()
	}
	// Error or client is fine, statement is covered
}
