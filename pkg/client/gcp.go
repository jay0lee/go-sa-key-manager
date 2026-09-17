package client

import (
	"context"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"github.com/googleapis/gax-go/v2"
	"github.com/jay0lee/go-sa-key-manager/pkg/errors"
	"google.golang.org/api/option"
)

// iamAdminAPI defines the subset of IAM Admin API operations used by GCPClient.
type iamAdminAPI interface {
	ListServiceAccountKeys(ctx context.Context, req *adminpb.ListServiceAccountKeysRequest, opts ...gax.CallOption) (*adminpb.ListServiceAccountKeysResponse, error)
	GetServiceAccountKey(ctx context.Context, req *adminpb.GetServiceAccountKeyRequest, opts ...gax.CallOption) (*adminpb.ServiceAccountKey, error)
	CreateServiceAccountKey(ctx context.Context, req *adminpb.CreateServiceAccountKeyRequest, opts ...gax.CallOption) (*adminpb.ServiceAccountKey, error)
	UploadServiceAccountKey(ctx context.Context, req *adminpb.UploadServiceAccountKeyRequest, opts ...gax.CallOption) (*adminpb.ServiceAccountKey, error)
	DeleteServiceAccountKey(ctx context.Context, req *adminpb.DeleteServiceAccountKeyRequest, opts ...gax.CallOption) error
	DisableServiceAccountKey(ctx context.Context, req *adminpb.DisableServiceAccountKeyRequest, opts ...gax.CallOption) error
	EnableServiceAccountKey(ctx context.Context, req *adminpb.EnableServiceAccountKeyRequest, opts ...gax.CallOption) error
	Close() error
}

type adminClientFactory func(ctx context.Context, opts ...option.ClientOption) (iamAdminAPI, error)

var defaultClientFactory adminClientFactory = func(ctx context.Context, opts ...option.ClientOption) (iamAdminAPI, error) {
	return admin.NewIamClient(ctx, opts...)
}

// GCPClientOptions provides configuration options for creating a GCPClient.
type GCPClientOptions struct {
	CredentialsFile string
}

// GCPClient implements IAMClient backed by Google Cloud IAM Admin API.
type GCPClient struct {
	api iamAdminAPI
}

// NewGCPClient creates a new GCPClient using Application Default Credentials (ADC)
// or an optional explicit credentials file.
func NewGCPClient(ctx context.Context, opts GCPClientOptions) (IAMClient, error) {
	var clientOpts []option.ClientOption
	if opts.CredentialsFile != "" {
		clientOpts = append(clientOpts, option.WithCredentialsFile(opts.CredentialsFile))
	}

	apiClient, err := defaultClientFactory(ctx, clientOpts...)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return &GCPClient{api: apiClient}, nil
}

// ListKeys retrieves keys associated with the specified service account.
func (c *GCPClient) ListKeys(ctx context.Context, saEmail string, keyTypes []KeyType) ([]*KeyInfo, error) {
	var protoKeyTypes []adminpb.ListServiceAccountKeysRequest_KeyType
	for _, kt := range keyTypes {
		switch kt {
		case KeyTypeUserManaged:
			protoKeyTypes = append(protoKeyTypes, adminpb.ListServiceAccountKeysRequest_USER_MANAGED)
		case KeyTypeSystemManaged:
			protoKeyTypes = append(protoKeyTypes, adminpb.ListServiceAccountKeysRequest_SYSTEM_MANAGED)
		default:
			protoKeyTypes = append(protoKeyTypes, adminpb.ListServiceAccountKeysRequest_KEY_TYPE_UNSPECIFIED)
		}
	}

	req := &adminpb.ListServiceAccountKeysRequest{
		Name:     FormatServiceAccountResourceName(saEmail),
		KeyTypes: protoKeyTypes,
	}

	resp, err := c.api.ListServiceAccountKeys(ctx, req)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	var results []*KeyInfo
	for _, k := range resp.Keys {
		results = append(results, protoToKeyInfo(k))
	}
	return results, nil
}

// GetKey retrieves a specific key for the service account.
func (c *GCPClient) GetKey(ctx context.Context, saEmail, keyID string) (*KeyInfo, error) {
	req := &adminpb.GetServiceAccountKeyRequest{
		Name: FormatKeyResourceName(saEmail, keyID),
	}

	resp, err := c.api.GetServiceAccountKey(ctx, req)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return protoToKeyInfo(resp), nil
}

// CreateKey creates a new GCP-managed service account key pair (RSA 2048).
func (c *GCPClient) CreateKey(ctx context.Context, saEmail string) (*KeyInfo, error) {
	req := &adminpb.CreateServiceAccountKeyRequest{
		Name:               FormatServiceAccountResourceName(saEmail),
		PrivateKeyType:     adminpb.ServiceAccountPrivateKeyType_TYPE_GOOGLE_CREDENTIALS_FILE,
		KeyAlgorithm:       adminpb.ServiceAccountKeyAlgorithm_KEY_ALG_RSA_2048,
	}

	resp, err := c.api.CreateServiceAccountKey(ctx, req)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return protoToKeyInfo(resp), nil
}

// UploadKey associates a user-managed public key X.509 certificate with the service account.
func (c *GCPClient) UploadKey(ctx context.Context, saEmail string, publicKeyCertPEM []byte) (*KeyInfo, error) {
	req := &adminpb.UploadServiceAccountKeyRequest{
		Name:          FormatServiceAccountResourceName(saEmail),
		PublicKeyData: publicKeyCertPEM,
	}

	resp, err := c.api.UploadServiceAccountKey(ctx, req)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return protoToKeyInfo(resp), nil
}

// DeleteKey permanently deletes a service account key.
func (c *GCPClient) DeleteKey(ctx context.Context, saEmail, keyID string) error {
	req := &adminpb.DeleteServiceAccountKeyRequest{
		Name: FormatKeyResourceName(saEmail, keyID),
	}

	err := c.api.DeleteServiceAccountKey(ctx, req)
	if err != nil {
		return errors.WrapGCPError(err)
	}
	return nil
}

// DisableKey disables an active service account key.
func (c *GCPClient) DisableKey(ctx context.Context, saEmail, keyID string) error {
	req := &adminpb.DisableServiceAccountKeyRequest{
		Name: FormatKeyResourceName(saEmail, keyID),
	}

	err := c.api.DisableServiceAccountKey(ctx, req)
	if err != nil {
		return errors.WrapGCPError(err)
	}
	return nil
}

// EnableKey enables a disabled service account key.
func (c *GCPClient) EnableKey(ctx context.Context, saEmail, keyID string) error {
	req := &adminpb.EnableServiceAccountKeyRequest{
		Name: FormatKeyResourceName(saEmail, keyID),
	}

	err := c.api.EnableServiceAccountKey(ctx, req)
	if err != nil {
		return errors.WrapGCPError(err)
	}
	return nil
}

// Close closes the underlying IAM client connections.
func (c *GCPClient) Close() error {
	return c.api.Close()
}

func protoToKeyInfo(k *adminpb.ServiceAccountKey) *KeyInfo {
	if k == nil {
		return nil
	}

	var kt KeyType
	switch k.KeyType {
	case adminpb.ListServiceAccountKeysRequest_USER_MANAGED:
		kt = KeyTypeUserManaged
	case adminpb.ListServiceAccountKeysRequest_SYSTEM_MANAGED:
		kt = KeyTypeSystemManaged
	default:
		kt = KeyTypeUnspecified
	}

	var validAfter, validBefore = k.ValidAfterTime.AsTime(), k.ValidBeforeTime.AsTime()

	return &KeyInfo{
		ID:              ExtractKeyID(k.Name),
		Name:            k.Name,
		KeyType:         kt,
		KeyAlgorithm:    k.KeyAlgorithm.String(),
		ValidAfterTime:  validAfter,
		ValidBeforeTime: validBefore,
		Disabled:        k.Disabled,
		PrivateKeyData:  k.PrivateKeyData,
		PublicKeyData:   k.PublicKeyData,
	}
}
