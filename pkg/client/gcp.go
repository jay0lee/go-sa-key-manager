package client

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/jay0lee/go-sa-key-manager/pkg/errors"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"
)

// iamAdminAPI defines the subset of IAM API operations used by GCPClient.
type iamAdminAPI interface {
	ListServiceAccountKeys(ctx context.Context, parent string, keyTypes []string) ([]*iam.ServiceAccountKey, error)
	GetServiceAccountKey(ctx context.Context, name string) (*iam.ServiceAccountKey, error)
	CreateServiceAccountKey(ctx context.Context, parent string, req *iam.CreateServiceAccountKeyRequest) (*iam.ServiceAccountKey, error)
	UploadServiceAccountKey(ctx context.Context, parent string, req *iam.UploadServiceAccountKeyRequest) (*iam.ServiceAccountKey, error)
	DeleteServiceAccountKey(ctx context.Context, name string) error
	DisableServiceAccountKey(ctx context.Context, name string) error
	EnableServiceAccountKey(ctx context.Context, name string) error
	Close() error
}

type adminClientFactory func(ctx context.Context, opts GCPClientOptions) (iamAdminAPI, error)

type iamRESTAdapter struct {
	service *iam.Service
}

func (a *iamRESTAdapter) ListServiceAccountKeys(ctx context.Context, parent string, keyTypes []string) ([]*iam.ServiceAccountKey, error) {
	call := a.service.Projects.ServiceAccounts.Keys.List(parent)
	if len(keyTypes) > 0 {
		call = call.KeyTypes(keyTypes...)
	}
	resp, err := call.Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

func (a *iamRESTAdapter) GetServiceAccountKey(ctx context.Context, name string) (*iam.ServiceAccountKey, error) {
	return a.service.Projects.ServiceAccounts.Keys.Get(name).PublicKeyType("TYPE_X509_PEM_FILE").Context(ctx).Do()
}

func (a *iamRESTAdapter) CreateServiceAccountKey(ctx context.Context, parent string, req *iam.CreateServiceAccountKeyRequest) (*iam.ServiceAccountKey, error) {
	return a.service.Projects.ServiceAccounts.Keys.Create(parent, req).Context(ctx).Do()
}

func (a *iamRESTAdapter) UploadServiceAccountKey(ctx context.Context, parent string, req *iam.UploadServiceAccountKeyRequest) (*iam.ServiceAccountKey, error) {
	return a.service.Projects.ServiceAccounts.Keys.Upload(parent, req).Context(ctx).Do()
}

func (a *iamRESTAdapter) DeleteServiceAccountKey(ctx context.Context, name string) error {
	_, err := a.service.Projects.ServiceAccounts.Keys.Delete(name).Context(ctx).Do()
	return err
}

func (a *iamRESTAdapter) DisableServiceAccountKey(ctx context.Context, name string) error {
	_, err := a.service.Projects.ServiceAccounts.Keys.Disable(name, &iam.DisableServiceAccountKeyRequest{}).Context(ctx).Do()
	return err
}

func (a *iamRESTAdapter) EnableServiceAccountKey(ctx context.Context, name string) error {
	_, err := a.service.Projects.ServiceAccounts.Keys.Enable(name, &iam.EnableServiceAccountKeyRequest{}).Context(ctx).Do()
	return err
}

func (a *iamRESTAdapter) Close() error {
	return nil
}

var defaultClientFactory adminClientFactory = func(ctx context.Context, opts GCPClientOptions) (iamAdminAPI, error) {
	var clientOpts []option.ClientOption
	if opts.CredentialsFile != "" {
		clientOpts = append(clientOpts, option.WithCredentialsFile(opts.CredentialsFile))
	}

	if opts.DebugHTTP {
		loggingTr := NewHTTPLoggingTransport(http.DefaultTransport, opts.LogWriter, opts.MaskTokens)
		tr, err := htransport.NewTransport(ctx, loggingTr, clientOpts...)
		if err != nil {
			return nil, err
		}
		httpClient := &http.Client{Transport: tr}
		clientOpts = append(clientOpts, option.WithHTTPClient(httpClient))
	}

	svc, err := iam.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, err
	}
	return &iamRESTAdapter{service: svc}, nil
}

// GCPClientOptions provides configuration options for creating a GCPClient.
type GCPClientOptions struct {
	CredentialsFile string
	DebugHTTP       bool
	MaskTokens      bool
	LogWriter       io.Writer
}

// GCPClient implements IAMClient backed by Google Cloud IAM REST API.
type GCPClient struct {
	api iamAdminAPI
}

// NewGCPClient creates a new GCPClient using Application Default Credentials (ADC)
// or an optional explicit credentials file.
func NewGCPClient(ctx context.Context, opts GCPClientOptions) (IAMClient, error) {
	apiClient, err := defaultClientFactory(ctx, opts)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return &GCPClient{api: apiClient}, nil
}

// ListKeys retrieves keys associated with the specified service account.
func (c *GCPClient) ListKeys(ctx context.Context, saEmail string, keyTypes []KeyType) ([]*KeyInfo, error) {
	var strKeyTypes []string
	for _, kt := range keyTypes {
		switch kt {
		case KeyTypeUserManaged:
			strKeyTypes = append(strKeyTypes, "USER_MANAGED")
		case KeyTypeSystemManaged:
			strKeyTypes = append(strKeyTypes, "SYSTEM_MANAGED")
		default:
			strKeyTypes = append(strKeyTypes, "KEY_TYPE_UNSPECIFIED")
		}
	}

	parent := FormatServiceAccountResourceName(saEmail)
	keys, err := c.api.ListServiceAccountKeys(ctx, parent, strKeyTypes)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	var results []*KeyInfo
	for _, k := range keys {
		results = append(results, iamToKeyInfo(k))
	}
	return results, nil
}

// GetKey retrieves a specific key for the service account.
func (c *GCPClient) GetKey(ctx context.Context, saEmail, keyID string) (*KeyInfo, error) {
	name := FormatKeyResourceName(saEmail, keyID)
	key, err := c.api.GetServiceAccountKey(ctx, name)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return iamToKeyInfo(key), nil
}

// CreateKey creates a new GCP-managed service account key pair (RSA 2048).
func (c *GCPClient) CreateKey(ctx context.Context, saEmail string) (*KeyInfo, error) {
	parent := FormatServiceAccountResourceName(saEmail)
	req := &iam.CreateServiceAccountKeyRequest{
		KeyAlgorithm:   "KEY_ALG_RSA_2048",
		PrivateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE",
	}

	key, err := c.api.CreateServiceAccountKey(ctx, parent, req)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return iamToKeyInfo(key), nil
}

// UploadKey associates a user-managed public key X.509 certificate with the service account.
func (c *GCPClient) UploadKey(ctx context.Context, saEmail string, publicKeyCertPEM []byte) (*KeyInfo, error) {
	parent := FormatServiceAccountResourceName(saEmail)
	req := &iam.UploadServiceAccountKeyRequest{
		PublicKeyData: string(publicKeyCertPEM),
	}

	key, err := c.api.UploadServiceAccountKey(ctx, parent, req)
	if err != nil {
		return nil, errors.WrapGCPError(err)
	}

	return iamToKeyInfo(key), nil
}

// DeleteKey permanently deletes a service account key.
func (c *GCPClient) DeleteKey(ctx context.Context, saEmail, keyID string) error {
	name := FormatKeyResourceName(saEmail, keyID)
	err := c.api.DeleteServiceAccountKey(ctx, name)
	if err != nil {
		return errors.WrapGCPError(err)
	}
	return nil
}

// DisableKey disables an active service account key.
func (c *GCPClient) DisableKey(ctx context.Context, saEmail, keyID string) error {
	name := FormatKeyResourceName(saEmail, keyID)
	err := c.api.DisableServiceAccountKey(ctx, name)
	if err != nil {
		return errors.WrapGCPError(err)
	}
	return nil
}

// EnableKey enables a disabled service account key.
func (c *GCPClient) EnableKey(ctx context.Context, saEmail, keyID string) error {
	name := FormatKeyResourceName(saEmail, keyID)
	err := c.api.EnableServiceAccountKey(ctx, name)
	if err != nil {
		return errors.WrapGCPError(err)
	}
	return nil
}

// Close closes the underlying IAM client connections.
func (c *GCPClient) Close() error {
	return c.api.Close()
}

func iamToKeyInfo(k *iam.ServiceAccountKey) *KeyInfo {
	if k == nil {
		return nil
	}

	var kt KeyType
	switch k.KeyType {
	case "USER_MANAGED":
		kt = KeyTypeUserManaged
	case "SYSTEM_MANAGED":
		kt = KeyTypeSystemManaged
	default:
		kt = KeyTypeUnspecified
	}

	var validAfter, validBefore time.Time
	if k.ValidAfterTime != "" {
		validAfter, _ = time.Parse(time.RFC3339, k.ValidAfterTime)
	}
	if k.ValidBeforeTime != "" {
		validBefore, _ = time.Parse(time.RFC3339, k.ValidBeforeTime)
	}

	var privBytes []byte
	if k.PrivateKeyData != "" {
		privBytes, _ = base64.StdEncoding.DecodeString(k.PrivateKeyData)
	}

	var pubBytes []byte
	if k.PublicKeyData != "" {
		if decoded, err := base64.StdEncoding.DecodeString(k.PublicKeyData); err == nil && len(decoded) > 0 {
			pubBytes = decoded
		} else {
			pubBytes = []byte(k.PublicKeyData)
		}
	}

	return &KeyInfo{
		ID:              ExtractKeyID(k.Name),
		Name:            k.Name,
		KeyType:         kt,
		KeyAlgorithm:    k.KeyAlgorithm,
		ValidAfterTime:  validAfter,
		ValidBeforeTime: validBefore,
		Disabled:        k.Disabled,
		PrivateKeyData:  privBytes,
		PublicKeyData:   pubBytes,
	}
}
