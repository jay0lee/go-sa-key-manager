package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// GCPCredentials represents the JSON structure of a Google Cloud Service Account credentials file.
type GCPCredentials struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id,omitempty"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// ExtractProjectIDFromEmail attempts to deduce the GCP project ID from a service account email.
// Standard pattern: [name]@[project-id].iam.gserviceaccount.com
func ExtractProjectIDFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	domain := parts[1]
	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		return strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
	}
	// Also handle [project-id]@appspot.gserviceaccount.com
	if strings.HasSuffix(domain, ".gserviceaccount.com") {
		return strings.TrimSuffix(domain, ".gserviceaccount.com")
	}
	return ""
}

// BuildGCPCredentialsJSON constructs a valid Google Cloud Service Account credentials JSON payload.
func BuildGCPCredentialsJSON(projectID, keyID, clientEmail string, privateKeyPEM []byte) ([]byte, error) {
	if clientEmail == "" {
		return nil, errors.New("client email cannot be empty")
	}
	if len(privateKeyPEM) == 0 {
		return nil, errors.New("private key PEM cannot be empty")
	}
	if projectID == "" {
		projectID = ExtractProjectIDFromEmail(clientEmail)
		if projectID == "" {
			projectID = "unknown-project"
		}
	}

	creds := GCPCredentials{
		Type:                    "service_account",
		ProjectID:               projectID,
		PrivateKeyID:            keyID,
		PrivateKey:              string(privateKeyPEM),
		ClientEmail:             clientEmail,
		AuthURI:                 "https://accounts.google.com/o/oauth2/auth",
		TokenURI:                "https://oauth2.googleapis.com/token",
		AuthProviderX509CertURL: "https://www.googleapis.com/oauth2/v1/certs",
		ClientX509CertURL:       fmt.Sprintf("https://www.googleapis.com/robot/v1/metadata/x509/%s", clientEmail),
	}

	return json.MarshalIndent(creds, "", "  ")
}

// ParseGCPCredentialsJSON parses a service account credentials JSON byte slice.
func ParseGCPCredentialsJSON(data []byte) (*GCPCredentials, error) {
	if len(data) == 0 {
		return nil, errors.New("credentials data cannot be empty")
	}
	var creds GCPCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse GCP credentials JSON: %w", err)
	}
	if creds.Type != "service_account" {
		return nil, fmt.Errorf("invalid credential type %q, expected 'service_account'", creds.Type)
	}
	return &creds, nil
}
