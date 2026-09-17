package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	// Test invalid sizes
	if _, err := GenerateRSAKeyPair(512); err == nil {
		t.Fatalf("expected error for 512 bits")
	}
	if _, err := GenerateRSAKeyPair(768); err == nil {
		t.Fatalf("expected error for 768 bits")
	}

	// Test valid 1024 size (supported with warning)
	priv1024, err := GenerateRSAKeyPair(1024)
	if err != nil {
		t.Fatalf("unexpected error generating 1024 bit key: %v", err)
	}
	if priv1024.N.BitLen() != 1024 {
		t.Fatalf("expected 1024 bits, got %d", priv1024.N.BitLen())
	}

	// Test valid 2048 size
	priv, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("unexpected error generating 2048 bit key: %v", err)
	}
	if priv.N.BitLen() != 2048 {
		t.Fatalf("expected 2048 bits, got %d", priv.N.BitLen())
	}
}

func TestEncodePrivateKeyPEM(t *testing.T) {
	// Test PKCS8 nil
	if _, err := EncodePrivateKeyToPKCS8PEM(nil); err == nil {
		t.Fatalf("expected error for nil private key")
	}

	// Test PKCS1 nil
	if res := EncodePrivateKeyToPKCS1PEM(nil); res != nil {
		t.Fatalf("expected nil for nil PKCS1 private key")
	}

	priv, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Test PKCS8
	pkcs8PEM, err := EncodePrivateKeyToPKCS8PEM(priv)
	if err != nil {
		t.Fatalf("unexpected error encoding PKCS#8: %v", err)
	}
	block, _ := pem.Decode(pkcs8PEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY block")
	}

	// Test PKCS1
	pkcs1PEM := EncodePrivateKeyToPKCS1PEM(priv)
	block1, _ := pem.Decode(pkcs1PEM)
	if block1 == nil || block1.Type != "RSA PRIVATE KEY" {
		t.Fatalf("expected RSA PRIVATE KEY block")
	}
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	priv, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Nil key
	if _, err := CreateSelfSignedCertificate(nil, 24*time.Hour, "test"); err == nil {
		t.Fatalf("expected error for nil private key")
	}

	// Invalid validity
	if _, err := CreateSelfSignedCertificate(priv, 0, "test"); err == nil {
		t.Fatalf("expected error for 0 validity")
	}

	// Empty common name (should default)
	certPEM, err := CreateSelfSignedCertificate(priv, 24*time.Hour, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("failed to parse generated cert: %v", err)
	}
	if cert.Subject.CommonName != "service-account-key" {
		t.Fatalf("expected default commonName, got %q", cert.Subject.CommonName)
	}

	// Custom common name
	certPEM2, err := CreateSelfSignedCertificate(priv, 48*time.Hour, "custom-sa-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert2, err := ParseCertificate(certPEM2)
	if err != nil {
		t.Fatalf("failed to parse generated cert: %v", err)
	}
	if cert2.Subject.CommonName != "custom-sa-key" {
		t.Fatalf("expected custom-sa-key, got %q", cert2.Subject.CommonName)
	}
}

func TestParseCertificate(t *testing.T) {
	// Empty data
	if _, err := ParseCertificate(nil); err == nil {
		t.Fatalf("expected error for empty data")
	}

	// Wrong PEM block type
	badBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("foo")})
	if _, err := ParseCertificate(badBlock); err == nil {
		t.Fatalf("expected error for wrong PEM block type")
	}

	// Corrupted DER data
	if _, err := ParseCertificate([]byte("not-a-certificate")); err == nil {
		t.Fatalf("expected error for corrupted DER data")
	}

	// Certificate with non-RSA (ECDSA) public key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ec-cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	ecCertDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatalf("failed to create EC cert: %v", err)
	}
	ecCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecCertDER})
	if _, err := ParseCertificate(ecCertPEM); err == nil {
		t.Fatalf("expected error for non-RSA certificate")
	}

	// Valid RSA DER certificate (direct DER, no PEM)
	priv, _ := GenerateRSAKeyPair(2048)
	certPEM, _ := CreateSelfSignedCertificate(priv, 24*time.Hour, "test")
	block, _ := pem.Decode(certPEM)
	certFromDER, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected error parsing direct DER: %v", err)
	}
	if certFromDER.Subject.CommonName != "test" {
		t.Fatalf("expected commonName 'test', got %q", certFromDER.Subject.CommonName)
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	// Empty data
	if _, err := ParseRSAPublicKey(nil); err == nil {
		t.Fatalf("expected error for empty data")
	}

	priv, _ := GenerateRSAKeyPair(2048)

	// PKIX PEM
	pkixDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal PKIX: %v", err)
	}
	pkixPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})
	pub1, err := ParseRSAPublicKey(pkixPEM)
	if err != nil || pub1 == nil {
		t.Fatalf("failed to parse PKIX PEM: %v", err)
	}

	// PKIX PEM with corrupted bytes
	corruptedPKIX := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("corrupted")})
	if _, err := ParseRSAPublicKey(corruptedPKIX); err == nil {
		t.Fatalf("expected error for corrupted PKIX PEM")
	}

	// PKIX PEM with ECDSA key
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPKIXDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPKIXPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecPKIXDER})
	if _, err := ParseRSAPublicKey(ecPKIXPEM); err == nil {
		t.Fatalf("expected error for ECDSA public key in PKIX PEM")
	}

	// PKCS#1 PEM
	pkcs1DER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1DER})
	pub2, err := ParseRSAPublicKey(pkcs1PEM)
	if err != nil || pub2 == nil {
		t.Fatalf("failed to parse PKCS#1 PEM: %v", err)
	}

	// Unsupported PEM type
	unsupportedPEM := pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN KEY", Bytes: pkcs1DER})
	if _, err := ParseRSAPublicKey(unsupportedPEM); err == nil {
		t.Fatalf("expected error for unsupported PEM type")
	}

	// Direct DER PKIX RSA
	pubDERPKIX, err := ParseRSAPublicKey(pkixDER)
	if err != nil || pubDERPKIX == nil {
		t.Fatalf("failed to parse direct DER PKIX: %v", err)
	}

	// Direct DER PKIX ECDSA
	if _, err := ParseRSAPublicKey(ecPKIXDER); err == nil {
		t.Fatalf("expected error for direct DER PKIX ECDSA key")
	}

	// Direct DER PKCS#1 RSA
	pubDERPKCS1, err := ParseRSAPublicKey(pkcs1DER)
	if err != nil || pubDERPKCS1 == nil {
		t.Fatalf("failed to parse direct DER PKCS#1: %v", err)
	}

	// Direct DER corrupted
	if _, err := ParseRSAPublicKey([]byte("corrupted raw der")); err == nil {
		t.Fatalf("expected error for corrupted raw DER")
	}
}

func TestWrapRSAPublicKeyInCert(t *testing.T) {
	priv, _ := GenerateRSAKeyPair(2048)

	// Nil pub
	if _, err := WrapRSAPublicKeyInCert(nil, priv, 24*time.Hour, "test"); err == nil {
		t.Fatalf("expected error for nil pub")
	}

	// Nil signer
	if _, err := WrapRSAPublicKeyInCert(&priv.PublicKey, nil, 24*time.Hour, "test"); err == nil {
		t.Fatalf("expected error for nil signer")
	}

	// Validity <= 0
	if _, err := WrapRSAPublicKeyInCert(&priv.PublicKey, priv, 0, "test"); err == nil {
		t.Fatalf("expected error for 0 validity")
	}

	// Default commonName
	certPEM1, err := WrapRSAPublicKeyInCert(&priv.PublicKey, priv, 24*time.Hour, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert1, err := ParseCertificate(certPEM1)
	if err != nil || cert1.Subject.CommonName != "service-account-key" {
		t.Fatalf("expected default commonName, got %v", cert1)
	}

	// Custom commonName
	certPEM2, err := WrapRSAPublicKeyInCert(&priv.PublicKey, priv, 24*time.Hour, "custom-name")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert2, err := ParseCertificate(certPEM2)
	if err != nil || cert2.Subject.CommonName != "custom-name" {
		t.Fatalf("expected custom-name, got %v", cert2)
	}
}

func TestValidateCertValidity(t *testing.T) {
	// Nil cert
	if err := ValidateCertValidity(nil, time.Hour); err == nil {
		t.Fatalf("expected error for nil cert")
	}

	now := time.Now()

	// Expired cert
	expiredCert := &x509.Certificate{
		NotBefore: now.Add(-10 * time.Hour),
		NotAfter:  now.Add(-1 * time.Hour),
	}
	if err := ValidateCertValidity(expiredCert, 0); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}

	// Not yet valid cert
	futureCert := &x509.Certificate{
		NotBefore: now.Add(1 * time.Hour),
		NotAfter:  now.Add(10 * time.Hour),
	}
	if err := ValidateCertValidity(futureCert, 0); err == nil || !strings.Contains(err.Error(), "not valid until") {
		t.Fatalf("expected not valid until error, got %v", err)
	}

	// Currently valid cert, duration within limit
	validCert := &x509.Certificate{
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
	}
	if err := ValidateCertValidity(validCert, 48*time.Hour); err != nil {
		t.Fatalf("expected cert to be valid, got: %v", err)
	}

	// Currently valid cert, no max validity check (0)
	if err := ValidateCertValidity(validCert, 0); err != nil {
		t.Fatalf("expected cert to be valid with 0 maxValidity, got: %v", err)
	}

	// Currently valid cert, duration exceeds max validity
	if err := ValidateCertValidity(validCert, 10*time.Hour); err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed") {
		t.Fatalf("expected exceeds maximum allowed error, got %v", err)
	}
}

func TestExtractProjectIDFromEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"invalid-email", ""},
		{"too@many@at.com", ""},
		{"sa@my-prod-project.iam.gserviceaccount.com", "my-prod-project"},
		{"my-app@appspot.gserviceaccount.com", "appspot"},
		{"sa@example.com", ""},
	}

	for _, tc := range tests {
		got := ExtractProjectIDFromEmail(tc.email)
		if got != tc.expected {
			t.Errorf("ExtractProjectIDFromEmail(%q) = %q; want %q", tc.email, got, tc.expected)
		}
	}
}

func TestBuildAndParseGCPCredentialsJSON(t *testing.T) {
	priv, _ := GenerateRSAKeyPair(2048)
	pemBytes, _ := EncodePrivateKeyToPKCS8PEM(priv)

	// Empty email
	if _, err := BuildGCPCredentialsJSON("proj", "key-123", "", pemBytes); err == nil {
		t.Fatalf("expected error for empty client email")
	}

	// Empty private key
	if _, err := BuildGCPCredentialsJSON("proj", "key-123", "sa@proj.iam.gserviceaccount.com", nil); err == nil {
		t.Fatalf("expected error for empty private key PEM")
	}

	// Standard build with explicit project
	jsonBytes, err := BuildGCPCredentialsJSON("my-project", "key-456", "sa@my-project.iam.gserviceaccount.com", pemBytes)
	if err != nil {
		t.Fatalf("unexpected error building JSON: %v", err)
	}

	creds, err := ParseGCPCredentialsJSON(jsonBytes)
	if err != nil {
		t.Fatalf("unexpected error parsing JSON: %v", err)
	}
	if creds.ProjectID != "my-project" || creds.PrivateKeyID != "key-456" {
		t.Fatalf("unexpected credentials content: %+v", creds)
	}

	// Build with empty project, auto-extracted from standard email
	jsonBytes2, err := BuildGCPCredentialsJSON("", "key-789", "sa@auto-project.iam.gserviceaccount.com", pemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds2, err := ParseGCPCredentialsJSON(jsonBytes2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds2.ProjectID != "auto-project" {
		t.Fatalf("expected auto-project, got %q", creds2.ProjectID)
	}

	// Build with empty project and non-extractable email
	jsonBytes3, err := BuildGCPCredentialsJSON("", "key-000", "sa@customdomain.com", pemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds3, err := ParseGCPCredentialsJSON(jsonBytes3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds3.ProjectID != "unknown-project" {
		t.Fatalf("expected unknown-project, got %q", creds3.ProjectID)
	}

	// Parse errors
	if _, err := ParseGCPCredentialsJSON(nil); err == nil {
		t.Fatalf("expected error for empty credentials JSON")
	}
	if _, err := ParseGCPCredentialsJSON([]byte("not-json")); err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
	wrongType := []byte(`{"type": "authorized_user"}`)
	if _, err := ParseGCPCredentialsJSON(wrongType); err == nil {
		t.Fatalf("expected error for non service_account type")
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

func TestCryptoErrorPaths(t *testing.T) {
	priv, _ := GenerateRSAKeyPair(2048)

	// Test EncodePrivateKeyToPKCS8PEM marshal error
	origMarshal := marshalPKCS8
	marshalPKCS8 = func(key any) ([]byte, error) {
		return nil, errors.New("simulated marshal error")
	}
	if _, err := EncodePrivateKeyToPKCS8PEM(priv); err == nil {
		t.Fatalf("expected error from simulated marshal failure")
	}
	marshalPKCS8 = origMarshal

	// Test CreateSelfSignedCertificate rand.Int error
	origRand := randReader
	randReader = errReader{}
	if _, err := CreateSelfSignedCertificate(priv, 24*time.Hour, "test"); err == nil {
		t.Fatalf("expected error from failing randReader in CreateSelfSignedCertificate")
	}
	randReader = origRand

	// Test CreateSelfSignedCertificate createCertificate error
	origCreate := createCertificate
	createCertificate = func(rand io.Reader, template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
		return nil, errors.New("simulated cert creation error")
	}
	if _, err := CreateSelfSignedCertificate(priv, 24*time.Hour, "test"); err == nil {
		t.Fatalf("expected error from failing createCertificate in CreateSelfSignedCertificate")
	}

	// Test WrapRSAPublicKeyInCert rand.Int error
	randReader = errReader{}
	createCertificate = origCreate
	if _, err := WrapRSAPublicKeyInCert(&priv.PublicKey, priv, 24*time.Hour, "test"); err == nil {
		t.Fatalf("expected error from failing randReader in WrapRSAPublicKeyInCert")
	}
	randReader = origRand

	// Test WrapRSAPublicKeyInCert createCertificate error
	createCertificate = func(rand io.Reader, template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
		return nil, errors.New("simulated cert creation error")
	}
	if _, err := WrapRSAPublicKeyInCert(&priv.PublicKey, priv, 24*time.Hour, "test"); err == nil {
		t.Fatalf("expected error from failing createCertificate in WrapRSAPublicKeyInCert")
	}
	createCertificate = origCreate
}

