package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	randReader        = rand.Reader
	marshalPKCS8      = x509.MarshalPKCS8PrivateKey
	createCertificate = x509.CreateCertificate
)

// DefaultRSAKeySize is 2048 bits, matching GCP IAM's default RSA key specification.
const DefaultRSAKeySize = 2048

// GenerateRSAKeyPair generates an RSA private key with the given bit size.
// Supported bit sizes are 1024 (legacy/insecure), 2048, 3072, and 4096.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits != 1024 && bits != 2048 && bits != 3072 && bits != 4096 {
		return nil, fmt.Errorf("unsupported RSA key size %d: supported sizes are 1024 (insecure), 2048, 3072, or 4096 bits", bits)
	}
	return rsa.GenerateKey(randReader, bits)
}

// EncodePrivateKeyToPKCS8PEM encodes an RSA private key into PKCS#8 PEM format.
func EncodePrivateKeyToPKCS8PEM(priv *rsa.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key cannot be nil")
	}
	der, err := marshalPKCS8(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS#8 private key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// EncodePrivateKeyToPKCS1PEM encodes an RSA private key into PKCS#1 PEM format.
func EncodePrivateKeyToPKCS1PEM(priv *rsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	return pem.EncodeToMemory(block)
}

// CreateSelfSignedCertificate wraps an RSA public key in a self-signed X.509 v3 certificate
// with the specified validity duration and common name.
func CreateSelfSignedCertificate(priv *rsa.PrivateKey, validity time.Duration, commonName string) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if validity <= 0 {
		return nil, errors.New("validity duration must be greater than zero")
	}
	if commonName == "" {
		commonName = "service-account-key"
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(randReader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate serial number: %w", err)
	}

	notBefore := time.Now().Add(-5 * time.Minute) // 5 min skew tolerance
	notAfter := notBefore.Add(validity)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := createCertificate(randReader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, nil
}
