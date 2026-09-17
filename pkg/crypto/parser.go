package crypto

import (
	"crypto"
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

// ParseCertificate parses an X.509 certificate from PEM or DER encoded data and verifies it contains an RSA public key.
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, errors.New("certificate data cannot be empty")
	}

	var derBytes []byte
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block type %q, expected 'CERTIFICATE'", block.Type)
		}
		derBytes = block.Bytes
	} else {
		// Attempt direct DER interpretation
		derBytes = data
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("certificate does not contain an RSA public key (GCP IAM requires RSA)")
	}

	return cert, nil
}

// ParseRSAPublicKey parses an RSA public key from PEM (PKIX or PKCS#1) or DER data.
func ParseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, errors.New("public key data cannot be empty")
	}

	var derBytes []byte
	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
			}
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("public key is not an RSA key")
			}
			return rsaPub, nil
		case "RSA PUBLIC KEY":
			return x509.ParsePKCS1PublicKey(block.Bytes)
		default:
			return nil, fmt.Errorf("unsupported public key PEM type: %q", block.Type)
		}
	} else {
		derBytes = data
	}

	// Try DER PKIX
	if pub, err := x509.ParsePKIXPublicKey(derBytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("public key is not an RSA key")
	}

	// Try DER PKCS#1
	if rsaPub, err := x509.ParsePKCS1PublicKey(derBytes); err == nil {
		return rsaPub, nil
	}

	return nil, errors.New("failed to parse RSA public key from DER/PEM data")
}

// WrapRSAPublicKeyInCert wraps an arbitrary RSA public key (such as one from an HSM)
// into an X.509 v3 certificate signed by the provided signer.
func WrapRSAPublicKeyInCert(pub *rsa.PublicKey, signer crypto.Signer, validity time.Duration, commonName string) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key cannot be nil")
	}
	if signer == nil {
		return nil, errors.New("signer cannot be nil")
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

	now := time.Now()
	notBefore := now.Add(-5 * time.Minute) // 5 min skew tolerance
	notAfter := now.Add(validity)          // Key remains valid for the full specified period from creation

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

	certDER, err := createCertificate(randReader, &template, &template, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}

// ValidateCertValidity checks that a certificate is currently valid and doesn't exceed maxValidity.
func ValidateCertValidity(cert *x509.Certificate, maxValidity time.Duration) error {
	if cert == nil {
		return errors.New("certificate cannot be nil")
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired on %s", cert.NotAfter.Format(time.RFC3339))
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid until %s", cert.NotBefore.Format(time.RFC3339))
	}

	if maxValidity > 0 {
		duration := cert.NotAfter.Sub(cert.NotBefore)
		if duration > maxValidity {
			return fmt.Errorf("certificate validity duration of %v exceeds maximum allowed %v (policy constraint)",
				duration.Round(time.Hour), maxValidity)
		}
	}

	return nil
}
