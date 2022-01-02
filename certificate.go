package keybox

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

var (
	// ErrCertificateMustBePEMEncoded indicates that a given data block was not a PEM encoded block.
	ErrCertificateMustBePEMEncoded = errors.New("invalid Certificate: Certificate must be PEM encoded")

	// ErrNotACertificate indicates that a given PEM block did not contain a known certificate format.
	ErrNotACertificate = errors.New("invalid Key: PEM block must be a x509 certificate")
)

// LoadCertificate tries to load a certificate from a given path.
func LoadCertificate(path string) (*x509.Certificate, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParseCertificateFromPEMBytes(pemString)
}

// LoadCertificateWithPassword tries to load a certificate from a given path with a password.
func LoadCertificateWithPassword(path string, password []byte) (*x509.Certificate, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParseCertificateFromEncryptedPEMBytes(pemString, password)
}

// ParseCertificateFromPEMBytes parses a given byte array to a PEM block, and parses that block
// for a known certificate.
// Will return ErrCertificateMustBePEMEncoded if the given byte array is not a valid PEM block.
func ParseCertificateFromPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemBytes); block == nil {
		return nil, ErrCertificateMustBePEMEncoded
	}

	return ParseCertificateFromDERBytes(block.Bytes)
}

// ParseCertificateFromEncryptedPEMBytes parses and decrypts a given byte array and password to
// a PEM block, and parses that block for a known certificate.
// Will return ErrCertificateMustBePEMEncoded if the given byte array is not a valid PEM block, or
// ErrUnknownEncryption if the byte array was encrypted in an unknown format, or not encrypted
// at all.
// Note: Usage of RFC 1423 encrypted PEM blocks is deprecated since Go 1.16!
func ParseCertificateFromEncryptedPEMBytes(pemBytes []byte, password []byte) (*x509.Certificate, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemBytes); block == nil {
		return nil, ErrCertificateMustBePEMEncoded
	}

	var blockDecrypted []byte
	// nolint: staticcheck: Just passing through - deprecation is communicated in function signature
	if x509.IsEncryptedPEMBlock(block) {
		var err error
		// nolint: staticcheck
		if blockDecrypted, err = x509.DecryptPEMBlock(block, password); err != nil {
			return nil, err
		}
	} else {
		// Either its not a password secured block, or is encrypted in a format
		// we don't know.
		return nil, ErrUnknownEncryption
	}

	return ParseCertificateFromDERBytes(blockDecrypted)
}

// ParseCertificateFromDERBytes parse a given byte array for a ASN.1 DER encoded
// PKIX or PKCS #1 public key.
// Will return ErrNotACertificate if the given byte array is not in properly
// encoded DER form, or is not a known public key format.
func ParseCertificateFromDERBytes(derBytes []byte) (*x509.Certificate, error) {
	var err error

	var parsedKey *x509.Certificate
	if parsedKey, err = x509.ParseCertificate(derBytes); err != nil {
		return nil, ErrNotACertificate
	}

	return parsedKey, nil
}
