package keybox

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

var (
	// ErrNotAPublicKey indicates that a given PEM block did not contain a known public key format.
	ErrNotAPublicKey = errors.New("invalid Key: PEM block must be a PKIX or PKCS #1 public key")
)

// LoadPublicKey tries to load a public key from a given path.
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePublicKeyFromPEMBytes(pemString)
}

// LoadPublicKeyWithPassword tries to load a public key from a given path with a password.
func LoadPublicKeyWithPassword(path string, password []byte) (crypto.PublicKey, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePublicKeyFromEncryptedPEMBytes(pemString, password)
}

// ParsePublicKeyFromPEMBytes parses a given byte array to a PEM block, and parses that block
// for a known public key (see ParsePublicKeyFromDERBytes).
// Will return ErrKeyMustBePEMEncoded if the given byte array is not a valid PEM block.
func ParsePublicKeyFromPEMBytes(pemBytes []byte) (crypto.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemBytes); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	return ParsePublicKeyFromDERBytes(block.Bytes)
}

// ParsePublicKeyFromEncryptedPEMBytes parses and decrypts a given byte array and password to
// a PEM block, and parses that block for a known public key (see ParsePublicKeyFromDERBytes).
// Will return ErrKeyMustBePEMEncoded if the given byte array is not a valid PEM block.
func ParsePublicKeyFromEncryptedPEMBytes(pemBytes []byte, password []byte) (crypto.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemBytes); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var (
		err            error
		blockDecrypted []byte
	)
	if blockDecrypted, err = x509.DecryptPEMBlock(block, password); err != nil {
		return nil, err
	}

	return ParsePublicKeyFromDERBytes(blockDecrypted)
}

// ParsePublicKeyFromDERBytes parse a given byte array for a ASN.1 DER encoded
// PKIX or PKCS #1 public key.
// Will return ErrNotAPublicKey if the given byte array is not in properly
// encoded DER form, or is not a known public key format.
func ParsePublicKeyFromDERBytes(derBytes []byte) (crypto.PublicKey, error) {
	var err error

	var parsedKey crypto.PublicKey
	if parsedKey, err = x509.ParsePKIXPublicKey(derBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS1PublicKey(derBytes); err != nil {
			return nil, ErrNotAPublicKey
		}
	}

	return parsedKey, nil
}
