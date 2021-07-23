package keybox

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/youmark/pkcs8"
)

var (
	// ErrKeyMustBePEMEncoded indicates that a given data block was not a PEM encoded block.
	ErrKeyMustBePEMEncoded = errors.New("invalid Key: Key must be PEM encoded")

	// ErrNotAPrivateKey indicates that a given PEM block did not contain a known private key format.
	ErrNotAPrivateKey = errors.New("invalid Key: PEM block must be a PKCS #1, PKCS #8 or SEC 1 private key")

	// ErrUnknownEncryption indicates that the given PEM block was not encrypted in a known format,
	// or not encrypted in the first place.
	ErrUnknownEncryption = errors.New("invalid encryption: PEM block is encrypted in a unknown format, or not encrypted at all")
)

// LoadPrivateKey tries to load a private key from a given path.
func LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKeyFromPEMBytes(pemString)
}

// LoadPrivateKeyWithPassword tries to load a private key from a given path with a password.
func LoadPrivateKeyWithPassword(path string, password []byte) (crypto.PrivateKey, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKeyFromEncryptedPEMBytes(pemString, password)
}

// ParsePrivateKeyFromPEMBytes parses a given byte array to a PEM block, and parses that block
// for a known private key (see ParsePrivateKeyFromDERBytes).
// Will return ErrKeyMustBePEMEncoded if the given byte array is not a valid PEM block.
func ParsePrivateKeyFromPEMBytes(pemBytes []byte) (crypto.PrivateKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemBytes); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	return ParsePrivateKeyFromDERBytes(block.Bytes)
}

// ParsePrivateKeyFromEncryptedPEMBytes parses and decrypts a given byte array and password to
// a PEM block, and parses that block for a known private key (see ParsePrivateKeyFromDERBytes).
// Will return ErrKeyMustBePEMEncoded if the given byte array is not a valid PEM block.
func ParsePrivateKeyFromEncryptedPEMBytes(pemBytes []byte, password []byte) (crypto.PrivateKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(pemBytes); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var blockDecrypted []byte
	if x509.IsEncryptedPEMBlock(block) {
		var err error
		if blockDecrypted, err = x509.DecryptPEMBlock(block, password); err != nil {
			return nil, err
		}
	} else if pkcs8Decryption, err := tryPKCS8Decryption(block, password); err == nil {
		blockDecrypted = pkcs8Decryption
	} else {
		// Either its not a password secured block, or is encrypted in a format
		// we don't know.
		return nil, ErrUnknownEncryption
	}

	return ParsePrivateKeyFromDERBytes(blockDecrypted)
}

// ParsePrivateKeyFromDERBytes parse a given byte array for a ASN.1 DER encoded
// PKCS #1, PKCS #8 or SEC 1 private key.
// Will return ErrNotAPrivateKey if the given byte array is not in properly
// encoded DER form, or is not a known private key format.
func ParsePrivateKeyFromDERBytes(derBytes []byte) (crypto.PrivateKey, error) {
	var err error

	var parsedKey crypto.PrivateKey
	if parsedKey, err = x509.ParsePKCS1PrivateKey(derBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(derBytes); err != nil {
			if parsedKey, err = x509.ParseECPrivateKey(derBytes); err != nil {
				return nil, ErrNotAPrivateKey
			}
		}
	}

	return parsedKey, nil
}

func tryPKCS8Decryption(block *pem.Block, password []byte) ([]byte, error) {
	pkcs8PrivateKey, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)
	if err != nil {
		return nil, err
	}

	decryptedBytes, err := x509.MarshalPKCS8PrivateKey(pkcs8PrivateKey)
	if err != nil {
		return nil, err
	}

	return decryptedBytes, nil
}
