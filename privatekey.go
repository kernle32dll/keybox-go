package keybox

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

var (
	ErrKeyMustBePEMEncoded = errors.New("invalid Key: Key must be PEM encoded private key")
	ErrNotAPrivateKey      = errors.New("invalid Key: PEM block must be a PKCS #1, PKCS #8 or SEC 1 private key")
)

func LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKeyFromPEMBytes(pemString)
}

func LoadPrivateKeyWithPassword(path string, password []byte) (crypto.PrivateKey, error) {
	pemString, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKeyFromEncryptedPEMBytes(pemString, password)
}

// ParsePrivateKeyFromPEMBlock parses a given byte array to a PEM block, and parses that block
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

	var (
		err            error
		blockDecrypted []byte
	)
	if blockDecrypted, err = x509.DecryptPEMBlock(block, password); err != nil {
		return nil, err
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
