package keybox_test

import (
	"github.com/kernle32dll/keybox-go"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestLoadPublicKey(t *testing.T) {
	t.Parallel()

	// Generate keys

	rsaKey := GenerateRSAPublicKey(t)
	rsaPKIX := WriteBytesToTempFile(t, PEMEncodePKIXPublicKey(t, rsaKey))

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr error
	}{
		{name: "valid key", args: args{path: rsaPKIX}, want: rsaKey, wantErr: nil},
		{name: "non-existent file", args: args{path: "does not exist"}, want: nil, wantErr: os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.LoadPublicKey(tt.args.path)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("LoadPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPublicKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadPublicKeyWithPassword(t *testing.T) {
	t.Parallel()

	testPassphrase := "super-passphrase"

	// Generate keys

	rsaKey := GenerateRSAPublicKey(t)
	encryptedRsaPKIX := WriteBytesToTempFile(t, PEMEncryptDERBytes(t, PEMEncodePKIXPublicKey(t, rsaKey), testPassphrase))
	encryptedRsaPKIXWrongPassword := WriteBytesToTempFile(t, PEMEncryptDERBytes(t, PEMEncodePKIXPublicKey(t, rsaKey), "nope"))

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr error
	}{
		{name: "valid key", args: args{path: encryptedRsaPKIX}, want: rsaKey, wantErr: nil},
		{name: "valid key wrong password", args: args{path: encryptedRsaPKIXWrongPassword}, want: nil, wantErr: x509.IncorrectPasswordError},
		{name: "non-existent file", args: args{path: "does not exist"}, want: nil, wantErr: os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.LoadPublicKeyWithPassword(tt.args.path, []byte(testPassphrase))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("LoadPublicKeyWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPublicKeyWithPassword() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePublicKeyFromEncryptedPEMBytes(t *testing.T) {
	t.Parallel()

	testPassphrase := "super-passphrase"

	// Generate keys

	rsaKey := GenerateRSAPublicKey(t)
	encryptedRsaPKCS1 := PEMEncryptDERBytes(t, PEMEncodePKCS1PublicKey(rsaKey), testPassphrase)
	encryptedRsaPKIX := PEMEncryptDERBytes(t, PEMEncodePKIXPublicKey(t, rsaKey), testPassphrase)
	encryptedRsaPKIXWrongPassword := PEMEncryptDERBytes(t, PEMEncodePKIXPublicKey(t, rsaKey), "nope")

	ecdsaKey := GenerateECDSAPublicKey(t)
	encryptedEcdsaPKIX := PEMEncryptDERBytes(t, PEMEncodePKIXPublicKey(t, ecdsaKey), testPassphrase)

	ed25519Key := GenerateEd25519PublicKey(t)
	encryptedEd25519PKIX := PEMEncryptDERBytes(t, PEMEncodePKIXPublicKey(t, ed25519Key), testPassphrase)

	trashKey := pem.EncodeToMemory(&pem.Block{Type: "TRASH PUBLIC KEY"})
	encryptedTrashKey := PEMEncryptDERBytes(t, trashKey, testPassphrase)

	type args struct {
		pemBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr error
	}{
		{name: "RSA PKCS1", args: args{pemBytes: encryptedRsaPKCS1}, want: rsaKey, wantErr: nil},
		{name: "RSA PKIX", args: args{pemBytes: encryptedRsaPKIX}, want: rsaKey, wantErr: nil},

		{name: "RSA PKIX wrong password", args: args{pemBytes: encryptedRsaPKIXWrongPassword}, want: nil, wantErr: x509.IncorrectPasswordError},

		{name: "ecdsa PKIX", args: args{pemBytes: encryptedEcdsaPKIX}, want: ecdsaKey, wantErr: nil},

		{name: "ed25519 PKIX", args: args{pemBytes: encryptedEd25519PKIX}, want: ed25519Key, wantErr: nil},

		{name: "PEM but not a public key", args: args{pemBytes: encryptedTrashKey}, want: nil, wantErr: keybox.ErrNotAPublicKey},
		{name: "non-pem", args: args{pemBytes: []byte("shall not decode")}, want: nil, wantErr: keybox.ErrKeyMustBePEMEncoded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.ParsePublicKeyFromEncryptedPEMBytes(tt.args.pemBytes, []byte(testPassphrase))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParsePublicKeyFromPEMBytes() error = %s, wantErr %s", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePublicKeyFromPEMBytes() got = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("PEM but not encrypted", func(t *testing.T) {
		got, err := keybox.ParsePublicKeyFromEncryptedPEMBytes(trashKey, []byte(testPassphrase))
		if err == nil {
			t.Errorf("ParsePublicKeyFromPEMBytes() error = false, wantErr true")
			return
		}
		if got != nil {
			t.Errorf("ParsePublicKeyFromPEMBytes() got = %v, want nil", got)
		}
	})
}

func TestParsePublicKeyFromPEMBytes(t *testing.T) {
	t.Parallel()

	// Generate keys

	rsaKey := GenerateRSAPublicKey(t)
	rsaPKCS1 := PEMEncodePKCS1PublicKey(rsaKey)
	rsaPKIX := PEMEncodePKIXPublicKey(t, rsaKey)

	ecdsaKey := GenerateECDSAPublicKey(t)
	ecdsaPKIX := PEMEncodePKIXPublicKey(t, ecdsaKey)

	ed25519Key := GenerateEd25519PublicKey(t)
	ed25519PKIX := PEMEncodePKIXPublicKey(t, ed25519Key)

	trashKey := pem.EncodeToMemory(&pem.Block{Type: "TRASH PUBLIC KEY"})

	type args struct {
		pemBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr error
	}{
		{name: "RSA PKCS1", args: args{pemBytes: rsaPKCS1}, want: rsaKey, wantErr: nil},
		{name: "RSA PKIX", args: args{pemBytes: rsaPKIX}, want: rsaKey, wantErr: nil},

		{name: "ecdsa PKIX", args: args{pemBytes: ecdsaPKIX}, want: ecdsaKey, wantErr: nil},

		{name: "ed25519 PKIX", args: args{pemBytes: ed25519PKIX}, want: ed25519Key, wantErr: nil},

		{name: "PEM but not a public key", args: args{pemBytes: trashKey}, want: nil, wantErr: keybox.ErrNotAPublicKey},
		{name: "non-pem", args: args{pemBytes: []byte("shall not decode")}, want: nil, wantErr: keybox.ErrKeyMustBePEMEncoded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.ParsePublicKeyFromPEMBytes(tt.args.pemBytes)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParsePublicKeyFromPEMBytes() error = %s, wantErr %s", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePublicKeyFromPEMBytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func GenerateRSAPublicKey(t *testing.T) *rsa.PublicKey {
	privateKey := GenerateRSAKey(t)
	return &privateKey.PublicKey
}

func GenerateEd25519PublicKey(t *testing.T) ed25519.PublicKey {
	privateKey := GenerateEd25519Key(t)
	return privateKey.Public().(ed25519.PublicKey)
}

func GenerateECDSAPublicKey(t *testing.T) *ecdsa.PublicKey {
	privateKey := GenerateECDSAKey(t)
	return &privateKey.PublicKey
}

func PEMEncodePKCS1PublicKey(key *rsa.PublicKey) []byte {
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	}

	return pem.EncodeToMemory(publicKeyBlock)
}

func PEMEncodePKIXPublicKey(t *testing.T, key crypto.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("failed to marshall public key: %s", err)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.EncodeToMemory(publicKeyBlock)
}
