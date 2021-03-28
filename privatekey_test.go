package keybox_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/kernle32dll/keybox-go"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestLoadPrivateKey(t *testing.T) {
	t.Parallel()

	// Generate keys

	rsaKey := GenerateRSAKey(t)
	rsaPKCS8 := WriteBytesToTempFile(t, PEMEncodePKCS8PrivateKey(t, rsaKey))

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr error
	}{
		{name: "valid key", args: args{path: rsaPKCS8}, want: rsaKey, wantErr: nil},
		{name: "non-existent file", args: args{path: "does not exist"}, want: nil, wantErr: os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.LoadPrivateKey(tt.args.path)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("LoadPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPrivateKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadPrivateKeyWithPassword(t *testing.T) {
	t.Parallel()

	testPassphrase := "super-passphrase"

	// Generate keys

	rsaKey := GenerateRSAKey(t)
	encryptedRsaPKCS8 := WriteBytesToTempFile(t, PEMEncryptDERBytes(t, PEMEncodePKCS8PrivateKey(t, rsaKey), testPassphrase))
	encryptedRsaPKCS8WrongPassword := WriteBytesToTempFile(t, PEMEncryptDERBytes(t, PEMEncodePKCS8PrivateKey(t, rsaKey), "nope"))

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr error
	}{
		{name: "valid key", args: args{path: encryptedRsaPKCS8}, want: rsaKey, wantErr: nil},
		{name: "valid key wrong password", args: args{path: encryptedRsaPKCS8WrongPassword}, want: nil, wantErr: x509.IncorrectPasswordError},
		{name: "non-existent file", args: args{path: "does not exist"}, want: nil, wantErr: os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.LoadPrivateKeyWithPassword(tt.args.path, []byte(testPassphrase))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("LoadPrivateKeyWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPrivateKeyWithPassword() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePrivateKeyFromEncryptedPEMBytes(t *testing.T) {
	t.Parallel()

	testPassphrase := "super-passphrase"

	// Generate keys

	rsaKey := GenerateRSAKey(t)
	encryptedRsaPKCS1 := PEMEncryptDERBytes(t, PEMEncodePKCS1PrivateKey(rsaKey), testPassphrase)
	encryptedRsaPKCS8 := PEMEncryptDERBytes(t, PEMEncodePKCS8PrivateKey(t, rsaKey), testPassphrase)
	encryptedRsaPKCS8WrongPassword := PEMEncryptDERBytes(t, PEMEncodePKCS8PrivateKey(t, rsaKey), "nope")

	ecdsaKey := GenerateECDSAKey(t)
	encryptedEcdsaPKCS8 := PEMEncryptDERBytes(t, PEMEncodePKCS8PrivateKey(t, ecdsaKey), testPassphrase)
	encryptedEcdsaSEC1 := PEMEncryptDERBytes(t, PEMEncodeSEC1PrivateKey(t, ecdsaKey), testPassphrase)

	ed25519Key := GenerateEd25519Key(t)
	encryptedEd25519PKCS8 := PEMEncryptDERBytes(t, PEMEncodePKCS8PrivateKey(t, ed25519Key), testPassphrase)

	trashKey := pem.EncodeToMemory(&pem.Block{Type: "TRASH PRIVATE KEY"})
	encryptedTrashKey := PEMEncryptDERBytes(t, trashKey, testPassphrase)

	type args struct {
		pemBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr error
	}{
		{name: "RSA PKCS1", args: args{pemBytes: encryptedRsaPKCS1}, want: rsaKey, wantErr: nil},
		{name: "RSA PKCS8", args: args{pemBytes: encryptedRsaPKCS8}, want: rsaKey, wantErr: nil},

		{name: "RSA PKCS8 wrong password", args: args{pemBytes: encryptedRsaPKCS8WrongPassword}, want: nil, wantErr: x509.IncorrectPasswordError},

		{name: "ecdsa PKCS8", args: args{pemBytes: encryptedEcdsaPKCS8}, want: ecdsaKey, wantErr: nil},
		{name: "ecdsa SEC1", args: args{pemBytes: encryptedEcdsaSEC1}, want: ecdsaKey, wantErr: nil},

		{name: "ed25519 PKCS8", args: args{pemBytes: encryptedEd25519PKCS8}, want: ed25519Key, wantErr: nil},

		{name: "PEM but not a private key", args: args{pemBytes: encryptedTrashKey}, want: nil, wantErr: keybox.ErrNotAPrivateKey},
		{name: "non-pem", args: args{pemBytes: []byte("shall not decode")}, want: nil, wantErr: keybox.ErrKeyMustBePEMEncoded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.ParsePrivateKeyFromEncryptedPEMBytes(tt.args.pemBytes, []byte(testPassphrase))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParsePrivateKeyFromPEMBytes() error = %s, wantErr %s", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePrivateKeyFromPEMBytes() got = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("PEM but not encrypted", func(t *testing.T) {
		got, err := keybox.ParsePrivateKeyFromEncryptedPEMBytes(trashKey, []byte(testPassphrase))
		if err == nil {
			t.Errorf("ParsePrivateKeyFromPEMBytes() error = false, wantErr true")
			return
		}
		if got != nil {
			t.Errorf("ParsePrivateKeyFromPEMBytes() got = %v, want nil", got)
		}
	})
}

func TestParsePrivateKeyFromPEMBytes(t *testing.T) {
	t.Parallel()

	// Generate keys

	rsaKey := GenerateRSAKey(t)
	rsaPKCS1 := PEMEncodePKCS1PrivateKey(rsaKey)
	rsaPKCS8 := PEMEncodePKCS8PrivateKey(t, rsaKey)

	ecdsaKey := GenerateECDSAKey(t)
	ecdsaPKCS8 := PEMEncodePKCS8PrivateKey(t, ecdsaKey)
	ecdsaSEC1 := PEMEncodeSEC1PrivateKey(t, ecdsaKey)

	ed25519Key := GenerateEd25519Key(t)
	ed25519PKCS8 := PEMEncodePKCS8PrivateKey(t, ed25519Key)

	trashKey := pem.EncodeToMemory(&pem.Block{Type: "TRASH PRIVATE KEY"})

	type args struct {
		pemBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr error
	}{
		{name: "RSA PKCS1", args: args{pemBytes: rsaPKCS1}, want: rsaKey, wantErr: nil},
		{name: "RSA PKCS8", args: args{pemBytes: rsaPKCS8}, want: rsaKey, wantErr: nil},

		{name: "ecdsa PKCS8", args: args{pemBytes: ecdsaPKCS8}, want: ecdsaKey, wantErr: nil},
		{name: "ecdsa SEC1", args: args{pemBytes: ecdsaSEC1}, want: ecdsaKey, wantErr: nil},

		{name: "ed25519 PKCS8", args: args{pemBytes: ed25519PKCS8}, want: ed25519Key, wantErr: nil},

		{name: "PEM but not a private key", args: args{pemBytes: trashKey}, want: nil, wantErr: keybox.ErrNotAPrivateKey},
		{name: "non-pem", args: args{pemBytes: []byte("shall not decode")}, want: nil, wantErr: keybox.ErrKeyMustBePEMEncoded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.ParsePrivateKeyFromPEMBytes(tt.args.pemBytes)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParsePrivateKeyFromPEMBytes() error = %s, wantErr %s", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePrivateKeyFromPEMBytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func GenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %s", err)
	}

	return privateKey
}

func GenerateEd25519Key(t *testing.T) ed25519.PrivateKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %s", err)
	}

	return privateKey
}

func GenerateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %s", err)
	}

	return privateKey
}

func PEMEncodePKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.EncodeToMemory(privateKeyBlock)
}

func PEMEncodePKCS8PrivateKey(t *testing.T, key crypto.PrivateKey) []byte {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshall ecdsa key: %s", err)
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(privateKeyBlock)
}

func PEMEncodeSEC1PrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	privateKeyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshall ecdsa key: %s", err)
	}

	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(privateKeyBlock)
}

func PEMEncryptDERBytes(t *testing.T, bytes []byte, password string) []byte {
	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		t.Fatal("failed to decode pem bytes")
	}

	privateKeyBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("failed to encrypt pem block: %s", err)
	}

	return pem.EncodeToMemory(privateKeyBlock)
}

func WriteBytesToTempFile(t *testing.T, bytes []byte) string {
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("failed to create temp file: %s", err)
	}
	defer file.Close()

	t.Cleanup(func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Logf("failed to delete temp file: %s", err)
		}
	})

	if _, err := file.Write(bytes); err != nil {
		t.Fatalf("failed to write temp file: %s", err)
	}

	return file.Name()
}
