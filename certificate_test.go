package keybox_test

import (
	"github.com/kernle32dll/keybox-go"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"reflect"
	"testing"
)

func TestLoadCertificate(t *testing.T) {
	t.Parallel()

	// Generate certificate

	cert := GenerateCertificate(t)
	certFile := WriteBytesToTempFile(t, PEMEncodeCertificate(cert))

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		wantErr error
	}{
		{name: "valid certificate", args: args{path: certFile}, want: cert, wantErr: nil},
		{name: "non-existent file", args: args{path: "does not exist"}, want: nil, wantErr: os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.LoadCertificate(tt.args.path)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("LoadCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadCertificate() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadCertificateWithPassword(t *testing.T) {
	t.Parallel()

	testPassphrase := "super-passphrase"

	// Generate certificate

	cert := GenerateCertificate(t)
	certFile := WriteBytesToTempFile(t, PEMEncryptDERBytes(t, PEMEncodeCertificate(cert), testPassphrase))
	certFileWrongPassword := WriteBytesToTempFile(t, PEMEncryptDERBytes(t, PEMEncodeCertificate(cert), "nope"))

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		wantErr error
	}{
		{name: "valid certificate", args: args{path: certFile}, want: cert, wantErr: nil},
		{name: "valid certificate wrong password", args: args{path: certFileWrongPassword}, want: nil, wantErr: x509.IncorrectPasswordError},
		{name: "non-existent file", args: args{path: "does not exist"}, want: nil, wantErr: os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.LoadCertificateWithPassword(tt.args.path, []byte(testPassphrase))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("LoadCertificateWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadCertificateWithPassword() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCertificateFromEncryptedPEMBytes(t *testing.T) {
	t.Parallel()

	testPassphrase := "super-passphrase"

	// Generate certificate

	cert := GenerateCertificate(t)
	certBytes := PEMEncryptDERBytes(t, PEMEncodeCertificate(cert), testPassphrase)
	certBytesWrongPassword := PEMEncryptDERBytes(t, PEMEncodeCertificate(cert), "nope")

	trashCert := pem.EncodeToMemory(&pem.Block{Type: "TRASH CERTIFICATE"})
	encryptedTrashCert := PEMEncryptDERBytes(t, trashCert, testPassphrase)

	type args struct {
		pemBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		wantErr error
	}{
		{name: "x509", args: args{pemBytes: certBytes}, want: cert, wantErr: nil},
		{name: "x509 wrong password", args: args{pemBytes: certBytesWrongPassword}, want: nil, wantErr: x509.IncorrectPasswordError},

		{name: "PEM but not a certificate", args: args{pemBytes: encryptedTrashCert}, want: nil, wantErr: keybox.ErrNotACertificate},
		{name: "non-pem", args: args{pemBytes: []byte("shall not decode")}, want: nil, wantErr: keybox.ErrCertificateMustBePEMEncoded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.ParseCertificateFromEncryptedPEMBytes(tt.args.pemBytes, []byte(testPassphrase))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseCertificateFromPEMBytes() error = %s, wantErr %s", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCertificateFromPEMBytes() got = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("PEM but not encrypted", func(t *testing.T) {
		got, err := keybox.ParseCertificateFromEncryptedPEMBytes(trashCert, []byte(testPassphrase))
		if err == nil {
			t.Errorf("ParseCertificateFromPEMBytes() error = false, wantErr true")
			return
		}
		if got != nil {
			t.Errorf("ParseCertificateFromPEMBytes() got = %v, want nil", got)
		}
	})
}

func TestParseCertificateFromPEMBytes(t *testing.T) {
	t.Parallel()

	// Generate certificate

	cert := GenerateCertificate(t)
	certFile := PEMEncodeCertificate(cert)

	trashCert := pem.EncodeToMemory(&pem.Block{Type: "TRASH CERTIFICATE"})

	type args struct {
		pemBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		wantErr error
	}{
		{name: "x509", args: args{pemBytes: certFile}, want: cert, wantErr: nil},
		{name: "PEM but not a certificate", args: args{pemBytes: trashCert}, want: nil, wantErr: keybox.ErrNotACertificate},
		{name: "non-pem", args: args{pemBytes: []byte("shall not decode")}, want: nil, wantErr: keybox.ErrCertificateMustBePEMEncoded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keybox.ParseCertificateFromPEMBytes(tt.args.pemBytes)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseCertificateFromPEMBytes() error = %s, wantErr %s", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCertificateFromPEMBytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func GenerateCertificate(t *testing.T) *x509.Certificate {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(123),

		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},

		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to generate certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %s", err)
	}

	return cert
}

func PEMEncodeCertificate(certificate *x509.Certificate) []byte {
	CertificateBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}

	return pem.EncodeToMemory(CertificateBlock)
}
