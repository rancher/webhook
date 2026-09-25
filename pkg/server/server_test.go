package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeCert generates a fresh self-signed cert/key pair for cn and writes it to
// certPath/keyPath, so tests can simulate a secret rotation by calling it again.
func writeCert(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(0, 0).Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, certOut.Close())

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	require.NoError(t, keyOut.Close())
}

func TestCertReloaderCachesUntilFilesChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeCert(t, certPath, keyPath, "v1")

	r, err := newCertReloader(certPath, keyPath)
	require.NoError(t, err)

	first, err := r.getCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := r.getCertificate(nil)
	require.NoError(t, err)
	assert.Same(t, first, second, "expected cached cert to be reused when files are unchanged")

	// Bump mtimes so the reloader notices, but keep identical content: a
	// no-op rotation should still return an equivalent (re-parsed) cert.
	future := time.Now().Add(time.Minute)
	require.NoError(t, os.Chtimes(certPath, future, future))
	require.NoError(t, os.Chtimes(keyPath, future, future))

	third, err := r.getCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, third)
	assert.NotSame(t, first, third, "expected reload after mtime change")
}

func TestCertReloaderFallsBackToCachedCertOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeCert(t, certPath, keyPath, "v1")

	r, err := newCertReloader(certPath, keyPath)
	require.NoError(t, err)

	good, err := r.getCertificate(nil)
	require.NoError(t, err)

	// Simulate a rotation race: tls.crt updated, tls.key not yet - or
	// corrupted - so LoadX509KeyPair fails on the new pair.
	future := time.Now().Add(time.Minute)
	require.NoError(t, os.WriteFile(certPath, []byte("not a cert"), 0o600))
	require.NoError(t, os.Chtimes(certPath, future, future))

	fallback, err := r.getCertificate(nil)
	require.NoError(t, err, "reload failure should fall back to cached cert, not error the handshake")
	assert.Same(t, good, fallback)
}

func TestNewCertReloaderFailsWithNoCachedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	_, err := newCertReloader(certPath, keyPath)
	assert.Error(t, err, "startup with no cert files and no cache should fail, not serve nothing")
}
