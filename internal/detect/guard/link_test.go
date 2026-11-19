package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/Kytherion/KyGate/internal/detect/guard/guardpb"
)

// counting answers Info and counts the calls it gets.
type counting struct {
	guardpb.UnimplementedGuardServer
	n atomic.Int64
}

func (c *counting) Info(context.Context, *guardpb.InfoRequest) (*guardpb.InfoResponse, error) {
	c.n.Add(1)
	return &guardpb.InfoResponse{Version: "test", Ready: true}, nil
}

// pki makes a CA, a server certificate for localhost, and a client
// certificate, as files.
func pki(t *testing.T) (dir string, ca *x509.CertPool, server tls.Certificate) {
	dir = t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	issue := func(name string, usage x509.ExtKeyUsage, serial int64) (tls.Certificate, []byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		kb, _ := x509.MarshalECPrivateKey(k)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
		pair, _ := tls.X509KeyPair(certPEM, keyPEM)
		return pair, certPEM, keyPEM
	}
	server, _, _ = issue("guard", x509.ExtKeyUsageServerAuth, 2)
	_, cc, ck := issue("gateway", x509.ExtKeyUsageClientAuth, 3)
	os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)
	os.WriteFile(filepath.Join(dir, "client.pem"), cc, 0o600)
	os.WriteFile(filepath.Join(dir, "client.key"), ck, 0o600)
	ca = x509.NewCertPool()
	ca.AddCert(caCert)
	return dir, ca, server
}

func serveMTLS(t *testing.T, addr string, ca *x509.CertPool, cert tls.Certificate, g *counting) (string, bool) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", false
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: ca, ClientAuth: tls.RequireAndVerifyClientCert})))
	guardpb.RegisterGuardServer(s, g)
	go s.Serve(ln)
	t.Cleanup(s.Stop)
	return ln.Addr().String(), true
}

// Architecture section 4.4: the gateway reaches the Guard over mutual TLS
// and spreads calls over every address its name resolves to.
func TestGuardLinkMutualTLSAndRoundRobin(t *testing.T) {
	dir, ca, cert := pki(t)
	a, b := &counting{}, &counting{}
	addrA, _ := serveMTLS(t, "127.0.0.1:0", ca, cert, a)
	_, port, _ := net.SplitHostPort(addrA)
	_, v6 := serveMTLS(t, "[::1]:"+port, ca, cert, b)

	t.Setenv("KYGATE_GUARD_TLS_CA", filepath.Join(dir, "ca.pem"))
	// Without the gateway's own certificate, the Guard refuses.
	c, err := Dial("localhost:" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.api.Info(ctx, &guardpb.InfoRequest{}); err == nil {
		t.Fatal("a caller without a client certificate is refused")
	}
	c.Close()

	t.Setenv("KYGATE_GUARD_TLS_CERT", filepath.Join(dir, "client.pem"))
	t.Setenv("KYGATE_GUARD_TLS_KEY", filepath.Join(dir, "client.key"))
	if TransportDescription() != "mutual TLS" {
		t.Fatal(TransportDescription())
	}
	c, err = Dial("localhost:" + port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 20; i++ {
		if _, err := c.api.Info(ctx, &guardpb.InfoRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if !v6 {
		t.Logf("no IPv6 loopback here: round robin not observed (%d calls to one Guard)", a.n.Load())
		return
	}
	if a.n.Load() == 0 || b.n.Load() == 0 {
		t.Fatalf("calls are spread over both addresses: %d and %d", a.n.Load(), b.n.Load())
	}
}

func TestGuardTLSSettings(t *testing.T) {
	t.Setenv("KYGATE_GUARD_TLS_CA", "")
	t.Setenv("KYGATE_GUARD_TLS_CERT", "x.pem")
	if _, err := TransportFromEnv(); err == nil {
		t.Fatal("a client certificate needs the Guard's CA")
	}
}
