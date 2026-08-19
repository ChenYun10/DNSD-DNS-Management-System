// gencert 生成本地自签名泛域名证书（*.BASE_DOMAIN），用于开发/测试。
// 生产环境请使用正式 CA 签发的证书。
//
// 用法: gencert -domain dns.example.com -out certs/
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	domain := flag.String("domain", "dns.example.com", "base domain (wildcard *.<domain> included)")
	out := flag.String("out", "certs", "output directory")
	flag.Parse()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "*." + *domain, Organization: []string{"dns-platform dev"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"*." + *domain, *domain},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(*out, "fullchain.pem"), certPEM, 0o644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "privkey.pem"), keyPEM, 0o600); err != nil {
		panic(err)
	}
	fmt.Printf("OK: %s/fullchain.pem + %s/privkey.pem (wildcard *.%s, valid 2y)\n", *out, *out, *domain)
}
