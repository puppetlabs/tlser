package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sort"
	"time"
)

func generateSignedCert(
	cn string,
	ip, dns []string,
	daysValid int,
	key *rsa.PrivateKey,
	signer certificate,
) (string, string, error) {
	var err error
	input := certificate{key: key}
	if input.cert, err = getBaseCertTemplate(cn, ip, dns, daysValid); err != nil {
		log.Fatalf("Unable to generate certificate template: %v", err)
	}
	return getCertAndKey(input, signer)
}

func getCertAndKey(
	input certificate,
	signer certificate,
) (string, string, error) {
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		input.cert,
		signer.cert,
		&input.key.PublicKey,
		signer.key,
	)
	if err != nil {
		return "", "", fmt.Errorf("error creating certificate: %s", err)
	}

	certBuffer := bytes.Buffer{}
	if err := pem.Encode(
		&certBuffer,
		&pem.Block{Type: "CERTIFICATE", Bytes: derBytes},
	); err != nil {
		return "", "", fmt.Errorf("error pem-encoding certificate: %s", err)
	}

	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(
		&keyBuffer,
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(input.key),
		},
	); err != nil {
		return "", "", fmt.Errorf("error pem-encoding key: %s", err)
	}

	return certBuffer.String(), keyBuffer.String(), nil
}

func getBaseCertTemplate(
	cn string,
	ips []string,
	dnsNames []string,
	daysValid int,
) (*x509.Certificate, error) {
	ipAddresses, err := getNetIPs(ips)
	if err != nil {
		return nil, err
	}
	serialNumberUpperBound := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberUpperBound)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		IPAddresses: ipAddresses,
		DNSNames:    dnsNames,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * time.Duration(daysValid)),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}, nil
}

func getNetIPs(ips []string) ([]net.IP, error) {
	if ips == nil {
		return []net.IP{}, nil
	}
	var netIP net.IP
	netIPs := make([]net.IP, len(ips))
	for i, ipStr := range ips {
		netIP = net.ParseIP(ipStr)
		if netIP == nil {
			return nil, fmt.Errorf("error parsing ip: %s", ipStr)
		}
		netIPs[i] = netIP
	}
	return netIPs, nil
}

type certificate struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func (c certificate) isValid(signer certificate) bool {
	pool := x509.NewCertPool()
	pool.AddCert(signer.cert)
	_, err := c.cert.Verify(x509.VerifyOptions{Roots: pool})
	if err != nil {
		log.Printf("Invalid cert: %v", err)
		return false
	}
	return true
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Returns false if common name or alternate names don't match.
func (c certificate) inSync(cn string, ip, dns []string) bool {
	if c.cert.Subject.CommonName != cn {
		log.Printf("Subject out-of-sync: %v, %v", c.cert.Subject.CommonName, cn)
		return false
	}

	if !equal(c.cert.DNSNames, dns) {
		log.Printf("DNS names out-of-sync: %v, %v", c.cert.DNSNames, dns)
		return false
	}

	ipaddrs := make([]string, len(c.cert.IPAddresses))
	for i, addr := range c.cert.IPAddresses {
		ipaddrs[i] = addr.String()
	}
	if !equal(ipaddrs, ip) {
		log.Printf("IP addresses out-of-sync: %v, %v", ipaddrs, ip)
		return false
	}

	return true
}
