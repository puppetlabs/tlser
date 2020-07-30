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
	"time"
)

func generateSignedCert(
	cn string,
	ip, dns []string,
	daysValid int,
	signerCert *x509.Certificate,
	signerKey *rsa.PrivateKey,
) (string, string, error) {
	template, err := getBaseCertTemplate(cn, ip, dns, daysValid)
	if err != nil {
		log.Fatalf("Unable to generate certificate template: %v", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Unable to generate private key: %v", err)
	}

	return getCertAndKey(template, priv, signerCert, signerKey)
}

func getCertAndKey(
	template *x509.Certificate,
	signeeKey *rsa.PrivateKey,
	parent *x509.Certificate,
	signingKey *rsa.PrivateKey,
) (string, string, error) {
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parent,
		&signeeKey.PublicKey,
		signingKey,
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
			Bytes: x509.MarshalPKCS1PrivateKey(signeeKey),
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
