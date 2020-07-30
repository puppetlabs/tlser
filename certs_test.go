package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func generateCertificateAuthority() (*x509.Certificate, *rsa.PrivateKey, error) {
	template, err := getBaseCertTemplate("signer", nil, nil, 1)
	if err != nil {
		return nil, nil, err
	}
	template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign
	template.IsCA = true

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	bytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(bytes)
	return cert, priv, err
}

const (
	beginCertificate = "-----BEGIN CERTIFICATE-----"
	endCertificate   = "-----END CERTIFICATE-----"
)

func TestGetCertTemplate(t *testing.T) {
	const (
		cn   = "foo.com"
		ip1  = "10.0.0.1"
		ip2  = "10.0.0.2"
		dns1 = "bar.com"
		dns2 = "bat.com"
	)
	req := assert.New(t)

	signerCert, signerKey, err := generateCertificateAuthority()
	req.NoError(err)

	out, _, err := generateSignedCert(cn, []string{ip1, ip2}, []string{dns1, dns2}, 365, signerCert, signerKey)
	req.NoError(err)

	assert.Contains(t, out, beginCertificate)
	assert.Contains(t, out, endCertificate)

	decodedCert, _ := pem.Decode([]byte(out))
	assert.Nil(t, err)
	cert, err := x509.ParseCertificate(decodedCert.Bytes)
	assert.Nil(t, err)

	assert.Equal(t, cn, cert.Subject.CommonName)
	assert.Equal(t, 1, cert.SerialNumber.Sign())
	assert.Equal(t, 2, len(cert.IPAddresses))
	assert.Equal(t, ip1, cert.IPAddresses[0].String())
	assert.Equal(t, ip2, cert.IPAddresses[1].String())
	assert.Contains(t, cert.DNSNames, dns1)
	assert.Contains(t, cert.DNSNames, dns2)
	assert.False(t, cert.IsCA)
}
