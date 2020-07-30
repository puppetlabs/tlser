package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func generateCertificateAuthority() (certificate, error) {
	template, err := getBaseCertTemplate("signer", nil, nil, 1)
	if err != nil {
		return certificate{}, err
	}
	template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign
	template.IsCA = true

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return certificate{}, err
	}

	bytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return certificate{}, err
	}

	cert, err := x509.ParseCertificate(bytes)
	return certificate{cert: cert, key: priv}, err
}

func generateX509(cn string, ip, dns []string, daysValid int, key *rsa.PrivateKey, signer certificate) (*x509.Certificate, error) {
	out, _, err := generateSignedCert(cn, ip, dns, daysValid, key, signer)
	if err != nil {
		return nil, err
	}
	decodedCert, _ := pem.Decode([]byte(out))
	if decodedCert == nil {
		return nil, errors.New("failed")
	}
	return x509.ParseCertificate(decodedCert.Bytes)
}

func TestGetCertTemplate(t *testing.T) {
	const (
		cn   = "foo.com"
		ip1  = "10.0.0.1"
		ip2  = "10.0.0.2"
		dns1 = "bar.com"
		dns2 = "bat.com"
	)
	req := assert.New(t)

	signer, err := generateCertificateAuthority()
	req.NoError(err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	req.NoError(err)

	cert, err := generateX509(cn, []string{ip1, ip2}, []string{dns1, dns2}, 365, key, signer)
	req.NoError(err)

	req.Equal(cn, cert.Subject.CommonName)
	req.Equal(1, cert.SerialNumber.Sign())
	req.Equal(2, len(cert.IPAddresses))
	req.Equal(ip1, cert.IPAddresses[0].String())
	req.Equal(ip2, cert.IPAddresses[1].String())
	req.Contains(cert.DNSNames, dns1)
	req.Contains(cert.DNSNames, dns2)
	req.False(cert.IsCA)
}

func TestIsValid(t *testing.T) {
	req := assert.New(t)
	var cert certificate

	signer, err := generateCertificateAuthority()
	req.NoError(err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	req.NoError(err)

	cert.cert, err = generateX509("foo", []string{}, []string{}, 1, key, signer)
	req.NoError(err)
	req.True(cert.isValid(signer))

	signer2, err := generateCertificateAuthority()
	req.NoError(err)
	req.False(cert.isValid(signer2))

	cert.cert, err = generateX509("foo", []string{}, []string{}, 0, key, signer)
	req.NoError(err)
	req.False(cert.isValid(signer))

}

func TestInSync(t *testing.T) {
	const (
		cn   = "foo.com"
		ip1  = "10.0.0.1"
		ip2  = "10.0.0.2"
		dns1 = "bar.com"
		dns2 = "bat.com"
	)
	req := assert.New(t)
	var cert certificate

	signer, err := generateCertificateAuthority()
	req.NoError(err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	req.NoError(err)

	cert.cert, err = generateX509(cn, []string{}, []string{}, 1, key, signer)
	req.NoError(err)

	req.True(cert.inSync(cn, []string{}, []string{}))
	req.True(cert.inSync(cn, nil, []string{}))
	req.True(cert.inSync(cn, []string{}, nil))
	req.True(cert.inSync(cn, nil, nil))
	req.False(cert.inSync("bar", []string{}, []string{}))
	req.False(cert.inSync(cn, []string{ip1}, []string{}))
	req.False(cert.inSync(cn, []string{}, []string{dns1}))

	cert.cert, err = generateX509(cn, []string{ip1, ip2}, []string{dns2, dns1}, 1, key, signer)
	req.NoError(err)

	req.True(cert.inSync(cn, []string{ip1, ip2}, []string{dns1, dns2}))
	req.True(cert.inSync(cn, []string{ip2, ip1}, []string{dns2, dns1}))
	req.False(cert.inSync("bar", []string{ip1, ip2}, []string{dns1, dns2}))
	req.False(cert.inSync(cn, []string{ip1}, []string{dns1, dns2}))
	req.False(cert.inSync(cn, []string{ip1, ip2}, []string{dns2}))
}
