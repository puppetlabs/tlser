package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestSync(t *testing.T) {
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

	sync := syncer{
		id:        identifier{name: "tlser", namespace: "default"},
		subject:   cn,
		ip:        []string{ip1, ip2},
		dns:       []string{dns1, dns2},
		daysValid: 365,
		getSigner: func() (certificate, error) { return signer, nil },
	}

	var m1, m2, m3, m4, m5 secretMock

	m1.On("getSecret", sync.id).Return((*secret)(nil), errors.New("failed"))
	sync.secrets = &m1
	req.Error(sync.sync())
	m1.AssertExpectations(t)

	notFound := k8errors.NewNotFound(schema.GroupResource{Resource: "Secret"}, sync.id.name)
	m2.On("getSecret", sync.id).Return((*secret)(nil), notFound)
	m2.On("setSecret", mock.AnythingOfType("*v1.Secret"), false).Return(nil)
	sync.secrets = &m2
	req.NoError(sync.sync())
	m2.AssertExpectations(t)

	m3.On("getSecret", sync.id).Return((*secret)(nil), notFound)
	m3.On("setSecret", mock.AnythingOfType("*v1.Secret"), false).Return(errors.New("failed"))
	sync.secrets = &m3
	req.Error(sync.sync())
	m3.AssertExpectations(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	req.NoError(err)
	certBytes, keyBytes, err := generateSignedCert(cn, []string{ip1, ip2}, []string{dns1, dns2}, 50, key, signer)
	req.NoError(err)
	secret := secret{
		Type: tlsSecretType,
		Data: map[string][]byte{"tls.crt": []byte(certBytes), "tls.key": []byte(keyBytes)},
	}
	secret.Name = sync.id.name
	secret.Namespace = sync.id.namespace
	m4.On("getSecret", sync.id).Return(&secret, nil)
	sync.secrets = &m4
	req.NoError(sync.sync())
	m4.AssertExpectations(t)

	req.NoError(err)
	certBytes, keyBytes, err = generateSignedCert(cn, []string{}, []string{}, 50, key, signer)
	req.NoError(err)
	secret.Data = map[string][]byte{"tls.crt": []byte(certBytes), "tls.key": []byte(keyBytes)}
	m5.On("getSecret", sync.id).Return(&secret, nil)
	m5.On("setSecret", mock.AnythingOfType("*v1.Secret"), true).Return(nil)
	sync.secrets = &m5
	req.NoError(sync.sync())
	m5.AssertExpectations(t)
}
