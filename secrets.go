package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

const tlsSecretType = "kubernetes.io/tls"

type secret = corev1.Secret

type identifier struct {
	name, namespace string
}

func (id identifier) String() string {
	return fmt.Sprintf("%v in namespace %v", id.name, id.namespace)
}

type secrets interface {
	getSecret(id identifier) (*secret, error)
	setSecret(secret *secret, update bool) error
}

func getTLSFromSecret(c secrets, id identifier) (certificate, error) {
	secret, err := c.getSecret(id)
	if err != nil {
		return certificate{}, err
	}

	if secret.Type != tlsSecretType {
		return certificate{}, fmt.Errorf("secret %v must have type %v, not %v", id, tlsSecretType, secret.Type)
	}

	certBytes, keyBytes := secret.Data["tls.crt"], secret.Data["tls.key"]
	if certBytes == nil || keyBytes == nil {
		return certificate{}, fmt.Errorf("secret %v must include tls.crt and tls.key", id)
	}

	certDecoded, _ := pem.Decode(certBytes)
	if certDecoded == nil {
		return certificate{}, fmt.Errorf("unable to decode: %v", certBytes)
	}

	keyDecoded, _ := pem.Decode(keyBytes)
	if keyDecoded == nil {
		return certificate{}, fmt.Errorf("unable to decode: %v", keyBytes)
	}

	return parseCertPair(certDecoded.Bytes, keyDecoded.Bytes)
}

func parseCertPair(certBytes, keyBytes []byte) (certificate, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return certificate{}, fmt.Errorf("unable to parse certificate: %w", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return certificate{}, fmt.Errorf("unable to parse private key: %w", err)
	}

	return certificate{cert: cert, key: key}, nil
}
