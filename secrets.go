package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type identifier struct {
	name, namespace string
}

func (id identifier) String() string {
	return fmt.Sprintf("%v in namespace %v", id.name, id.namespace)
}

type secrets interface {
	getSecret(id identifier) (*corev1.Secret, error)
	setSecret(secret *corev1.Secret, update bool) error
}

func getTLSFromSecret(c secrets, id identifier) (certificate, error) {
	secret, err := c.getSecret(id)
	if err != nil {
		return certificate{}, err
	}

	if secret.Type != "kubernetes.io/tls" {
		return certificate{}, fmt.Errorf("Secret %v must have type kubernetes.io/tls, not %v", id, secret.Type)
	}

	certBytes, keyBytes := secret.Data["tls.crt"], secret.Data["tls.key"]
	if certBytes == nil || keyBytes == nil {
		return certificate{}, fmt.Errorf("Secret %v must include tls.crt and tls.key", id)
	}

	certDecoded, _ := pem.Decode(certBytes)
	if certDecoded == nil {
		return certificate{}, fmt.Errorf("Unable to decode: %v", certBytes)
	}

	keyDecoded, _ := pem.Decode(keyBytes)
	if keyDecoded == nil {
		return certificate{}, fmt.Errorf("Unable to decode: %v", keyBytes)
	}

	return parseCertPair(certDecoded.Bytes, keyDecoded.Bytes)
}

func parseCertPair(certBytes, keyBytes []byte) (certificate, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return certificate{}, fmt.Errorf("Unable to parse certificate: %v", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return certificate{}, fmt.Errorf("Unable to parse private key: %v", err)
	}

	return certificate{cert: cert, key: key}, nil
}
