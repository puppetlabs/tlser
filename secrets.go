package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type secretGetter interface {
	getSecret(name, namespace string) (*corev1.Secret, error)
	setSecret(secret *corev1.Secret, update bool) error
}

func getTLSFromSecret(c secretGetter, name, namespace string) (certificate, error) {
	secret, err := c.getSecret(name, namespace)
	if err != nil {
		return certificate{}, err
	}

	if secret.Type != "kubernetes.io/tls" {
		return certificate{}, fmt.Errorf("Secret %v in namespace %v must have type kubernetes.io/tls, not %v", name, namespace, secret.Type)
	}

	certBytes, keyBytes := secret.Data["tls.crt"], secret.Data["tls.key"]
	if certBytes == nil || keyBytes == nil {
		return certificate{}, errors.New("Secret %v in namespace %v must include tls.crt and tls.key")
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
