package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	k8errors "k8s.io/apimachinery/pkg/api/errors"
)

type syncer struct {
	secrets   secrets
	id        identifier
	subject   string
	ip, dns   []string
	daysValid int
	labels    labels
	getSigner func() (certificate, error)
}

func (s syncer) sync() error {
	signer, err := s.getSigner()
	if err != nil {
		return fmt.Errorf("unable to get signing certificate: %w", err)
	}

	priorSecret, err := s.secrets.getSecret(s.id)
	if err != nil && !k8errors.IsNotFound(err) {
		return fmt.Errorf("unable to retrieve secret %v: %w", s.id, err)
	}

	var previous certificate
	if priorSecret != nil {
		if previous, err = getTLSFromSecret(priorSecret, s.id); err != nil {
			return err
		}
	}

	// Check whether it needs to be updated.
	if priorSecret != nil && previous.isValid(signer) && previous.inSync(s.subject, s.ip, s.dns) {
		if s.labels.Equals(priorSecret.Labels) {
			log.Print("Previous secret matches parameters, no update performed.")
			return nil
		}

		log.Printf("Labels out-of-sync: %+v, %+v", priorSecret.Labels, s.labels)
		log.Printf("Updating labels on secret %v", s.id)
		priorSecret.Labels = s.labels
		if err := s.secrets.setSecret(priorSecret, true); err != nil {
			return fmt.Errorf("unable to update secret %v: %w", s.id, err)
		}
		return nil
	}

	rsaKey := previous.key
	if rsaKey == nil {
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("unable to generate private key: %w", err)
		}
	}

	cert, key, err := generateSignedCert(
		s.subject,
		s.ip,
		s.dns,
		s.daysValid,
		rsaKey,
		signer,
	)
	if err != nil {
		return fmt.Errorf("unable to generate certificate: %w", err)
	}

	// Upload the new cert/key pair.
	log.Printf("Uploading new cert to secret %v", s.id)
	var secret secret
	secret.Name = s.id.name
	secret.Namespace = s.id.namespace
	secret.Data = map[string][]byte{"tls.crt": []byte(cert), "tls.key": []byte(key)}
	secret.Type = tlsSecretType
	secret.Labels = s.labels
	if err := s.secrets.setSecret(&secret, previous.cert != nil); err != nil {
		return fmt.Errorf("unable to update secret %v: %w", s.id, err)
	}
	return nil
}
