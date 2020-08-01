// A utility for updating a Kubernetes TLS secret if it has expired or any of
// the inputs have changed.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

var (
	cacrt   = flag.String("cacert", "./ca.pem", "Path to a CA certificate")
	cakey   = flag.String("cakey", "./ca-key.pem", "Path to a CA private key")
	subject = flag.String("subject", "", "The certificate Subject Common Name")
	expire  = flag.Int("expire", 60, "Certificate expiration in days")
	dns     = flag.String("dns", "", "Comma-separated list of DNS alternative names")
	ip      = flag.String("ip", "", "Comma-separated list of valid IP addresses")

	k8sName  = flag.String("name", "", "Name of the Kubernetes secret to update")
	k8sNs    = flag.String("namespace", "default", "Namespace of the Kubernetes secret to update")
	interval = flag.String("interval", "", "Interval to check if cert is insync (ex: 1h, 30m)")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	if len(*subject) == 0 {
		log.Fatalf("Missing required -subject parameter")
	}

	var err error
	var syncInterval time.Duration
	if len(*interval) != 0 {
		syncInterval, err = time.ParseDuration(*interval)
		if err != nil {
			log.Fatalf("Parameter -interval was not a valid duration: %v", err)
		}
	}

	var ipStrings, dnsStrings []string
	if len(*ip) > 0 {
		ipStrings = strings.Split(*ip, ",")
	}
	if len(*dns) > 0 {
		dnsStrings = strings.Split(*dns, ",")
	}

	signer, err := readCa(*cacrt, *cakey)
	if err != nil {
		log.Fatalf("Failed to read CA files: %v", err)
	}

	if len(*k8sName) == 0 {
		log.Print("No secret name provided, generating cert on stdout")

		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Unable to generate private key: %v", err)
		}

		cert, key, err := generateSignedCert(
			*subject,
			ipStrings,
			dnsStrings,
			*expire,
			rsaKey,
			signer,
		)
		if err != nil {
			log.Fatalf("Unable to generate certificate: %v", err)
		}

		fmt.Print(cert, key)
		return
	}

	// Get a Kubernetes client
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatalf("Unable to get Kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Unable to initialize Kubernetes client: %v", err)
	}

	sync := syncer{
		secrets:   k8sAdapter{clientset: clientset},
		id:        identifier{name: *k8sName, namespace: *k8sNs},
		subject:   *subject,
		ip:        ipStrings,
		dns:       dnsStrings,
		daysValid: *expire,
		signer:    signer,
	}

	if syncInterval == time.Duration(0) {
		if err := sync.sync(); err != nil {
			log.Fatalf("Unable to sync certs: %v", err)
		}
		return
	}

	log.Printf("Monitoring every %v", syncInterval)
	for {
		if err := sync.sync(); err != nil {
			log.Fatalf("Unable to sync certs: %v", err)
		}
		time.Sleep(syncInterval)
	}
}

func readPem(file string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %w", cacrt, err)
	}

	decoded, _ := pem.Decode(bytes)
	if decoded == nil {
		return nil, fmt.Errorf("unable to decode: %v", bytes)
	}
	return decoded.Bytes, nil
}

func readCa(cacrt, cakey string) (certificate, error) {
	certBytes, err := readPem(cacrt)
	if err != nil {
		return certificate{}, err
	}

	keyBytes, err := readPem(cakey)
	if err != nil {
		return certificate{}, err
	}

	return parseCertPair(certBytes, keyBytes)
}

type k8sAdapter struct {
	clientset *kubernetes.Clientset
}

func (a k8sAdapter) getSecret(id identifier) (*secret, error) {
	return a.clientset.CoreV1().Secrets(id.namespace).Get(context.Background(), id.name, metav1.GetOptions{})
}

func (a k8sAdapter) setSecret(secret *secret, update bool) (err error) {
	secretI := a.clientset.CoreV1().Secrets(secret.Namespace)
	if update {
		_, err = secretI.Update(context.Background(), secret, metav1.UpdateOptions{})
	} else {
		_, err = secretI.Create(context.Background(), secret, metav1.CreateOptions{})
	}
	return
}
