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

	corev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
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

	k8sName = flag.String("name", "", "Name of the Kubernetes secret to update")
	k8sNs   = flag.String("namespace", "default", "Namespace of the Kubernetes secret to update")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	if len(*subject) == 0 {
		log.Fatalf("Missing required -subject parameter")
	}

	var sg secretGetter
	var previous certificate
	if len(*k8sName) == 0 {
		log.Print("No secret name provided, generating cert on stdout")
	} else {
		// Get a Kubernetes client
		cfg, err := config.GetConfig()
		if err != nil {
			log.Fatalf("Unable to get Kubernetes config: %v", err)
		}

		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			log.Fatalf("Unable to initialize Kubernetes client: %v", err)
		}
		sg = k8sAdapter{clientset: clientset}

		previous, err = getTLSFromSecret(sg, *k8sName, *k8sNs)
		if err != nil && !k8errors.IsNotFound(err) {
			log.Fatalf("Unable to retrieve secret %v in namespace %v: %v", *k8sName, *k8sNs, err)
		}
	}

	var ipStrings, dnsStrings []string
	if len(*ip) > 0 {
		ipStrings = strings.Split(*ip, ",")
	}
	if len(*dns) > 0 {
		dnsStrings = strings.Split(*dns, ",")
	}

	if previous.cert != nil {
		// Check whether it needs to be updated.
		if previous.isValid() && previous.inSync(*subject, ipStrings, dnsStrings) {
			log.Print("Previous cert matches parameters, no update performed.")
			return
		}
	}

	signer, err := readCa(*cacrt, *cakey)
	if err != nil {
		log.Fatal(err)
	}

	rsaKey := previous.key
	if rsaKey == nil {
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Unable to generate private key: %v", err)
		}
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

	if sg != nil {
		// Upload the new cert/key pair.
		log.Printf("Uploading new cert to secret %v in namespace %v", *k8sName, *k8sNs)
		var secret *corev1.Secret
		secret.Name = *k8sName
		secret.Namespace = *k8sNs
		secret.Data = map[string][]byte{"tls.crt": []byte(cert), "tls.key": []byte(key)}
		secret.Type = "kubernetes.io/tls"
		sg.setSecret(secret, previous.cert != nil)
	} else {
		fmt.Print(cert, key)
	}
}

func readPem(file string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Unable to read %v: %v", cacrt, err)
	}

	decoded, _ := pem.Decode(bytes)
	if decoded == nil {
		return nil, fmt.Errorf("Unable to decode: %v", bytes)
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

func (a k8sAdapter) getSecret(name, namespace string) (*corev1.Secret, error) {
	return a.clientset.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func (a k8sAdapter) setSecret(secret *corev1.Secret, update bool) (err error) {
	secretI := a.clientset.CoreV1().Secrets(secret.Namespace)
	if update {
		_, err = secretI.Update(context.Background(), secret, metav1.UpdateOptions{})
	} else {
		_, err = secretI.Create(context.Background(), secret, metav1.CreateOptions{})
	}
	return
}
