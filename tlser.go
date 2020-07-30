// A utility for updating a Kubernetes TLS secret if it has expired or any of
// the inputs have changed.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
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

func readCa() (*x509.Certificate, *rsa.PrivateKey, error) {
	bytes, err := readPem(*cacrt)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to parse CA certificate: %v", err)
	}

	bytes, err = readPem(*cakey)
	if err != nil {
		return nil, nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to parse CA private key: %v", err)
	}

	return cert, key, nil
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	if len(*subject) == 0 {
		log.Fatalf("Missing required --subject parameter")
	}

	if len(*k8sName) == 0 {
		log.Print("No secret name provided, generating cert on stdout")
	}

	signerCert, signerKey, err := readCa()
	if err != nil {
		log.Fatal(err)
	}

	var ipStrings, dnsStrings []string
	if len(*ip) > 0 {
		ipStrings = strings.Split(*ip, ",")
	}
	if len(*dns) > 0 {
		dnsStrings = strings.Split(*dns, ",")
	}

	cert, key, err := generateSignedCert(
		*subject,
		ipStrings,
		dnsStrings,
		*expire,
		signerCert,
		signerKey,
	)
	if err != nil {
		log.Fatalf("Unable to generate certificate: %v", err)
	}

	fmt.Print(cert, key)
}
