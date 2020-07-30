package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

type secretMock struct {
	secret *corev1.Secret
	err    error
}

func (m secretMock) getSecret(name, namespace string) (*corev1.Secret, error) {
	return m.secret, m.err
}

func (m secretMock) setSecret(secret *corev1.Secret, update bool) error {
	m.secret = secret
	return m.err
}

var (
	testCert = `-----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAgIJAOC7Munm9txXMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNV
BAMTCmluZ3Jlc3MtY2EwHhcNMjAwNzMwMTgxMjE1WhcNMjAwOTI4MTgxMjE1WjAW
MRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALnXQWyU6RJvQI2R3D0mtCEywkxoXWllTqXR1Ahy9H3kwWB2ph8TuPxE
fNssbJ4t9aoX4FA4ANr2W+r/L1YF38/+5dZhu3mRsMttqPuPnmXH2fYmxoqpbxEO
MNsEh/uiett6q+RyK9/EBTMTxfD1fBBZqGp4VtwMxsGkIEYPTWUr9nOHbhJ0K5wc
RTZ/QD21Ul/B29w9OV3tTpzopzZRjHQqHz9lygtlmE/BJEQ/NL2IL0POkwOX04te
YRRbORWJeY568aMSgjaa74lWlD+mL+NdImG2murwAakJaQNfQ1nA6Ws7tKNByEL/
oWAm963IU11feUjclT1be6UGuV+TIE0CAwEAAaM5MDcwCQYDVR0TBAIwADALBgNV
HQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3
DQEBBQUAA4IBAQAt1ogOhlcCpSGNpKcRX3vM+UDj0JiLevtIqUend8zlKJI6zobP
vrfwLh2IGGMkX1MI+fwbnbI2qlzBfn2FZAymfuKipbxRX1GPOCdNS4wty+/FKwdm
4ezYng7XEIQQNAKKkXo74hCiv0OfglG1S0CQyWuaPO9jqPpBwlejih8QWDUHSsTZ
8HDpUwz6IRzBdOUEkJvyNBHVkMOiO1u7w0C991lG0sRn4ipzqrR7QYKEgGo5Y0ES
bcvS1gCdvtSeuqWOjKsPFh0WTt84wO7ElXEsWJS0eE5dUlkoS+g0FJ45ACNK5Gib
lGuVXeBG2+1aSdVxI17jYBdvn+w2pZh8hpE1
-----END CERTIFICATE-----`
	testKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuddBbJTpEm9AjZHcPSa0ITLCTGhdaWVOpdHUCHL0feTBYHam
HxO4/ER82yxsni31qhfgUDgA2vZb6v8vVgXfz/7l1mG7eZGwy22o+4+eZcfZ9ibG
iqlvEQ4w2wSH+6J623qr5HIr38QFMxPF8PV8EFmoanhW3AzGwaQgRg9NZSv2c4du
EnQrnBxFNn9APbVSX8Hb3D05Xe1OnOinNlGMdCofP2XKC2WYT8EkRD80vYgvQ86T
A5fTi15hFFs5FYl5jnrxoxKCNprviVaUP6Yv410iYbaa6vABqQlpA19DWcDpazu0
o0HIQv+hYCb3rchTXV95SNyVPVt7pQa5X5MgTQIDAQABAoIBACMTwCOQj9WM7jBK
gbmBHqrNe+MUJ92G46tkyZK2r/M7REzC2GQxQs9K1g5Aelf48M+kJhC+IVsy+PKI
LBUekrodsKAgXlR57VbYYfbpispHSJqvgvYVOQONHCea2VfjuTDIHL3H1wQraZfU
eZ4bl8k2QxWllS9/sdxG8FiI9uDLcpsG9jCLHVA40WME+epPj/DII6R9cNS3FgWQ
1spyWHFA1GpylXsUHLoq8ExfKl8AmM7X9atPOHAb9RQ0juYrgQJYVnJcnMz7s/xp
Jz+DgVtlRn4ZsAXR3sAqPLvGKkRy6hyuA/6H/g8oVtBsbszqZwMDwtCGv9aiR/EA
DTCfq3kCgYEA9NvJ3zib3PBVbRCrP/VY4HArl8INNQcaUTcgvMhhFzlh8/Pw7RCV
R/5bxyULEukwjLTKWvsTLAbGeGvqSFzM+VS5VjxayAF18535aC7Bk681eMAr7RDt
7SlyljRuBmxkUmszhm3NL3h0ZLBm3RXXD3tI3zYUiZRr0uk+87MqYc8CgYEAwkwB
P2Q6SA/wXfdsAki+k57fua34cZC7LNFLp3l2tc6aMPBV3PyaGKRZbwRPmZwnyqLe
NjorFzQKFJx8oYbPo+hFoE/uVraaeLWS/J5kMu3cYC0GGlifruJTi53Vq8yuHhDK
3gYwFVpI44QEKnWlcHkF92ck6w6WsvjKQGxxbyMCgYBzIHw0RkuSgDXKSBIcymD1
dggpHIZVLnfDQ+ZSnOx5nPNfXo0jCa8G4KOKaPJh+95l6gNS78Y95xmeOS84wtll
Sd6ym0Ib1AP/fYFs6L7/j1vW4JRGrLUR03EbCp/IyWIKFnltdWcKMNqZFQ/oV4J8
tvy2ZpkVbwGbcyu0LcN5pQKBgHqw0/jbqZHnvrkXjDTFCtLc+BmgKcpMwmVCpKtU
oAmeNO/CU/X/7K6y2WapKjqtyNLEld1YTe2RBuyNBIZbQrMV8SGSV8aZ+GFRB0hO
HKesXAS/aaMpY2xjrq3zNQIPdcO2huQ8tBBHus8whhDpyVaElafskft8ct0BDXYx
BFBRAoGBAL5K/jClotZz5f0tDiLeXA85RVpwmYat1Dkd0isY+8axcUQs9rZo4wZL
yGW6NKwfbukf4YeBbL5CSiD+bFSLuHTy4V8C4khRaw5WINYn1x0RM3AH4K4gRE7a
Sucz81ym6QREo7DZ4lDXuz5PhPW4KLeoWRw8syyraVQ/o6RsbHQ1
-----END RSA PRIVATE KEY-----`
)

func TestGetTLSFromSecret(t *testing.T) {
	req := assert.New(t)

	_, err := getTLSFromSecret(secretMock{err: errors.New("failed")}, "foo", "default")
	req.Error(err)

	var secret corev1.Secret
	mock := secretMock{secret: &secret}

	_, err = getTLSFromSecret(mock, "foo", "default")
	req.Error(err)

	secret.Type = "kubernetes.io/tls"
	_, err = getTLSFromSecret(mock, "foo", "default")
	req.Error(err)

	secret.Data["tls.crt"] = []byte(testCert)
	_, err = getTLSFromSecret(mock, "foo", "default")
	req.Error(err)

	secret.Data["tls.key"] = []byte(testKey)
	cert, err := getTLSFromSecret(mock, "foo", "default")
	req.NoError(err)
	req.NotNil(cert.cert)
	req.NotNil(cert.key)
}
