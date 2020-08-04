# tlser

A tiny utility for ensuring TLS certificates in Kubernetes are up-to-date.

`tlser` can be used standalone to generate certificates from a pregenerated CA (cert/key pair). Just provide `-subject` to get started.

`tlser` is really intended to be used as a small `initContainer` in a Kubernetes cluster that ensures certificates that are used by an application are up-to-date with template input, via [Helm](https://helm.sh) or [KOTS](https://kots.io). It's intended to be much simpler to use than [cert-manager](https://cert-manager.io) while still providing fully usable certificate maintenance.

To use `tlser` in a cluster, include `puppet/tlser:1.1.1` as an `initContainer`, mount a CA cert/key pair as a volume, and specify necessary arguments (`-name` is required) such as
```
tlser -cacert /cert/tls.crt -cakey /cert/tls.key -name app-tls -subject example.com -dns example.com,localhost,app -ip 10.0.0.1 -expire 365
```

When run, `tlser` will check whether a secret exists. If it exists, is not expired or about to expire, and its properties already match the parameters, it won't be regenerated. Otherwise it generates a new certificate and updates or creates the appropriate secret.

`tlser` can also be run continuously to monitor a cert and update it when necessary by passing the `-interval` flag, such as `-interval 6h`.
