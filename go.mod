module github.com/puppetlabs/tlser

go 1.14

require (
	github.com/stretchr/testify v1.7.0
	k8s.io/api v0.21.7
	k8s.io/apimachinery v0.21.7
	k8s.io/client-go v0.21.7
	sigs.k8s.io/controller-runtime v0.9.7
)

// Fix CVE; pulled in by controller-runtime.
replace github.com/miekg/dns => github.com/miekg/dns v1.1.25
