module github.com/trevex/terraform-provider-dns-gssapi

go 1.15

require (
	github.com/bodgit/tsig v0.0.0-20200920200203-498050e2aa64
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.0.4
	github.com/jcmturner/gokrb5/v8 v8.4.1
	github.com/miekg/dns v1.1.35
)

replace google.golang.org/api v0.28.0 => github.com/googleapis/google-api-go-client v0.28.0
