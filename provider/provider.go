package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/trevex/terraform-provider-dns-gssapi/client"
)

type ProviderContext struct {
	Client  *client.Client
	Keyname string
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"ip": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("DNS_GSSAPI_IP", ""),
				},
				"hostname": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("DNS_GSSAPI_HOSTNAME", nil),
				},
				"port": {
					Type:        schema.TypeInt,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("DNS_GSSAPI_PORT", 53),
				},
				"realm": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("DNS_GSSAPI_REALM", nil),
				},
				"username": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("DNS_GSSAPI_USERNAME", nil),
				},
				"password": {
					Type:        schema.TypeString,
					Required:    true,
					Sensitive:   true,
					DefaultFunc: schema.EnvDefaultFunc("DNS_GSSAPI_PASSWORD", nil),
				},
			},
			ResourcesMap: map[string]*schema.Resource{
				"dns_record_set": resourceRecordSet(),
			},
			DataSourcesMap:       map[string]*schema.Resource{},
			ConfigureContextFunc: providerConfigure,
		}

		return p
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	ip := d.Get("ip").(string)
	hostname := d.Get("hostname").(string)
	port := d.Get("port").(int)
	realm := d.Get("realm").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	var diags diag.Diagnostics
	// if username == "" || password == "" {
	// 	diags = append(diags, diag.Diagnostic{
	// 		Severity: diag.Error,
	// 		Summary:  "Unable to create HashiCups client",
	// 		Detail:   "Unable to authenticate user for authenticated HashiCups client",
	// 	})
	// 	return nil, diags
	// }
	c := client.NewClient(&client.Config{
		HostIP:   ip,
		Hostname: hostname,
		Port:     fmt.Sprintf("%d", port),
		Realm:    realm,
	})
	keyname, _, err := c.NegotiateContext(username, password)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Failed to negotiate kerberos context using credentials",
			Detail:   fmt.Sprintf("Authentication failed with error: %s", err),
		})
		return nil, diags
	}

	pc := &ProviderContext{
		Client:  c,
		Keyname: keyname,
	}
	return pc, diags
}
