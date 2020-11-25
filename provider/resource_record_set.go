package provider

import (
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/miekg/dns"
	"github.com/trevex/terraform-provider-dns-gssapi/client"
)

func resourceRecordSet() *schema.Resource {
	return &schema.Resource{
		Create: resourceRecordSetCreate,
		Read:   resourceRecordSetRead,
		Update: resourceRecordSetUpdate,
		Delete: resourceRecordSetDelete,

		Schema: map[string]*schema.Schema{
			"zone": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"rrdatas": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Set: hashIPString,
			},
			"ttl": {
				Type:     schema.TypeInt,
				Optional: true,
				ForceNew: true,
				Default:  3600,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func resourceRecordSetCreate(d *schema.ResourceData, meta interface{}) error {
	d.SetId(resourceFQDN(d))
	return resourceRecordSetUpdate(d, meta)
}

func resourceRecordSetRead(d *schema.ResourceData, meta interface{}) error {
	if meta == nil {
		return fmt.Errorf("client is not set")
	}

	fqdn := resourceFQDN(d)
	rrType := resourceType(d)

	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, rrType)

	r, err := exchange(msg, meta)
	if err != nil {
		return fmt.Errorf("Error querying DNS record: %s", err)
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return fmt.Errorf("Error querying DNS record: %v (%s)", r.Rcode, dns.RcodeToString[r.Rcode])
	}
	// TODO: handle TypeNS

	if len(r.Answer) > 0 {
		var ttls sort.IntSlice

		rrDatas := schema.NewSet(hashIPString, nil)
		for _, answer := range r.Answer {
			d, ttl, err := getValue(answer)
			if err != nil {
				return fmt.Errorf("Error querying DNS record: %s", err)
			}
			rrDatas.Add(d)
			ttls = append(ttls, ttl)
		}
		sort.Sort(ttls)

		d.Set("rrdatas", rrDatas)
		d.Set("ttl", ttls[0])
	} else {
		d.SetId("")
	}
	return nil
}

func resourceRecordSetUpdate(d *schema.ResourceData, meta interface{}) error {
	if meta == nil {
		return fmt.Errorf("client is not set")
	}

	ttl := d.Get("ttl").(int)
	rType := d.Get("type").(string)
	fqdn := resourceFQDN(d)

	msg := new(dns.Msg)
	msg.SetUpdate(d.Get("zone").(string))

	if d.HasChange("rrdatas") {
		o, n := d.GetChange("rrdatas")
		os := o.(*schema.Set)
		ns := n.(*schema.Set)
		remove := os.Difference(ns).List()
		insert := ns.Difference(os).List()

		// Loop through all the old addresses and remove them
		for _, rrData := range remove {
			rrRemove, _ := dns.NewRR(fmt.Sprintf("%s %d %s %s", fqdn, ttl, rType, rrData.(string)))
			msg.Remove([]dns.RR{rrRemove})
		}
		// Loop through all the new addresses and insert them
		for _, rrData := range insert {
			rrInsert, _ := dns.NewRR(fmt.Sprintf("%s %d A %s", fqdn, ttl, rType, rrData.(string)))
			msg.Insert([]dns.RR{rrInsert})
		}

		r, err := exchange(msg, meta)
		if err != nil {
			d.SetId("")
			return fmt.Errorf("Error updating DNS record: %s", err)
		}
		if r.Rcode != dns.RcodeSuccess {
			d.SetId("")
			return fmt.Errorf("Error updating DNS record: %v (%s)", r.Rcode, dns.RcodeToString[r.Rcode])
		}
	}
	return resourceRecordSetRead(d, meta)
}

func resourceRecordSetDelete(d *schema.ResourceData, meta interface{}) error {
	if meta == nil {
		return fmt.Errorf("client is not set")
	}

	fqdn := resourceFQDN(d)
	rrType := resourceType(d)

	msg := new(dns.Msg)
	msg.SetUpdate(d.Get("zone").(string))

	rr, _ := dns.NewRR(fmt.Sprintf("%s 0 %s", fqdn, dns.TypeToString[rrType]))
	msg.RemoveRRset([]dns.RR{rr})

	r, err := exchange(msg, meta)
	if err != nil {
		return fmt.Errorf("Error deleting DNS record: %s", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Error deleting DNS record: %v (%s)", r.Rcode, dns.RcodeToString[r.Rcode])
	}

	return nil
}

func resourceFQDN(d *schema.ResourceData) string {
	fqdn := d.Get("zone").(string)
	if name, ok := d.GetOk("name"); ok {
		fqdn = fmt.Sprintf("%s.%s", name.(string), fqdn)
	}
	return fqdn
}

func resourceType(d *schema.ResourceData) uint16 {
	t := d.Get("type").(string)
	switch t {
	case "A":
		return dns.TypeA
	case "CNAME":
		return dns.TypeCNAME
	}
	return dns.TypeNone
}

func exchange(msg *dns.Msg, meta interface{}) (*dns.Msg, error) {
	pc := meta.(*ProviderContext)
	c := pc.Client
	retryTCP := false
	retries := 5

Retry:
	msg.SetTsig(pc.Keyname, client.TSIGGSS, 300, time.Now().Unix())

	r, _, err := c.Exchange(msg)

	if r.Truncated {
		if retryTCP {
			switch c.Net {
			case "udp":
				c.Net = "tcp"
			case "udp4":
				c.Net = "tcp4"
			case "udp6":
				c.Net = "tcp6"
			default:
				return nil, fmt.Errorf("Unknown transport: %s", c.Net)
			}
		} else {
			msg.SetEdns0(dns.DefaultMsgSize, false)
			retryTCP = true
		}
		retries = 5
		goto Retry
	}
	if r.Rcode == dns.RcodeServerFailure && retries > 0 {
		retries--
		goto Retry
	}
	if isTimeout(err) && retries > 0 {
		retries--
		goto Retry
	}
	return r, err
}

func isTimeout(err error) bool {
	timeout, ok := err.(net.Error)
	return ok && timeout.Timeout()
}

func hashIPString(v interface{}) int {
	addr := v.(string)
	ip := net.ParseIP(addr)
	h := fnv.New32a()
	if ip == nil {
		h.Write([]byte(addr))
	} else {
		h.Write([]byte(ip.String()))
	}
	return int(h.Sum32())
}

func getValue(answer interface{}) (string, int, error) {
	switch r := answer.(type) {
	case *dns.A:
		return scanAnswer(r.String())
	case *dns.CNAME:
		return scanAnswer(r.String())
	default:
		return "", 0, fmt.Errorf("unsupported answer type")
	}
}

func scanAnswer(str string) (string, int, error) {
	var name, class, typ, addr string
	var ttl int
	_, err := fmt.Sscanf(str, "%s\t%d\t%s\t%s\t%s", &name, &ttl, &class, &typ, &addr)
	return addr, ttl, err
}
