package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/trevex/terraform-provider-dns-gssapi/client"
)

type Env struct {
	client.Config
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	env := Env{}
	if err := json.Unmarshal(data, &env); err != nil {
		panic(err)
	}

	c := client.NewClient(&env.Config)
	keyname, _, err := c.NegotiateContext(env.Username, env.Password)
	if err != nil {
		panic(err)
	}

	name := fmt.Sprintf("%s.%s.", "mytestfromgolang", env.Domain)
	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn(env.Domain))
	insert, err := dns.NewRR(fmt.Sprintf("%s 300 A 192.0.2.1", name))
	if err != nil {
		panic(err)
	}
	msg.Insert([]dns.RR{insert})
	msg.SetTsig(keyname, client.TSIGGSS, 300, time.Now().Unix())

	fmt.Println(msg.String())

	rr, _, err := c.Exchange(msg)
	if err != nil {
		panic(err)
	}
	if rr.Rcode != dns.RcodeSuccess {
		fmt.Printf("DNS error: %s (%d)\n", dns.RcodeToString[rr.Rcode], rr.Rcode)
	}
}
