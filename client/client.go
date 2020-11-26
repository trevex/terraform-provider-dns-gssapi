// Heavily based on Matt Dainty work, who based it on the extension of
// Miek Gieben to the official Go code, see LICENSE.

package client

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bodgit/tsig"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/miekg/dns"
)

const (
	TSIGGSS                  = tsig.GSS
	dnsTimeout time.Duration = 2 * time.Second
)

type Config struct {
	HostIP   string `json:"ip"`
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
	Realm    string `json:"realm"`
}

type context struct {
	client *client.Client
	key    types.EncryptionKey
}

type Client struct {
	dns.Client
	Config
	m   sync.RWMutex
	ctx map[string]context

	SkipVerify bool
}

func NewClient(cfg *Config) *Client {
	return &Client{
		Config: *cfg,
		ctx:    make(map[string]context),
	}
}

func (c *Client) NegotiateContext(username, password string) (string, *time.Time, error) {
	host := c.Hostname
	if c.HostIP != "" {
		host = c.HostIP
	}

	cfg, err := config.NewFromString(generateConfig(c.Realm, c.HostIP))
	if err != nil {
		return "", nil, fmt.Errorf("Failed to load generated config: %w", err)
	}
	cl := client.NewWithPassword(username, c.Realm, password, cfg, client.DisablePAFXFAST(true))
	err = cl.Login()
	if err != nil {
		return "", nil, fmt.Errorf("Failed to login: %w", err)
	}

	keyname := generateTKEYName(c.Hostname)

	tkt, key, err := cl.GetServiceTicket(generateSPN(c.Hostname))
	if err != nil {
		return "", nil, err
	}

	apreq, err := spnego.NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagInteg}, []int{gssapi.ContextFlagMutual})
	if err != nil {
		return "", nil, err
	}

	b, err := apreq.Marshal()
	if err != nil {
		return "", nil, err
	}

	// We don't care about non-TKEY answers, no additional RR's to send, and no signing
	tkey, _, err := tsig.ExchangeTKEY(host, keyname, tsig.GSS, tsig.TkeyModeGSS, 3600, b, nil, nil, nil, nil)
	if err != nil {
		return "", nil, err
	}

	if tkey.Header().Name != keyname {
		return "", nil, fmt.Errorf("TKEY name does not match")
	}

	b, err = hex.DecodeString(tkey.Key)
	if err != nil {
		return "", nil, err
	}

	var aprep spnego.KRB5Token
	err = aprep.Unmarshal(b)
	if err != nil {
		return "", nil, err
	}

	if aprep.IsKRBError() {
		return "", nil, fmt.Errorf("received Kerberos error")
	}

	if !aprep.IsAPRep() {
		return "", nil, fmt.Errorf("didn't receive an AP_REP")
	}

	b, err = crypto.DecryptEncPart(aprep.APRep.EncPart, key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return "", nil, err
	}

	var payload messages.EncAPRepPart
	err = payload.Unmarshal(b)
	if err != nil {
		return "", nil, err
	}

	expiry := time.Unix(int64(tkey.Expiration), 0)

	c.m.Lock()
	defer c.m.Unlock()

	c.ctx[keyname] = context{
		client: cl,
		key:    payload.Subkey,
	}

	return keyname, &expiry, nil
}

func (c *Client) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	co, err := c.Dial(net.JoinHostPort(c.HostIP, c.Port))
	if err != nil {
		return nil, 0, err
	}
	defer co.Close()

	keyname := m.IsTsig().Hdr.Name // TODO: properly check availability
	co.SetupTSIG(keyname, c.generate, c.verify)

	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}
	// Otherwise use the client's configured UDP size.
	if opt == nil && c.UDPSize >= dns.MinMsgSize {
		co.UDPSize = c.UDPSize
	}

	t := time.Now()
	// write with the appropriate write timeout
	co.SetWriteDeadline(t.Add(c.getTimeoutForRequest(c.writeTimeout())))
	if err = co.WriteMsg(m); err != nil {
		return nil, 0, err
	}

	co.SetReadDeadline(time.Now().Add(c.getTimeoutForRequest(c.readTimeout())))
	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = dns.ErrId
	}
	rtt = time.Since(t)
	return r, rtt, err
}

// Dial connects to the address on the named network.
func (c *Client) Dial(address string) (conn *Conn, err error) {
	// create a new dialer with the appropriate timeout
	var d net.Dialer
	if c.Dialer == nil {
		d = net.Dialer{}
	} else {
		d = net.Dialer(*c.Dialer)
	}
	d.Timeout = c.getTimeoutForRequest(c.writeTimeout())

	network := "udp"
	useTLS := false

	switch c.Net {
	case "tcp-tls":
		network = "tcp"
		useTLS = true
	case "tcp4-tls":
		network = "tcp4"
		useTLS = true
	case "tcp6-tls":
		network = "tcp6"
		useTLS = true
	default:
		if c.Net != "" {
			network = c.Net
		}
	}

	conn = new(Conn)
	if useTLS {
		conn.Conn.Conn, err = tls.DialWithDialer(&d, network, address, c.TLSConfig)
	} else {
		conn.Conn.Conn, err = d.Dial(network, address)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Return the appropriate timeout for a specific request
func (c *Client) getTimeoutForRequest(timeout time.Duration) time.Duration {
	var requestTimeout time.Duration
	if c.Timeout != 0 {
		requestTimeout = c.Timeout
	} else {
		requestTimeout = timeout
	}
	// net.Dialer.Timeout has priority if smaller than the timeouts computed so
	// far
	if c.Dialer != nil && c.Dialer.Timeout != 0 {
		if c.Dialer.Timeout < requestTimeout {
			requestTimeout = c.Dialer.Timeout
		}
	}
	return requestTimeout
}

func (c *Client) dialTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.DialTimeout != 0 {
		return c.DialTimeout
	}
	return dnsTimeout
}

func (c *Client) readTimeout() time.Duration {
	if c.ReadTimeout != 0 {
		return c.ReadTimeout
	}
	return dnsTimeout
}

func (c *Client) writeTimeout() time.Duration {
	if c.WriteTimeout != 0 {
		return c.WriteTimeout
	}
	return dnsTimeout
}

// GenerateGSS generates the TSIG MAC based on the established context.
// It is intended to be called as an algorithm-specific callback.
// It is called with the bytes of the DNS message, the algorithm name, the
// TSIG name (which is the negotiated TKEY for this context) and the secret
// (which is ignored).
// It returns the bytes for the TSIG MAC and any error that occurred.
func (c *Client) generate(msg []byte, algorithm, name, secret string) ([]byte, error) {

	if strings.ToLower(algorithm) != tsig.GSS {
		return nil, dns.ErrKeyAlg
	}

	c.m.RLock()
	defer c.m.RUnlock()

	ctx, ok := c.ctx[name]
	if !ok {
		return nil, dns.ErrSecret
	}

	token := gssapi.MICToken{
		Flags:     gssapi.MICTokenFlagAcceptorSubkey,
		SndSeqNum: 0,
		Payload:   msg,
	}

	if err := token.SetChecksum(ctx.key, keyusage.GSSAPI_INITIATOR_SIGN); err != nil {
		return nil, err
	}

	b, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	return b, nil
}

// VerifyGSS verifies the TSIG MAC based on the established context.
// It is intended to be called as an algorithm-specific callback.
// It is called with the bytes of the DNS message, the TSIG record, the TSIG
// name (which is the negotiated TKEY for this context) and the secret (which
// is ignored).
// It returns any error that occurred.
func (c *Client) verify(stripped []byte, t *dns.TSIG, name, secret string) error {

	if strings.ToLower(t.Algorithm) != tsig.GSS {
		return dns.ErrKeyAlg
	}

	if c.SkipVerify {
		return nil
	}

	c.m.RLock()
	defer c.m.RUnlock()

	ctx, ok := c.ctx[name]
	if !ok {
		return dns.ErrSecret
	}

	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}

	var token gssapi.MICToken
	err = token.Unmarshal(mac, true)
	if err != nil {
		return err
	}
	token.Payload = stripped

	// This is the actual verification bit
	_, err = token.Verify(ctx.key, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil {
		return err
	}

	return nil
}

func generateConfig(realm, host string) string {
	return `
[libdefaults]
    default_realm = ` + realm + `
    kdc_timesync = 1
    ccache_type = 1
    forwardable = true
    proxiable = true
    fcc-mit-ticketflags = true

[realms]
    ` + realm + ` = {
        kdc = ` + host + `
        admin_server = ` + host + `
    }
`
}

func generateTKEYName(host string) string {
	seed := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(seed)
	return dns.Fqdn(fmt.Sprintf("%d.sig-%s", rng.Int31(), host))
}

func generateSPN(host string) string {
	if dns.IsFqdn(host) {
		return fmt.Sprintf("DNS/%s", host[:len(host)-1])
	}
	return fmt.Sprintf("DNS/%s", host)
}
