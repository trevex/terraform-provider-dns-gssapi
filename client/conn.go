// Heavily based on Matt Dainty work, who based it on the extension of
// Miek Gieben to the official Go code, see LICENSE.

package client

import (
	"github.com/miekg/dns"
)

type Conn struct {
	dns.Conn

	// Additional fields required for TSIG validation using GSSAPI
	generate TsigGenerateFn
	verify   TsigVerifyFn
	mac      string
}

func (co *Conn) SetupTSIG(keyname string, generate TsigGenerateFn, verify TsigVerifyFn) {
	co.TsigSecret = map[string]string{
		keyname: "",
	}
	co.generate = generate
	co.verify = verify
}

// ReadMsg reads a message from the connection co.
// If the received message contains a TSIG record the transaction signature
// is verified. This method always tries to return the message, however if an
// error is returned there are no guarantees that the returned message is a
// valid representation of the packet read.
func (co *Conn) ReadMsg() (*dns.Msg, error) {
	p, err := co.ReadMsgHeader(nil)
	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	if err := m.Unpack(p); err != nil {
		// If an error was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use an erroneous message
		return m, err
	}
	if t := m.IsTsig(); t != nil {
		if t.Algorithm == TSIGGSS {
			if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
				return m, dns.ErrSecret
			}
			err = TsigVerifyByAlgorithm(p, co.verify, t.Hdr.Name, co.TsigSecret[t.Hdr.Name], co.mac, false)
		} else {
			if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
				return m, dns.ErrSecret
			}
			// Need to work on the original message p, as that was used to calculate the tsig.
			err = TsigVerify(p, co.TsigSecret[t.Hdr.Name], co.mac, false)
		}
	}
	return m, err
}

// WriteMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *dns.Msg) (err error) {
	var out []byte
	if t := m.IsTsig(); t != nil {
		mac := ""
		if t.Algorithm == TSIGGSS {
			if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
				return dns.ErrSecret
			}
			out, mac, err = TsigGenerateByAlgorithm(m, co.generate, t.Hdr.Name, co.TsigSecret[t.Hdr.Name], co.mac, false)
		} else {
			if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
				return dns.ErrSecret
			}
			out, mac, err = TsigGenerate(m, co.TsigSecret[t.Hdr.Name], co.mac, false)
		}
		// Set for the next read, although only used in zone transfers
		co.mac = mac
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	if _, err = co.Write(out); err != nil {
		return err
	}
	return nil
}
