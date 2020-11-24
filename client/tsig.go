// Heavily based on Matt Dainty work, who based it on the extension of
// Miek Gieben to the official Go code, see LICENSE.

package client

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type TsigGenerateFn func(msg []byte, algorithm, name, secret string) ([]byte, error)
type TsigVerifyFn func(msg []byte, tsig *dns.TSIG, name, secret string) error

// TSIG is the RR the holds the transaction signature of a message.
// See RFC 2845 and RFC 4635.
type TSIG struct {
	dns.TSIG
}

// The following values must be put in wireformat, so that the MAC can be calculated.
// RFC 2845, section 3.4.2. TSIG Variables.
type tsigWireFmt struct {
	// From RR_Header
	Name  string `dns:"domain-name"`
	Class uint16
	Ttl   uint32
	// Rdata of the TSIG
	Algorithm  string `dns:"domain-name"`
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
	// MACSize, MAC and OrigId excluded
	Error     uint16
	OtherLen  uint16
	OtherData string `dns:"size-hex:OtherLen"`
}

// If we have the MAC use this type to convert it to wiredata. Section 3.4.3. Request MAC
type macWireFmt struct {
	MACSize uint16
	MAC     string `dns:"size-hex:MACSize"`
}

// 3.3. Time values used in TSIG calculations
type timerWireFmt struct {
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
}

func tsigGenerateHmac(msg []byte, algorithm, name, secret string) ([]byte, error) {
	rawsecret, err := fromBase64([]byte(secret))
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	switch strings.ToLower(algorithm) {
	case dns.HmacMD5:
		h = hmac.New(md5.New, []byte(rawsecret))
	case dns.HmacSHA1:
		h = hmac.New(sha1.New, []byte(rawsecret))
	case dns.HmacSHA256:
		h = hmac.New(sha256.New, []byte(rawsecret))
	case dns.HmacSHA512:
		h = hmac.New(sha512.New, []byte(rawsecret))
	default:
		return nil, dns.ErrKeyAlg
	}
	h.Write(msg)

	return h.Sum(nil), nil
}

// TsigGenerate fills out the TSIG record attached to the message.
// The message should contain
// a "stub" TSIG RR with the algorithm, key name (owner name of the RR),
// time fudge (defaults to 300 seconds) and the current time
// The TSIG MAC is saved in that Tsig RR.
// When TsigGenerate is called for the first time requestMAC is set to the empty string and
// timersOnly is false.
// If something goes wrong an error is returned, otherwise it is nil.
func TsigGenerate(m *dns.Msg, secret, requestMAC string, timersOnly bool) ([]byte, string, error) {
	return TsigGenerateByAlgorithm(m, tsigGenerateHmac, "", secret, requestMAC, timersOnly)
}

// TsigGenerateByAlgorithm fills out the TSIG record attached to the message
// using a callback to implement the algorithm-specific generation.
// The message should contain
// a "stub" TSIG RR with the algorithm, key name (owner name of the RR),
// time fudge (defaults to 300 seconds) and the current time
// The TSIG MAC is saved in that Tsig RR.
// When TsigGenerate is called for the first time requestMAC is set to the empty string and
// timersOnly is false.
// If something goes wrong an error is returned, otherwise it is nil.
func TsigGenerateByAlgorithm(m *dns.Msg, cb TsigGenerateFn, name, secret, requestMAC string, timersOnly bool) ([]byte, string, error) {
	if m.IsTsig() == nil {
		panic("dns: TSIG not last RR in additional")
	}

	rr := m.Extra[len(m.Extra)-1].(*dns.TSIG)
	m.Extra = m.Extra[0 : len(m.Extra)-1] // kill the TSIG from the msg
	mbuf, err := m.Pack()
	if err != nil {
		return nil, "", err
	}
	buf := tsigBuffer(mbuf, rr, requestMAC, timersOnly)

	t := new(TSIG)

	h, err := cb(buf, rr.Algorithm, name, secret)
	if err != nil {
		return nil, "", err
	}

	t.MAC = hex.EncodeToString(h)
	t.MACSize = uint16(len(t.MAC) / 2) // Size is half!

	t.Hdr = dns.RR_Header{Name: rr.Hdr.Name, Rrtype: dns.TypeTSIG, Class: dns.ClassANY, Ttl: 0}
	t.Fudge = rr.Fudge
	t.TimeSigned = rr.TimeSigned
	t.Algorithm = rr.Algorithm
	t.OrigId = m.Id

	tbuf := make([]byte, dns.Len(t))
	if off, err := dns.PackRR(t, tbuf, 0, nil, false); err == nil {
		tbuf = tbuf[:off] // reset to actual size used
	} else {
		return nil, "", err
	}
	mbuf = append(mbuf, tbuf...)
	// Update the ArCount directly in the buffer.
	binary.BigEndian.PutUint16(mbuf[10:], uint16(len(m.Extra)+1))

	return mbuf, t.MAC, nil
}

func tsigVerifyHmac(msg []byte, tsig *dns.TSIG, name, secret string) error {
	rawsecret, err := fromBase64([]byte(secret))
	if err != nil {
		return err
	}

	msgMAC, err := hex.DecodeString(tsig.MAC)
	if err != nil {
		return err
	}

	var h hash.Hash
	switch strings.ToLower(tsig.Algorithm) {
	case dns.HmacMD5:
		h = hmac.New(md5.New, rawsecret)
	case dns.HmacSHA1:
		h = hmac.New(sha1.New, rawsecret)
	case dns.HmacSHA256:
		h = hmac.New(sha256.New, rawsecret)
	case dns.HmacSHA512:
		h = hmac.New(sha512.New, rawsecret)
	default:
		return dns.ErrKeyAlg
	}
	h.Write(msg)
	if !hmac.Equal(h.Sum(nil), msgMAC) {
		return dns.ErrSig
	}
	return nil
}

// TsigVerify verifies the TSIG on a message.
// If the signature does not validate err contains the
// error, otherwise it is nil.
func TsigVerify(msg []byte, secret, requestMAC string, timersOnly bool) error {
	return TsigVerifyByAlgorithm(msg, tsigVerifyHmac, "", secret, requestMAC, timersOnly)
}

// TsigVerifyByAlgorithm verifies the TSIG on a message using a callback to
// implement the algorithm-specific verification.
// If the signature does not validate err contains the
// error, otherwise it is nil.
func TsigVerifyByAlgorithm(msg []byte, cb TsigVerifyFn, name, secret, requestMAC string, timersOnly bool) error {
	// Strip the TSIG from the incoming msg
	stripped, tsig, err := stripTsig(msg)
	if err != nil {
		return err
	}

	buf := tsigBuffer(stripped, tsig, requestMAC, timersOnly)

	// Fudge factor works both ways. A message can arrive before it was signed because
	// of clock skew.
	now := uint64(time.Now().Unix())
	ti := now - tsig.TimeSigned
	if now < tsig.TimeSigned {
		ti = tsig.TimeSigned - now
	}
	if uint64(tsig.Fudge) < ti {
		return dns.ErrTime
	}

	return cb(buf, tsig, name, secret)
}

// Create a wiredata buffer for the MAC calculation.
func tsigBuffer(msgbuf []byte, rr *dns.TSIG, requestMAC string, timersOnly bool) []byte {
	var buf []byte
	if rr.TimeSigned == 0 {
		rr.TimeSigned = uint64(time.Now().Unix())
	}
	if rr.Fudge == 0 {
		rr.Fudge = 300 // Standard (RFC) default.
	}

	// Replace message ID in header with original ID from TSIG
	binary.BigEndian.PutUint16(msgbuf[0:2], rr.OrigId)

	if requestMAC != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(requestMAC) / 2)
		m.MAC = requestMAC
		buf = make([]byte, len(requestMAC)) // long enough
		n, _ := packMacWire(m, buf)
		buf = buf[:n]
	}

	tsigvar := make([]byte, dns.DefaultMsgSize)
	if timersOnly {
		tsig := new(timerWireFmt)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		n, _ := packTimerWire(tsig, tsigvar)
		tsigvar = tsigvar[:n]
	} else {
		tsig := new(tsigWireFmt)
		tsig.Name = strings.ToLower(rr.Hdr.Name)
		tsig.Class = dns.ClassANY
		tsig.Ttl = rr.Hdr.Ttl
		tsig.Algorithm = strings.ToLower(rr.Algorithm)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		tsig.Error = rr.Error
		tsig.OtherLen = rr.OtherLen
		tsig.OtherData = rr.OtherData
		n, _ := packTsigWire(tsig, tsigvar)
		tsigvar = tsigvar[:n]
	}

	if requestMAC != "" {
		x := append(buf, msgbuf...)
		buf = append(x, tsigvar...)
	} else {
		buf = append(msgbuf, tsigvar...)
	}
	return buf
}

// Strip the TSIG from the raw message.
func stripTsig(msg []byte) ([]byte, *dns.TSIG, error) {
	// Copied from msg.go's Unpack() Header, but modified.
	var (
		dh  dns.Header
		err error
	)
	off, tsigoff := 0, 0

	if dh, off, err = unpackMsgHdr(msg, off); err != nil {
		return nil, nil, err
	}
	if dh.Arcount == 0 {
		return nil, nil, dns.ErrNoSig
	}

	// Rcode, see msg.go Unpack()
	if int(dh.Bits&0xF) == dns.RcodeNotAuth {
		return nil, nil, dns.ErrAuth
	}

	for i := 0; i < int(dh.Qdcount); i++ {
		_, off, err = unpackQuestion(msg, off)
		if err != nil {
			return nil, nil, err
		}
	}

	_, off, err = unpackRRslice(int(dh.Ancount), msg, off)
	if err != nil {
		return nil, nil, err
	}
	_, off, err = unpackRRslice(int(dh.Nscount), msg, off)
	if err != nil {
		return nil, nil, err
	}

	rr := new(dns.TSIG)
	var extra dns.RR
	for i := 0; i < int(dh.Arcount); i++ {
		tsigoff = off
		extra, off, err = dns.UnpackRR(msg, off)
		if err != nil {
			return nil, nil, err
		}
		if extra.Header().Rrtype == dns.TypeTSIG {
			rr = extra.(*dns.TSIG)
			// Adjust Arcount.
			arcount := binary.BigEndian.Uint16(msg[10:])
			binary.BigEndian.PutUint16(msg[10:], arcount-1)
			break
		}
	}
	if rr == nil {
		return nil, nil, dns.ErrNoSig
	}
	return msg[:tsigoff], rr, nil
}

func packTsigWire(tw *tsigWireFmt, msg []byte) (int, error) {
	// copied from zmsg.go TSIG packing
	// RR_Header
	off, err := dns.PackDomainName(tw.Name, msg, 0, nil, false)
	if err != nil {
		return off, err
	}
	off, err = packUint16(tw.Class, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(tw.Ttl, msg, off)
	if err != nil {
		return off, err
	}

	off, err = dns.PackDomainName(tw.Algorithm, msg, off, nil, false)
	if err != nil {
		return off, err
	}
	off, err = packUint48(tw.TimeSigned, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(tw.Fudge, msg, off)
	if err != nil {
		return off, err
	}

	off, err = packUint16(tw.Error, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(tw.OtherLen, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packStringHex(tw.OtherData, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func packMacWire(mw *macWireFmt, msg []byte) (int, error) {
	off, err := packUint16(mw.MACSize, msg, 0)
	if err != nil {
		return off, err
	}
	off, err = packStringHex(mw.MAC, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func packTimerWire(tw *timerWireFmt, msg []byte) (int, error) {
	off, err := packUint48(tw.TimeSigned, msg, 0)
	if err != nil {
		return off, err
	}
	off, err = packUint16(tw.Fudge, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if off+2 > len(msg) {
		return 0, len(msg), fmt.Errorf("overflow unpacking uint16")
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

func packUint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing uint16")
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func packUint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing uint32")
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func packUint48(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+6 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing uint64 as uint48")
	}
	msg[off] = byte(i >> 40)
	msg[off+1] = byte(i >> 32)
	msg[off+2] = byte(i >> 24)
	msg[off+3] = byte(i >> 16)
	msg[off+4] = byte(i >> 8)
	msg[off+5] = byte(i)
	off += 6
	return off, nil
}

func packStringHex(s string, msg []byte, off int) (int, error) {
	h, err := hex.DecodeString(s)
	if err != nil {
		return len(msg), err
	}
	if off+(len(h)) > len(msg) {
		return len(msg), fmt.Errorf("overflow packing hex")
	}
	copy(msg[off:off+len(h)], h)
	off += len(h)
	return off, nil
}

// unpackRRslice unpacks msg[off:] into an []RR.
// If we cannot unpack the whole array, then it will return nil
func unpackRRslice(l int, msg []byte, off int) (dst1 []dns.RR, off1 int, err error) {
	var r dns.RR
	// Don't pre-allocate, l may be under attacker control
	var dst []dns.RR
	for i := 0; i < l; i++ {
		off1 := off
		r, off, err = dns.UnpackRR(msg, off)
		if err != nil {
			off = len(msg)
			break
		}
		// If offset does not increase anymore, l is a lie
		if off1 == off {
			l = i
			break
		}
		dst = append(dst, r)
	}
	if err != nil && off == len(msg) {
		dst = nil
	}
	return dst, off, err
}

func unpackQuestion(msg []byte, off int) (dns.Question, int, error) {
	var (
		q   dns.Question
		err error
	)
	q.Name, off, err = dns.UnpackDomainName(msg, off)
	if err != nil {
		return q, off, err
	}
	if off == len(msg) {
		return q, off, nil
	}
	q.Qtype, off, err = unpackUint16(msg, off)
	if err != nil {
		return q, off, err
	}
	if off == len(msg) {
		return q, off, nil
	}
	q.Qclass, off, err = unpackUint16(msg, off)
	if off == len(msg) {
		return q, off, nil
	}
	return q, off, err
}

func unpackMsgHdr(msg []byte, off int) (dns.Header, int, error) {
	var (
		dh  dns.Header
		err error
	)
	dh.Id, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Bits, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Qdcount, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Ancount, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Nscount, off, err = unpackUint16(msg, off)
	if err != nil {
		return dh, off, err
	}
	dh.Arcount, off, err = unpackUint16(msg, off)
	return dh, off, err
}
