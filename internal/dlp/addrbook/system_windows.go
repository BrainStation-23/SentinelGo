package addrbook

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DNS record types and DnsQuery results.
const (
	dnsTypeA          = 1
	dnsTypeAAAA       = 28
	dnsFreeRecordList = 1
	dnsErrorNameError = 9003 // DNS_ERROR_RCODE_NAME_ERROR
	dnsInfoNoRecords  = 9501 // DNS_INFO_NO_RECORDS
)

// System resolves host's A and AAAA records through the Windows DNS client
// (and its cache), with the smallest TTL among them.
func System(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	type result struct {
		addrs []netip.Addr
		ttl   time.Duration
		err   error
	}
	ch := make(chan result, 1)
	go func() { // DnsQuery can't be cancelled; the caller doesn't wait past ctx
		var r result
		r.ttl = maxDNSTTL
		var errs []error
		for _, qt := range []uint16{dnsTypeA, dnsTypeAAAA} {
			addrs, ttl, err := dnsQuery(host, qt)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			r.addrs = append(r.addrs, addrs...)
			if len(addrs) > 0 {
				r.ttl = min(r.ttl, ttl)
			}
		}
		if len(r.addrs) == 0 && len(errs) > 0 {
			r.err = errors.Join(errs...)
		}
		ch <- r
	}()
	select {
	case r := <-ch:
		return r.addrs, r.ttl, r.err
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

func dnsQuery(host string, qtype uint16) ([]netip.Addr, time.Duration, error) {
	var rec *windows.DNSRecord
	err := windows.DnsQuery(host, qtype, 0, nil, &rec, nil)
	if errors.Is(err, windows.Errno(dnsErrorNameError)) || errors.Is(err, windows.Errno(dnsInfoNoRecords)) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("DnsQuery %s type %d: %w", host, qtype, err)
	}
	defer windows.DnsRecordListFree(rec, dnsFreeRecordList)
	var addrs []netip.Addr
	ttl := maxDNSTTL
	for r := rec; r != nil; r = r.Next {
		if r.Type != qtype { // CNAMEs on the way
			continue
		}
		switch qtype {
		case dnsTypeA:
			addrs = append(addrs, netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&r.Data[0]))))
		case dnsTypeAAAA:
			addrs = append(addrs, netip.AddrFrom16(*(*[16]byte)(unsafe.Pointer(&r.Data[0]))))
		}
		ttl = min(ttl, time.Duration(r.Ttl)*time.Second)
	}
	return addrs, ttl, nil
}
