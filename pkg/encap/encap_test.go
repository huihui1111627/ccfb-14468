package encap

import (
	"net/netip"
	"testing"

	"ivat/pkg/headers"
)

func TestEncapDecapRoundTrip(t *testing.T) {
	inner := headers.BuildIPv4(&headers.IPv4Header{
		TotalLength: 40, TTL: 64, Protocol: headers.ProtoUDP,
		Src: netip.MustParseAddr("192.0.2.1"),
		Dst: netip.MustParseAddr("198.51.100.10"),
	}, make([]byte, 20))

	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")
	pkt, err := Encap(inner, src, dst, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncap(pkt) {
		t.Fatal("封装报文未被识别")
	}
	h, err := headers.ParseIPv6(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if h.NextHeader != 41 || h.Src != src || h.Dst != dst {
		t.Fatal("外层 v6 头字段错误")
	}
	got, outer, err := Decap(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if outer.NextHeader != 41 || len(got) != len(inner) {
		t.Fatal("解封装结果不匹配")
	}
}

func TestDecapRejectsNonEncap(t *testing.T) {
	pkt := headers.BuildIPv6(&headers.IPv6Header{
		Length: 8, NextHeader: headers.ProtoUDP, HopLimit: 64,
		Src: netip.MustParseAddr("::1"), Dst: netip.MustParseAddr("::2"),
	}, make([]byte, 8))
	if _, _, err := Decap(pkt); err == nil {
		t.Fatal("非封装报文应被拒绝")
	}
}
