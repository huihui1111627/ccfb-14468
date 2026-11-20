package translate

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"ivat/pkg/headers"
)

var (
	src4 = netip.MustParseAddr("192.0.2.1")
	dst4 = netip.MustParseAddr("198.51.100.10")
	src6 = netip.MustParseAddr("2001:db8:ffff::1")
	dst6 = netip.MustParseAddr("64:ff9b::c633:640a")
)

func constMapper(want netip.Addr) AddrMapper {
	return func(netip.Addr) (netip.Addr, bool) { return want, true }
}

func udpPacket(t *testing.T, src, dst netip.Addr, sport, dport uint16, payload []byte, df bool) []byte {
	seg := headers.BuildUDP(&headers.UDPHeader{
		SrcPort: sport, DstPort: dport,
		Length: uint16(headers.UDPLen + len(payload)),
	}, payload)
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV4(src.As4(), dst.As4(), headers.ProtoUDP, len(seg)),
		seg, headers.UDPChecksumPos())
	binary.BigEndian.PutUint16(seg[headers.UDPChecksumPos():], csum)
	var flags uint16
	if df {
		flags = headers.V4FlagDF
	}
	return headers.BuildIPv4(&headers.IPv4Header{
		TOS: 0xb8, TotalLength: uint16(headers.V4MinHeaderLen + len(seg)),
		ID: 42, FlagsFrag: flags, TTL: 64, Protocol: headers.ProtoUDP,
		Src: src, Dst: dst,
	}, seg)
}

func TestUDPTranslationRoundTrip(t *testing.T) {
	for _, neutral := range []bool{false, true} {
		tr := New(Config{V6MTU: 1500, V4MTU: 1500, ChecksumNeutral: neutral})
		body := []byte("广电业务流-视频分片-0001")
		pkt := udpPacket(t, src4, dst4, 5000, 8000, body, true)

		v6pkt, err := tr.V4ToV6(pkt, constMapper(src6), constMapper(dst6))
		if err != nil {
			t.Fatalf("neutral=%v v4→v6: %v", neutral, err)
		}
		h6, err := headers.ParseIPv6(v6pkt)
		if err != nil {
			t.Fatal(err)
		}
		if h6.Src != src6 || h6.Dst != dst6 {
			t.Fatal("地址翻译错误")
		}
		if h6.TrafficClass != 0xb8 {
			t.Fatalf("TOS/TrafficClass 未逐位保留: %#x", h6.TrafficClass)
		}
		if h6.HopLimit != 64 {
			t.Fatalf("TTL/HopLimit 规则错误: %d", h6.HopLimit)
		}
		if h6.NextHeader != headers.ProtoUDP {
			t.Fatal("协议号映射错误")
		}
		// 负载逐字节一致
		got := v6pkt[headers.V6HeaderLen+headers.UDPLen:]
		if string(got) != string(body) {
			t.Fatal("负载被破坏")
		}

		// 反向翻译
		back, err := tr.V6ToV4(v6pkt, constMapper(src4), constMapper(dst4))
		if err != nil {
			t.Fatalf("v6→v4: %v", err)
		}
		h4, ihl, _ := headers.ParseIPv4(back)
		if h4.Src != src4 || h4.Dst != dst4 || h4.TOS != 0xb8 || h4.Protocol != headers.ProtoUDP {
			t.Fatal("反向翻译字段错误")
		}
		if !h4.DF() {
			t.Fatal("v6 原子报文翻译后 DF 应置位")
		}
		gotBody := back[ihl+headers.UDPLen:]
		if string(gotBody) != string(body) {
			t.Fatal("往返后负载不一致")
		}
		// 反向结果的 UDP 校验和必须自洽
		seg := back[ihl:]
		want := headers.TransportChecksum(
			headers.PseudoHeaderV4(src4.As4(), dst4.As4(), headers.ProtoUDP, len(seg)),
			seg, headers.UDPChecksumPos())
		if binary.BigEndian.Uint16(seg[headers.UDPChecksumPos():]) != want {
			t.Fatal("v4 UDP 校验和不自洽")
		}
	}
}

func TestChecksumNeutralKeepsValue(t *testing.T) {
	// 校验和中立布局下，翻译前后 TCP/UDP 校验和字段必须逐字节不变。
	tr := New(Config{V6MTU: 1500, V4MTU: 1500, ChecksumNeutral: true})
	body := []byte("neutral-checksum-test")
	pkt := udpPacket(t, src4, dst4, 5000, 8000, body, true)
	oldCsum := binary.BigEndian.Uint16(pkt[headers.V4MinHeaderLen+headers.UDPChecksumPos():])

	v6pkt, err := tr.V4ToV6(pkt, constMapper(src6), constMapper(dst6))
	if err != nil {
		t.Fatal(err)
	}
	newCsum := binary.BigEndian.Uint16(v6pkt[headers.V6HeaderLen+headers.UDPChecksumPos():])
	if oldCsum != newCsum {
		t.Fatalf("校验和中立布局下校验和被改动: %#x → %#x", oldCsum, newCsum)
	}
}

func TestV4UDPChecksumZeroMustBeComputed(t *testing.T) {
	// v4 UDP 允许校验和 0，v6 不允许，翻译后必须补算。
	tr := New(Config{V6MTU: 1500, V4MTU: 1500})
	seg := headers.BuildUDP(&headers.UDPHeader{
		SrcPort: 5000, DstPort: 8000, Length: 12,
	}, []byte("abcd"))
	binary.BigEndian.PutUint16(seg[headers.UDPChecksumPos():], 0)
	pkt := headers.BuildIPv4(&headers.IPv4Header{
		TotalLength: uint16(headers.V4MinHeaderLen + len(seg)),
		TTL:         64, Protocol: headers.ProtoUDP, Src: src4, Dst: dst4, FlagsFrag: headers.V4FlagDF,
	}, seg)
	v6pkt, err := tr.V4ToV6(pkt, constMapper(src6), constMapper(dst6))
	if err != nil {
		t.Fatal(err)
	}
	csum := binary.BigEndian.Uint16(v6pkt[headers.V6HeaderLen+headers.UDPChecksumPos():])
	if csum == 0 {
		t.Fatal("v6 UDP 校验和为 0，未按规则补算")
	}
}

func TestPTBOnOversizeDF(t *testing.T) {
	tr := New(Config{V6MTU: 1280, V4MTU: 1500})
	big := make([]byte, 1400-headers.V4MinHeaderLen)
	pkt := udpPacket(t, src4, dst4, 5000, 8000, big, true)
	_, err := tr.V4ToV6(pkt, constMapper(src6), constMapper(dst6))
	e, ok := err.(*ErrICMP)
	if !ok {
		t.Fatalf("期望 ErrICMP，实际 %v", err)
	}
	if e.V6Type != headers.ICMP6PktTooBig || e.MTU != 1280 {
		t.Fatalf("PTB 内容错误: %+v", e)
	}

	// 反方向：v6 报文超过 v4 MTU → Frag Needed
	tr2 := New(Config{V6MTU: 1500, V4MTU: 1280})
	v6big := headers.BuildIPv6(&headers.IPv6Header{
		Length: 1400, NextHeader: headers.ProtoUDP, HopLimit: 64, Src: src6, Dst: dst6,
	}, make([]byte, 1400))
	_, err = tr2.V6ToV4(v6big, constMapper(src4), constMapper(dst4))
	e2, ok := err.(*ErrICMP)
	if !ok || e2.V4Type != headers.ICMP4DstUnreach || e2.Code != headers.ICMP4FragNeededDF {
		t.Fatalf("期望 Frag Needed，实际 %v", err)
	}
}

func TestNestedICMPTranslation(t *testing.T) {
	tr := New(Config{V6MTU: 1500, V4MTU: 1500})
	// 构造一个触发差错的原始 UDP 报文，再套进 ICMPv4 Frag Needed。
	orig := udpPacket(t, dst4, src4, 8000, 5000, []byte("inner-payload"), true)
	var rest [4]byte
	headers.SetMTU(&rest, 1400, false)
	icmpSeg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4DstUnreach, Code: headers.ICMP4FragNeededDF,
		Rest: rest, Body: orig,
	})
	binary.BigEndian.PutUint16(icmpSeg[headers.ICMPChecksumPos():], headers.Checksum(icmpSeg))
	outer := headers.BuildIPv4(&headers.IPv4Header{
		TotalLength: uint16(headers.V4MinHeaderLen + len(icmpSeg)),
		TTL:         64, Protocol: headers.ProtoICMPv4, Src: dst4, Dst: src4,
	}, icmpSeg)

	v6pkt, err := tr.V4ToV6(outer, constMapper(dst6), constMapper(src6))
	if err != nil {
		t.Fatalf("外层翻译失败: %v", err)
	}
	h6, _ := headers.ParseIPv6(v6pkt)
	if h6.NextHeader != headers.ProtoICMPv6 {
		t.Fatal("外层协议号应为 ICMPv6")
	}
	msg, _ := headers.ParseICMP(v6pkt[headers.V6HeaderLen:])
	if msg.Type != headers.ICMP6PktTooBig {
		t.Fatalf("类型映射错误: %d", msg.Type)
	}
	mtu := headers.MTU(msg.Rest)
	if mtu != 1380 { // 1400 - 20
		t.Fatalf("MTU 头长差调整错误: %d", mtu)
	}
	// 内层必须已被翻译成 v6 报文
	inner, err := headers.ParseIPv6(msg.Body)
	if err != nil {
		t.Fatalf("内层未翻译为 IPv6: %v", err)
	}
	if inner.NextHeader != headers.ProtoUDP {
		t.Fatal("内层协议号未翻译")
	}
}

func TestICMPRedirectDropped(t *testing.T) {
	tr := New(Config{V6MTU: 1500, V4MTU: 1500})
	icmpSeg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4Redirect, Code: 0,
		Body: make([]byte, 28),
	})
	binary.BigEndian.PutUint16(icmpSeg[headers.ICMPChecksumPos():], headers.Checksum(icmpSeg))
	outer := headers.BuildIPv4(&headers.IPv4Header{
		TotalLength: uint16(headers.V4MinHeaderLen + len(icmpSeg)),
		TTL:         64, Protocol: headers.ProtoICMPv4, Src: dst4, Dst: src4,
	}, icmpSeg)
	_, err := tr.V4ToV6(outer, constMapper(dst6), constMapper(src6))
	if e, ok := err.(*ErrDrop); !ok {
		t.Fatalf("Redirect 应被丢弃，实际 %v", err)
	} else {
		t.Logf("丢弃原因: %s", e.Reason)
	}
}

func TestICMPv6ParamProblemReverseDrop(t *testing.T) {
	tr := New(Config{V6MTU: 1500, V4MTU: 1500})
	// 代码 0 的参数问题在 v4 无稳定对应物，应丢弃
	seg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP6ParamProblem, Code: 0, Body: make([]byte, 40),
	})
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV6(src6.As16(), dst6.As16(), headers.ProtoICMPv6, len(seg)),
		seg, headers.ICMPChecksumPos())
	binary.BigEndian.PutUint16(seg[headers.ICMPChecksumPos():], csum)
	pkt := headers.BuildIPv6(&headers.IPv6Header{
		Length: uint16(len(seg)), NextHeader: headers.ProtoICMPv6,
		HopLimit: 64, Src: src6, Dst: dst6,
	}, seg)
	if _, err := tr.V6ToV4(pkt, constMapper(src4), constMapper(dst4)); err == nil {
		t.Fatal("无对应物的 ICMPv6 类型未被丢弃")
	}
}
