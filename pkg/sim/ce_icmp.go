package sim

import (
	"encoding/binary"
	"net/netip"

	"ivat/pkg/headers"
	"ivat/pkg/napt"
)

// fixInnerICMPInbound 处理入向 ICMPv4 差错报文（对端 → 本户）。
//
// 体内引用的是本户此前发出的报文：内层目的是对端、内层源是本户共享 v4，
// 其源端口（或内层 Echo ID）就是本户 NAPT 的外部端口。据此直查表，
// 把它还原成户内主机的内部端口与私网地址，终端协议栈才能把差错
// 匹配回自己的 socket。
func (c *CE) fixInnerICMPInbound(seg []byte) ([]byte, netip.Addr, bool) {
	msg, err := headers.ParseICMP(seg)
	if err != nil {
		return nil, netip.Addr{}, false
	}
	inner, ihl, err := headers.ParseIPv4(msg.Body)
	if err != nil || len(msg.Body) < ihl+4 {
		return nil, netip.Addr{}, false
	}
	var (
		m     *napt.Mapping
		found bool
	)
	switch inner.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		extSPort := binary.BigEndian.Uint16(msg.Body[ihl : ihl+2])
		m, found = c.napt.LookupByExternal(inner.Protocol, extSPort)
	case headers.ProtoICMPv4:
		if len(msg.Body) < ihl+8 {
			return nil, netip.Addr{}, false
		}
		extID := binary.BigEndian.Uint16(msg.Body[ihl+4 : ihl+6])
		m, found = c.napt.LookupByExternal(napt.ProtoICMP, extID)
	default:
		return nil, netip.Addr{}, false
	}
	if !found {
		return nil, netip.Addr{}, false
	}

	body := append([]byte(nil), msg.Body...)
	switch inner.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		// 内层源端口：外部端口 → 内部端口
		binary.BigEndian.PutUint16(body[ihl:ihl+2], m.InternalPt)
	case headers.ProtoICMPv4:
		binary.BigEndian.PutUint16(body[ihl+4:ihl+6], m.InternalPt)
	}
	// 内层源地址：共享 v4 → 户内主机私网地址
	dst := netip.AddrFrom4(m.InternalIP)
	dstB := dst.As4()
	copy(body[12:16], dstB[:])
	binary.BigEndian.PutUint16(body[10:12], 0)
	binary.BigEndian.PutUint16(body[10:12], headers.Checksum(body[:ihl]))
	// 内层传输层校验和随地址、端口变化重算（伪头部源=私网主机，目的=对端）
	if inner.Protocol == headers.ProtoTCP || inner.Protocol == headers.ProtoUDP {
		pos := headers.UDPChecksumPos()
		if inner.Protocol == headers.ProtoTCP {
			pos = headers.TCPChecksumPos()
		}
		l4 := body[ihl:]
		pseudo := headers.PseudoHeaderV4(dstB, inner.Dst.As4(), inner.Protocol, len(l4))
		csum := headers.TransportChecksum(pseudo, l4, pos)
		binary.BigEndian.PutUint16(l4[pos:], csum)
	}
	msg.Body = body
	out := headers.BuildICMP(msg)
	binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], 0)
	binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], headers.Checksum(out))
	return out, dst, true
}

// fixInnerICMPOutbound 处理外出 ICMPv4 差错（户内主机产生 → 对端）。
// 体内引用的是户内主机此前发出的报文：把内部源端口/私网源地址
// 换成 NAPT 外部端口/共享 v4。
func (c *CE) fixInnerICMPOutbound(seg []byte) ([]byte, bool) {
	msg, err := headers.ParseICMP(seg)
	if err != nil {
		return nil, false
	}
	inner, ihl, err := headers.ParseIPv4(msg.Body)
	if err != nil || len(msg.Body) < ihl+4 {
		return nil, false
	}
	var (
		m     *napt.Mapping
		found bool
	)
	switch inner.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		intSPort := binary.BigEndian.Uint16(msg.Body[ihl : ihl+2])
		m, found = c.napt.LookupOutbound(inner.Protocol, inner.Src.As4(), intSPort,
			inner.Dst.As4(), binary.BigEndian.Uint16(msg.Body[ihl+2:ihl+4]))
	case headers.ProtoICMPv4:
		if len(msg.Body) < ihl+8 {
			return nil, false
		}
		intID := binary.BigEndian.Uint16(msg.Body[ihl+4 : ihl+6])
		m, found = c.napt.LookupOutbound(napt.ProtoICMP, inner.Src.As4(), intID,
			inner.Dst.As4(), 0)
	default:
		return nil, false
	}
	if !found {
		return nil, false
	}
	body := append([]byte(nil), msg.Body...)
	switch inner.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		binary.BigEndian.PutUint16(body[ihl:ihl+2], m.ExternalPt)
	case headers.ProtoICMPv4:
		binary.BigEndian.PutUint16(body[ihl+4:ihl+6], m.ExternalPt)
	}
	srcB := c.SharedV4.As4()
	copy(body[12:16], srcB[:])
	binary.BigEndian.PutUint16(body[10:12], 0)
	binary.BigEndian.PutUint16(body[10:12], headers.Checksum(body[:ihl]))
	if inner.Protocol == headers.ProtoTCP || inner.Protocol == headers.ProtoUDP {
		pos := headers.UDPChecksumPos()
		if inner.Protocol == headers.ProtoTCP {
			pos = headers.TCPChecksumPos()
		}
		l4 := body[ihl:]
		pseudo := headers.PseudoHeaderV4(srcB, inner.Dst.As4(), inner.Protocol, len(l4))
		csum := headers.TransportChecksum(pseudo, l4, pos)
		binary.BigEndian.PutUint16(l4[pos:], csum)
	}
	msg.Body = body
	out := headers.BuildICMP(msg)
	binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], 0)
	binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], headers.Checksum(out))
	return out, true
}

// handleTranslatedICMPV6 处理翻译模式下到达 WAN 的 ICMPv6 差错：
// 翻译器把它翻成 v4 差错后，体内端口仍需 NAPT 还原。
func (c *CE) handleTranslatedICMPV6(v6pkt []byte) {
	mapSrc := func(a netip.Addr) (netip.Addr, bool) {
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		if v4, _, ok := c.Rule.DecodeIPv6(a); ok {
			return v4, true
		}
		return syntheticRouterV4(a), true
	}
	mapDst := func(netip.Addr) (netip.Addr, bool) { return c.SharedV4, true }
	// 内层是本户外出报文：源（本户 v6）→ 共享 v4，目的（对端 DMR）→ 公网 v4。
	innerMapSrc := func(a netip.Addr) (netip.Addr, bool) {
		if _, _, ok := c.Rule.DecodeIPv6(a); ok {
			return c.SharedV4, true
		}
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		return netip.Addr{}, false
	}
	innerMapDst := func(a netip.Addr) (netip.Addr, bool) {
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		return netip.Addr{}, false
	}
	v4pkt, err := c.Translator.V6ToV4WithInner(v6pkt, mapSrc, mapDst, innerMapSrc, innerMapDst)
	if err != nil {
		c.drop()
		return
	}
	c.handleInboundV4(v4pkt)
}

// tunnelICMPToV4 封装模式下，骨干产生的 ICMPv6 差错（PTB/超时）
// 需要合成等价 v4 差错回户内：按封装内层报文找到户内主机与外部端口，
// 再还原内部端口。
func (c *CE) tunnelICMPToV4(v6pkt []byte) ([]byte, bool) {
	h, err := headers.ParseIPv6(v6pkt)
	if err != nil || h.NextHeader != headers.ProtoICMPv6 {
		return nil, false
	}
	msg, err := headers.ParseICMP(v6pkt[headers.V6HeaderLen:])
	if err != nil {
		return nil, false
	}
	// 体内引用的是封装报文（外层 v6 + 内层 v4）。
	innerV6, err := headers.ParseIPv6(msg.Body)
	if err != nil || innerV6.NextHeader != 41 {
		return nil, false
	}
	innerV4 := msg.Body[headers.V6HeaderLen:]
	if _, _, err := headers.ParseIPv4(innerV4); err != nil {
		return nil, false
	}

	var v4Type, v4Code uint8
	switch msg.Type {
	case headers.ICMP6PktTooBig:
		v4Type, v4Code = headers.ICMP4DstUnreach, headers.ICMP4FragNeededDF
	case headers.ICMP6TimeExceed:
		v4Type, v4Code = headers.ICMP4TimeExceed, 0
	case headers.ICMP6DstUnreach:
		v4Type, v4Code = headers.ICMP4DstUnreach, headers.ICMP4HostUnreach
	default:
		return nil, false
	}

	outMsg := &headers.ICMPMessage{Type: v4Type, Code: v4Code,
		Body: truncate(innerV4, 548)}
	if v4Type == headers.ICMP4DstUnreach && v4Code == headers.ICMP4FragNeededDF {
		// 隧道 MTU 折算回 v4 口径：外层 v6 头 40 字节。
		mtu := headers.MTU(msg.Rest)
		if mtu > headers.V6HeaderLen {
			mtu -= headers.V6HeaderLen
		}
		headers.SetMTU(&outMsg.Rest, mtu, false)
	}
	seg := headers.BuildICMP(outMsg)
	binary.BigEndian.PutUint16(seg[headers.ICMPChecksumPos():], 0)
	binary.BigEndian.PutUint16(seg[headers.ICMPChecksumPos():], headers.Checksum(seg))

	// 合成目的为本户共享 v4 的 v4 报文，再走标准 NAPT 入向修正。
	pkt := headers.BuildIPv4(&headers.IPv4Header{
		TotalLength: uint16(headers.V4MinHeaderLen + len(seg)),
		TTL:         64, Protocol: headers.ProtoICMPv4,
		Src: c.SharedV4, Dst: c.SharedV4,
	}, seg)
	return pkt, true
}

// sendLocalFragNeeded 翻译/封装前发现 PMTU 超限，直接给户内主机回差错。
// origPkt 是触发问题的完整 v4 报文，按 RFC 792 截断后放入 ICMP 体内，
// 主机协议栈据此把差错匹配回自己的 socket 并更新 PMTU 缓存。
func (c *CE) sendLocalFragNeeded(origPkt []byte, v6MTU uint32) {
	h, _, err := headers.ParseIPv4(origPkt)
	if err != nil {
		return
	}
	// 主机侧看到的是 v4 MTU：v6 口径 + v6 头(40) - v4 头(20)。
	v4MTU := v6MTU + headers.V6HeaderLen - headers.V4MinHeaderLen
	var rest [4]byte
	headers.SetMTU(&rest, v4MTU, false)
	quoted := truncate(origPkt, headers.V4MinHeaderLen+8)
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4DstUnreach, Code: headers.ICMP4FragNeededDF,
		Rest: rest, Body: quoted,
	})
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], 0)
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], headers.Checksum(msg))
	errPkt := headers.BuildIPv4(&headers.IPv4Header{
		TotalLength: uint16(headers.V4MinHeaderLen + len(msg)),
		TTL:         64, Protocol: headers.ProtoICMPv4,
		Src: h.Dst, Dst: h.Src,
	}, msg)
	c.handleInboundV4(errPkt)
}
