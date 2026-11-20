package sim

import (
	"net/netip"
	"sync"

	"ivat/pkg/encap"
	"ivat/pkg/headers"
	"ivat/pkg/maprule"
	"ivat/pkg/translate"
)

// BR 是边界设备。它的全部"配置"是一个规则域加一个翻译器：
// 任何报文的映射结果都由规则数学当场算出，设备内没有连接表，
// 因此不存在"表项一满全县看不了电视"的故障面。
type BR struct {
	Name       string
	Domain     *maprule.Domain
	Mode       Mode
	Translator *translate.Translator
	V6Addr     netip.Addr

	cloud *V6Cloud
	v4net *V4Net

	mu    sync.Mutex
	stats BRStats
}

// BRStats 只记录计数，不记录任何每条连接的状态。
type BRStats struct {
	V4In         int
	V6In         int
	Translated46 int
	Translated64 int
	EncapIn      int
	EncapOut     int
	Dropped      int
	ICMPErrors   int
}

func NewBR(name string, domain *maprule.Domain, mode Mode,
	cloud *V6Cloud, v4net *V4Net, tr *translate.Translator, v6addr netip.Addr) *BR {
	br := &BR{
		Name: name, Domain: domain, Mode: mode, Translator: tr,
		V6Addr: v6addr, cloud: cloud, v4net: v4net,
	}
	return br
}

// V4Input 是 BR 公网 v4 侧入口。
func (b *BR) V4Input(packet []byte) {
	b.mu.Lock()
	b.stats.V4In++
	b.mu.Unlock()

	h, ihl, err := headers.ParseIPv4(packet)
	if err != nil {
		b.drop()
		return
	}

	if b.Mode == ModeMAPE {
		b.encapV4ToV6(packet, h)
		return
	}

	// MAP-T：目的地址+标识字段 → PSID → 户 v6，全部当场计算。
	mapSrc := func(netip.Addr) (netip.Addr, bool) { return EncodeDMR(h.Src), true }
	mapDst := func(dst netip.Addr) (netip.Addr, bool) {
		rule := b.Domain.MatchV4(dst)
		if rule == nil {
			return netip.Addr{}, false
		}
		// 差错 ICMP 的户标识在内层源端口（innerIdent），
		// 普通报文在传输层目的端口（subscriberIdent）。
		var ident uint16
		if h.Protocol == headers.ProtoICMPv4 && isICMPErrorType(packet[ihl]) {
			ident = b.innerIdent(h, packet[ihl:])
		} else {
			ident = b.subscriberIdent(h, packet[ihl:])
		}
		if ident == 0 {
			return netip.Addr{}, false
		}
		psid, member := rule.PSIDFromPort(ident)
		if !member {
			return netip.Addr{}, false
		}
		addr, err := rule.EncodeIPv6(dst, psid)
		if err != nil {
			return netip.Addr{}, false
		}
		return addr, true
	}
	// 差错体内层是户的"外出"报文（源=共享 v4、目的=公网对端），
	// 与外层方向相反，需独立映射：内层共享 v4→户 v6，公网→DMR。
	innerMapSrc := func(a netip.Addr) (netip.Addr, bool) {
		rule := b.Domain.MatchV4(a)
		if rule == nil {
			return netip.Addr{}, false
		}
		// 内层源端口即外部端口，携带户 PSID。
		ident := b.innerIdent(h, packet[ihl:])
		if ident == 0 {
			return netip.Addr{}, false
		}
		psid, member := rule.PSIDFromPort(ident)
		if !member {
			return netip.Addr{}, false
		}
		addr, err := rule.EncodeIPv6(a, psid)
		if err != nil {
			return netip.Addr{}, false
		}
		return addr, true
	}
	innerMapDst := func(a netip.Addr) (netip.Addr, bool) {
		return EncodeDMR(a), true
	}
	out, err := b.Translator.V4ToV6WithInner(packet, mapSrc, mapDst, innerMapSrc, innerMapDst)
	if err != nil {
		if _, ok := err.(*translate.ErrICMP); ok {
			// 由 v4 侧 MTU 引发的拒绝：外网自身已先行 PTB，这里计数即可。
			b.mu.Lock()
			b.stats.ICMPErrors++
			b.mu.Unlock()
		}
		b.drop()
		return
	}
	b.mu.Lock()
	b.stats.Translated46++
	b.mu.Unlock()
	b.cloud.Send(out)
}

func (b *BR) encapV4ToV6(packet []byte, h *headers.IPv4Header) {
	rule := b.Domain.MatchV4(h.Dst)
	if rule == nil {
		b.drop()
		return
	}
	// 与翻译路径一致：差错 ICMP 用内层源端口定位户，其余用传输层目的端口。
	var ident uint16
	l4 := packet[headers.V4MinHeaderLen:]
	if h.Protocol == headers.ProtoICMPv4 && isICMPErrorType(packet[headers.V4MinHeaderLen]) {
		ident = b.innerIdent(h, l4)
	} else {
		ident = b.subscriberIdent(h, l4)
	}
	if ident == 0 {
		b.drop()
		return
	}
	psid, member := rule.PSIDFromPort(ident)
	if !member {
		b.drop()
		return
	}
	dst6, err := rule.EncodeIPv6(h.Dst, psid)
	if err != nil {
		b.drop()
		return
	}
	pkt, err := encap.Encap(packet, b.V6Addr, dst6, 64)
	if err != nil {
		b.drop()
		return
	}
	b.mu.Lock()
	b.stats.EncapOut++
	b.mu.Unlock()
	b.cloud.Send(pkt)
}

// V6Input 是 BR 骨干侧入口。
func (b *BR) V6Input(packet []byte) {
	b.mu.Lock()
	b.stats.V6In++
	b.mu.Unlock()

	if encap.IsEncap(packet) {
		inner, _, err := encap.Decap(packet)
		if err != nil {
			b.drop()
			return
		}
		b.mu.Lock()
		b.stats.EncapIn++
		b.mu.Unlock()
		b.forwardV4(inner)
		return
	}

	h, err := headers.ParseIPv6(packet)
	if err != nil {
		b.drop()
		return
	}
	// 骨干产生的 ICMPv6 差错（PTB/超时）：翻译回 v4 送外网，
	// 让 traceroute 与 PMTUD 跨地址族继续工作。
	if h.NextHeader == headers.ProtoICMPv6 && isICMPError(packet[headers.V6HeaderLen:]) {
		b.translateV6ErrorToV4(packet)
		return
	}

	mapSrc := func(a netip.Addr) (netip.Addr, bool) {
		rule, _, v4, ok := b.Domain.MatchV6(a)
		if ok && rule != nil {
			return v4, true
		}
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		return netip.Addr{}, false
	}
	mapDst := func(a netip.Addr) (netip.Addr, bool) {
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		// 目的是同域另一户：解出其共享 v4（同域直通正常不会到 BR，
		// 这里保留兜底，使策略强制经 BR 时仍可工作）。
		if _, _, v4, ok := b.Domain.MatchV6(a); ok {
			return v4, true
		}
		return netip.Addr{}, false
	}
	out, err := b.Translator.V6ToV4(packet, mapSrc, mapDst)
	if err != nil {
		if e, ok := err.(*translate.ErrICMP); ok {
			_ = e
			b.mu.Lock()
			b.stats.ICMPErrors++
			b.mu.Unlock()
		}
		b.drop()
		return
	}
	b.mu.Lock()
	b.stats.Translated64++
	b.mu.Unlock()
	b.forwardV4(out)
}

func (b *BR) forwardV4(pkt []byte) {
	b.v4net.Send(pkt)
}

// translateV6ErrorToV4 把骨干侧 ICMPv6 差错无状态翻译成 v4 差错。
// 体内引用报文同样被翻译器里外两层处理，BR 不保存任何上下文。
func (b *BR) translateV6ErrorToV4(v6pkt []byte) {
	mapSrc := func(a netip.Addr) (netip.Addr, bool) {
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		if _, _, v4, ok := b.Domain.MatchV6(a); ok {
			return v4, true
		}
		return netip.Addr{}, false
	}
	mapDst := func(a netip.Addr) (netip.Addr, bool) {
		if _, _, v4, ok := b.Domain.MatchV6(a); ok {
			return v4, true
		}
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		return netip.Addr{}, false
	}
	out, err := b.Translator.V6ToV4(v6pkt, mapSrc, mapDst)
	if err != nil {
		b.drop()
		return
	}
	b.mu.Lock()
	b.stats.Translated64++
	b.stats.ICMPErrors++
	b.mu.Unlock()
	b.forwardV4(out)
}

func (b *BR) drop() {
	b.mu.Lock()
	b.stats.Dropped++
	b.mu.Unlock()
}

// Stats 返回计数快照。
func (b *BR) Stats() BRStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

// dstPortOf 尽力提取 v4 报文的传输层目的端口；
// ICMP/无端口协议返回 0（这类流量的户选择在翻译 ICMP 时由体内端口完成）。
func dstPortOf(packet []byte, ihl int) uint16 {
	if len(packet) < ihl+4 {
		return 0
	}
	h, _, err := headers.ParseIPv4(packet)
	if err != nil {
		return 0
	}
	switch h.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		return uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])
	}
	return 0
}

// innerIdent 提取差错 ICMP 体内层报文里户的外部端口（内层源端口/ID）。
func (b *BR) innerIdent(outer *headers.IPv4Header, l4 []byte) uint16 {
	if outer.Protocol != headers.ProtoICMPv4 || len(l4) < 8 {
		return 0
	}
	typ := l4[0]
	if !isICMPErrorType(typ) {
		return 0
	}
	body := l4[8:] // 跳过 ICMP 通用头
	inner, ihl, err := headers.ParseIPv4(body)
	if err != nil || len(body) < ihl+2 {
		return 0
	}
	switch inner.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		return uint16(body[ihl])<<8 | uint16(body[ihl+1]) // 内层源端口
	case headers.ProtoICMPv4:
		if len(body) >= ihl+6 {
			return uint16(body[ihl+4])<<8 | uint16(body[ihl+5]) // 内层 Echo ID
		}
	}
	return 0
}

// subscriberIdent 按 RFC 7599 §7.2 从入向 v4 报文提取用于定位户的标识：
//   - TCP/UDP：传输层目的端口；
//   - ICMP Echo 请求/应答：Echo 标识符（CE 已把 NAPT 外部端口放在 ID）；
//   - ICMP 差错：体内引用报文的传输层目的端口或内层 Echo ID；
//   - 其余情况返回 0（无法定位）。
func (b *BR) subscriberIdent(h *headers.IPv4Header, l4 []byte) uint16 {
	switch h.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		if len(l4) < 4 {
			return 0
		}
		return uint16(l4[2])<<8 | uint16(l4[3])
	case headers.ProtoICMPv4:
		if len(l4) < 8 {
			return 0
		}
		typ := l4[0]
		if typ == headers.ICMP4EchoRequest || typ == headers.ICMP4EchoReply {
			return uint16(l4[4])<<8 | uint16(l4[5])
		}
		if isICMPErrorType(typ) {
			body := l4[8:] // 跳过 8 字节 ICMP 通用头
			inner, ihl, err := headers.ParseIPv4(body)
			if err != nil || len(body) < ihl+4 {
				return 0
			}
			switch inner.Protocol {
			case headers.ProtoTCP, headers.ProtoUDP:
				return uint16(body[ihl+2])<<8 | uint16(body[ihl+3])
			case headers.ProtoICMPv4:
				if len(body) >= ihl+6 {
					return uint16(body[ihl+4])<<8 | uint16(body[ihl+5])
				}
			}
		}
	}
	return 0
}
