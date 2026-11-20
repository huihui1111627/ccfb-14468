package sim

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	"ivat/pkg/encap"
	"ivat/pkg/headers"
	"ivat/pkg/maprule"
	"ivat/pkg/napt"
	"ivat/pkg/translate"
)

// Mode 选择 CE/BR 的工作模式。
type Mode int

const (
	ModeMAPT Mode = iota // 翻译模式（RFC 7599）
	ModeMAPE             // 封装模式（RFC 7597）
)

func (m Mode) String() string {
	if m == ModeMAPE {
		return "MAP-E 封装"
	}
	return "MAP-T 翻译"
}

// PortUseRecord 记录一次外部端口分配，供验收核对
// "端口落在本户端口集内、户与户不相交"。
type PortUseRecord struct {
	Subscriber string
	Proto      uint8
	Internal   string
	External   uint16
	PSID       uint16
}

// CE 是用户侧网关（一户一台）。
type CE struct {
	Name       string
	Rule       *maprule.Rule // 本户 BMR
	SharedV4   netip.Addr
	PSID       uint16
	WANV6      netip.Addr
	Mode       Mode
	Translator *translate.Translator

	cloud   *V6Cloud
	brV6    netip.Addr // MAP-E 默认隧道对端（BR）
	lan     map[netip.Addr]Port
	lanMu   sync.RWMutex
	napt    *napt.Table
	portSet map[uint16]struct{}

	mu      sync.Mutex
	portLog []PortUseRecord
	stats   CEStats
}

// CEStats 是 CE 的处理计数。
type CEStats struct {
	LANIn        int
	WANIn        int
	Translated   int
	Encapsulated int
	Decapsulated int
	DirectPeer   int // 同域直通、未绕 BR 的报文数
	NAPTDrops    int
	OtherDrops   int
}

// NewCE 构造一台用户侧网关并挂接到骨干云。
func NewCE(name string, rule *maprule.Rule, shared netip.Addr, psid uint16,
	mode Mode, cloud *V6Cloud, brV6 netip.Addr, tr *translate.Translator) (*CE, error) {
	wan, err := rule.EncodeIPv6(shared, psid)
	if err != nil {
		return nil, err
	}
	ports, err := rule.Expand(psid)
	if err != nil {
		return nil, err
	}
	ce := &CE{
		Name: name, Rule: rule, SharedV4: shared, PSID: psid, WANV6: wan,
		Mode: mode, Translator: tr, cloud: cloud, brV6: brV6,
		lan:     map[netip.Addr]Port{},
		napt:    napt.NewTable(ports),
		portSet: toSet(ports),
	}
	cloud.AttachCE(wan, ce.WANInput)
	return ce, nil
}

func toSet(ports []uint16) map[uint16]struct{} {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	return m
}

// AttachHost 把终端挂到 LAN（等价于 ARP 表项）。
func (c *CE) AttachHost(ip netip.Addr, p Port) {
	c.lanMu.Lock()
	c.lan[ip] = p
	c.lanMu.Unlock()
}

// WANInput 是骨干侧收包入口。
func (c *CE) WANInput(packet []byte) {
	c.mu.Lock()
	c.stats.WANIn++
	c.mu.Unlock()

	if c.Mode == ModeMAPE && encap.IsEncap(packet) {
		inner, _, err := encap.Decap(packet)
		if err != nil {
			c.drop()
			return
		}
		c.mu.Lock()
		c.stats.Decapsulated++
		c.mu.Unlock()
		c.handleInboundV4(inner)
		return
	}

	// MAP-T 路径，或骨干产生的 ICMPv6 差错
	h, err := headers.ParseIPv6(packet)
	if err != nil {
		c.drop()
		return
	}
	if h.NextHeader == headers.ProtoICMPv6 && isICMPError(packet[headers.V6HeaderLen:]) {
		// 封装模式下的 PTB/超时：转成 v4 差错回给户内主机
		if c.Mode == ModeMAPE {
			if v4err, ok := c.tunnelICMPToV4(packet); ok {
				c.handleInboundV4(v4err)
			} else {
				c.drop()
			}
			return
		}
		c.handleTranslatedICMPV6(packet)
		return
	}

	// 普通 MAP-T 报文：v6→v4 无状态翻译
	mapSrc := func(a netip.Addr) (netip.Addr, bool) {
		if v4, _, ok := c.Rule.DecodeIPv6(a); ok {
			return v4, true
		}
		if v4, ok := DecodeDMR(a); ok {
			return v4, true
		}
		// 路径上的路由器（如云自身的 fe80::1）不携带户标识，
		// 合成一个本地链路 v4 地址承载差错源，语义不变。
		return syntheticRouterV4(a), true
	}
	mapDst := func(netip.Addr) (netip.Addr, bool) { return c.SharedV4, true }
	// 差错体内层是本户的"外出"报文（源=本户、目的=对端），
	// 与外层（源=对端、目的=本户）方向相反，映射必须按外出语义构造：
	// 内层源（本户 v6）→ 共享 v4；内层目的（对端 DMR）→ 公网 v4。
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
	v4pkt, err := c.Translator.V6ToV4WithInner(packet, mapSrc, mapDst, innerMapSrc, innerMapDst)
	if err != nil {
		c.drop()
		return
	}
	c.mu.Lock()
	c.stats.Translated++
	c.mu.Unlock()
	c.handleInboundV4(v4pkt)
}

// LANInput 是户内终端发往网关的入口（完整 IPv4 报文）。
func (c *CE) LANInput(packet []byte) {
	c.mu.Lock()
	c.stats.LANIn++
	c.mu.Unlock()
	h, ihl, err := headers.ParseIPv4(packet)
	if err != nil {
		c.drop()
		return
	}
	// 外出方向先做户内 NAPT44（外部端口只取本户端口集）。
	natPkt, ok := c.naptOutbound(packet, h, ihl)
	if !ok {
		c.mu.Lock()
		c.stats.NAPTDrops++
		c.mu.Unlock()
		return
	}
	if c.Mode == ModeMAPE {
		c.encapOutbound(natPkt)
		return
	}
	c.translateOutbound(natPkt)
}

// ---------- 外出 ----------

func (c *CE) translateOutbound(v4pkt []byte) {
	h, ihl, _ := headers.ParseIPv4(v4pkt)
	dst6, direct := c.chooseDstV6(h, v4pkt[ihl:])
	if direct {
		c.mu.Lock()
		c.stats.DirectPeer++
		c.mu.Unlock()
	}
	mapSrc := func(netip.Addr) (netip.Addr, bool) { return c.WANV6, true }
	mapDst := func(netip.Addr) (netip.Addr, bool) { return dst6, true }
	v6pkt, err := c.Translator.V4ToV6(v4pkt, mapSrc, mapDst)
	if err != nil {
		if e, ok := err.(*translate.ErrICMP); ok {
			// 翻译器要求回 PTB：构造带原始报文头的 v4 Frag Needed 回送户内
			c.sendLocalFragNeeded(v4pkt, e.MTU)
			return
		}
		c.drop()
		return
	}
	c.mu.Lock()
	c.stats.Translated++
	c.mu.Unlock()
	c.cloud.Send(v6pkt)
}

func (c *CE) encapOutbound(v4pkt []byte) {
	h, ihl, _ := headers.ParseIPv4(v4pkt)
	dst6, direct := c.chooseDstV6(h, v4pkt[ihl:])
	if direct {
		c.mu.Lock()
		c.stats.DirectPeer++
		c.mu.Unlock()
	} else {
		dst6 = c.brV6 // 出域流量封装到 BR 隧道端点
	}
	pkt, err := encap.Encap(v4pkt, c.WANV6, dst6, 64)
	if err != nil {
		c.drop()
		return
	}
	c.mu.Lock()
	c.stats.Encapsulated++
	c.mu.Unlock()
	c.cloud.Send(pkt)
}

// chooseDstV6 决定目的 IPv6：同域可解析则直连对端户 CE，否则走 DMR/BR。
// 返回的 direct 标记该报文是否无需绕 BR。
func (c *CE) chooseDstV6(h *headers.IPv4Header, l4 []byte) (netip.Addr, bool) {
	// 仅 TCP/UDP 携带端口，可无状态反解对端 PSID。
	if h.Protocol != headers.ProtoTCP && h.Protocol != headers.ProtoUDP {
		return EncodeDMR(h.Dst), false
	}
	if len(l4) < 4 {
		return EncodeDMR(h.Dst), false
	}
	dstPort := binary.BigEndian.Uint16(l4[2:4])
	psid, member := c.Rule.PSIDFromPort(dstPort)
	if !member {
		return EncodeDMR(h.Dst), false
	}
	// 同域：目的 v4 必须在规则覆盖段内，且不是自己的共享地址回环场景。
	if c.Rule.ContainsV4(h.Dst) {
		if peer, err := c.Rule.EncodeIPv6(h.Dst, psid); err == nil && peer != c.WANV6 {
			return peer, true
		}
	}
	return EncodeDMR(h.Dst), false
}

// ---------- NAPT44 ----------

func (c *CE) naptOutbound(pkt []byte, h *headers.IPv4Header, ihl int) ([]byte, bool) {
	out := append([]byte(nil), pkt...)
	l4 := out[ihl:]
	switch h.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		return c.naptOutboundTransport(out, h, ihl, l4)
	case headers.ProtoICMPv4:
		return c.naptOutboundICMP(out, h, ihl, l4)
	default:
		return out, true // 无端口协议直接透传（BR 侧按规则处理）
	}
}

func (c *CE) naptOutboundTransport(out []byte, h *headers.IPv4Header, ihl int, l4 []byte) ([]byte, bool) {
	if len(l4) < 4 {
		return nil, false
	}
	srcPort := binary.BigEndian.Uint16(l4[0:2])
	dstPort := binary.BigEndian.Uint16(l4[2:4])
	m, err := c.napt.Allocate(h.Protocol, h.Src.As4(), srcPort, h.Dst.As4(), dstPort)
	if err != nil {
		return nil, false
	}
	c.recordPort(h.Protocol, fmt.Sprintf("%s:%d", h.Src, srcPort), m.ExternalPt)
	if m.ExternalPt == srcPort && h.Src == c.SharedV4 {
		return out, true
	}
	// 重写源地址（私网→共享 v4）与源端口（→端口集成员）。
	binary.BigEndian.PutUint16(l4[0:2], m.ExternalPt)
	src4 := c.SharedV4.As4()
	copy(out[12:16], src4[:])
	// 重算传输层校验和：地址与端口都变了，整体重算最稳妥。
	pos := headers.UDPChecksumPos()
	if h.Protocol == headers.ProtoTCP {
		pos = headers.TCPChecksumPos()
	}
	segLen := len(l4)
	pseudo := headers.PseudoHeaderV4(c.SharedV4.As4(), h.Dst.As4(), h.Protocol, segLen)
	if h.Protocol == headers.ProtoUDP {
		// v4 UDP 允许 0；这里统一计算真实值。
	}
	csum := headers.TransportChecksum(pseudo, l4, pos)
	binary.BigEndian.PutUint16(l4[pos:], csum)
	// IPv4 头校验和随源地址变化重算。
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], headers.Checksum(out[:ihl]))
	return out, true
}

func (c *CE) naptOutboundICMP(out []byte, h *headers.IPv4Header, ihl int, l4 []byte) ([]byte, bool) {
	msg, err := headers.ParseICMP(l4)
	if err != nil {
		return nil, false
	}
	if msg.Type == headers.ICMP4EchoRequest {
		id := headers.EchoID(msg.Rest)
		m, err := c.napt.Allocate(napt.ProtoICMP, h.Src.As4(), id, h.Dst.As4(), 0)
		if err != nil {
			return nil, false
		}
		c.recordPort(napt.ProtoICMP, fmt.Sprintf("%s:id=%d", h.Src, id), m.ExternalPt)
		headers.SetEchoID(&msg.Rest, m.ExternalPt)
		fixed := headers.BuildICMP(msg)
		binary.BigEndian.PutUint16(fixed[headers.ICMPChecksumPos():], 0)
		binary.BigEndian.PutUint16(fixed[headers.ICMPChecksumPos():], headers.Checksum(fixed))
		// 源地址也要换成共享 v4。
		result := append([]byte(nil), out[:ihl]...)
		src4 := c.SharedV4.As4()
		copy(result[12:16], src4[:])
		result = append(result, fixed...)
		binary.BigEndian.PutUint16(result[10:12], 0)
		binary.BigEndian.PutUint16(result[10:12], headers.Checksum(result[:ihl]))
		return result, true
	}
	if isICMPErrorType(msg.Type) {
		// 外出差错：体内引用报文的源端口要按表回写；查不到映射则丢弃。
		fixed, ok := c.fixInnerICMPOutbound(l4)
		if !ok {
			return nil, false
		}
		result := append([]byte(nil), out[:ihl]...)
		result = append(result, fixed...)
		binary.BigEndian.PutUint16(result[10:12], 0)
		binary.BigEndian.PutUint16(result[10:12], headers.Checksum(result[:ihl]))
		return result, true
	}
	return out, true
}

// ---------- 入向 ----------

func (c *CE) handleInboundV4(v4pkt []byte) {
	h, ihl, err := headers.ParseIPv4(v4pkt)
	if err != nil {
		c.drop()
		return
	}
	natPkt, dst, ok := c.naptInbound(v4pkt, h, ihl)
	if !ok {
		c.mu.Lock()
		c.stats.NAPTDrops++
		c.mu.Unlock()
		return
	}
	c.lanMu.RLock()
	p, known := c.lan[dst]
	c.lanMu.RUnlock()
	if !known {
		c.drop()
		return
	}
	p(natPkt)
}

func (c *CE) naptInbound(pkt []byte, h *headers.IPv4Header, ihl int) ([]byte, netip.Addr, bool) {
	out := append([]byte(nil), pkt...)
	l4 := out[ihl:]
	switch h.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		if len(l4) < 4 {
			return nil, netip.Addr{}, false
		}
		extPort := binary.BigEndian.Uint16(l4[2:4])
		m, err := c.napt.LookupInbound(h.Protocol, extPort, h.Src.As4(),
			binary.BigEndian.Uint16(l4[0:2]))
		if err != nil {
			// 无映射：仍交给户内主机，由协议栈回端口不可达/RST
			return out, c.firstLANHost(), true
		}
		binary.BigEndian.PutUint16(l4[2:4], m.InternalPt)
		dst := netip.AddrFrom4(m.InternalIP)
		dstB := dst.As4()
		copy(out[16:20], dstB[:])
		pos := headers.UDPChecksumPos()
		if h.Protocol == headers.ProtoTCP {
			pos = headers.TCPChecksumPos()
		}
		pseudo := headers.PseudoHeaderV4(h.Src.As4(), dstB, h.Protocol, len(l4))
		csum := headers.TransportChecksum(pseudo, l4, pos)
		binary.BigEndian.PutUint16(l4[pos:], csum)
		binary.BigEndian.PutUint16(out[10:12], 0)
		binary.BigEndian.PutUint16(out[10:12], headers.Checksum(out[:ihl]))
		return out, dst, true
	case headers.ProtoICMPv4:
		return c.naptInboundICMP(out, h, ihl)
	default:
		return out, c.firstLANHost(), true
	}
}

func (c *CE) naptInboundICMP(out []byte, h *headers.IPv4Header, ihl int) ([]byte, netip.Addr, bool) {
	msg, err := headers.ParseICMP(out[ihl:])
	if err != nil {
		return nil, netip.Addr{}, false
	}
	if msg.Type == headers.ICMP4EchoReply || msg.Type == headers.ICMP4EchoRequest {
		extID := headers.EchoID(msg.Rest)
		m, err := c.napt.LookupInbound(napt.ProtoICMP, extID, h.Src.As4(), 0)
		if err != nil {
			return nil, netip.Addr{}, false
		}
		headers.SetEchoID(&msg.Rest, m.InternalPt)
		fixed := headers.BuildICMP(msg)
		binary.BigEndian.PutUint16(fixed[headers.ICMPChecksumPos():], 0)
		binary.BigEndian.PutUint16(fixed[headers.ICMPChecksumPos():], headers.Checksum(fixed))
		result := append([]byte(nil), out[:ihl]...)
		dst := netip.AddrFrom4(m.InternalIP)
		dstB := dst.As4()
		copy(result[16:20], dstB[:])
		result = append(result, fixed...)
		binary.BigEndian.PutUint16(result[10:12], 0)
		binary.BigEndian.PutUint16(result[10:12], headers.Checksum(result[:ihl]))
		return result, dst, true
	}
	if isICMPErrorType(msg.Type) {
		fixed, dst, ok := c.fixInnerICMPInbound(out[ihl:])
		if !ok {
			return nil, netip.Addr{}, false
		}
		result := append([]byte(nil), out[:ihl]...)
		dstB := dst.As4()
		copy(result[16:20], dstB[:])
		result = append(result, fixed...)
		binary.BigEndian.PutUint16(result[10:12], 0)
		binary.BigEndian.PutUint16(result[10:12], headers.Checksum(result[:ihl]))
		return result, dst, true
	}
	return out, c.firstLANHost(), true
}

func (c *CE) firstLANHost() netip.Addr {
	c.lanMu.RLock()
	defer c.lanMu.RUnlock()
	for ip := range c.lan {
		return ip
	}
	return netip.Addr{}
}

func (c *CE) recordPort(proto uint8, internal string, ext uint16) {
	if _, ok := c.portSet[ext]; !ok {
		panic(fmt.Sprintf("CE %s 分配了端口集外端口 %d", c.Name, ext))
	}
	c.mu.Lock()
	c.portLog = append(c.portLog, PortUseRecord{
		Subscriber: c.Name, Proto: proto, Internal: internal,
		External: ext, PSID: c.PSID,
	})
	c.mu.Unlock()
}

// PortLog 返回端口分配记录快照。
func (c *CE) PortLog() []PortUseRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]PortUseRecord, len(c.portLog))
	copy(out, c.portLog)
	return out
}

// Stats 返回 CE 计数快照。
func (c *CE) Stats() CEStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// NAPTStats 返回户内 NAPT 表规模。
func (c *CE) NAPTStats() napt.Stats { return c.napt.Stats() }

func (c *CE) drop() {
	c.mu.Lock()
	c.stats.OtherDrops++
	c.mu.Unlock()
}

// DMR 前缀：RFC 6052 知名前缀 64:ff9b::/96。
var dmrPrefix = netip.MustParsePrefix("64:ff9b::/96")

// EncodeDMR 把外部公网 v4 编码成 DMR v6 地址。
func EncodeDMR(v4 netip.Addr) netip.Addr {
	var b [16]byte
	b[0], b[1] = 0x64, 0xff // 64:ff9b::/96
	v := v4.As4()
	copy(b[12:16], v[:])
	return netip.AddrFrom16(b)
}

// DecodeDMR 还原 DMR 地址；非 DMR 空间返回 false。
func DecodeDMR(v6 netip.Addr) (netip.Addr, bool) {
	b := v6.As16()
	if b[0] == 0x64 && b[1] == 0xff {
		// 订阅户地址在 b[12:14] 放 PSID、b[14:16] 为 0；
		// DMR 要求 b[8:12] 全 0（/96 前缀零位）。
		if b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 {
			return netip.AddrFrom4([4]byte(b[12:16])), true
		}
	}
	return netip.Addr{}, false
}

// syntheticRouterV4 为路径上无法映射的 v6 路由器地址合成一个 v4 表示，
// 仅用于 ICMP 差错报文的外层源地址（终端只用它判断"来自网络"）。
func syntheticRouterV4(v6 netip.Addr) netip.Addr {
	b := v6.As16()
	return netip.AddrFrom4([4]byte{169, 254, b[14], b[15]})
}

func isICMPError(seg []byte) bool {
	if len(seg) < 1 {
		return false
	}
	return isICMPErrorType(seg[0])
}

func isICMPErrorType(t uint8) bool {
	// 注意：v4/v6 常量数值空间重叠（如 v4 DstUnreach=3 与 v6 TimeExceed=3），
	// 本函数在调用点按地址族区分使用；这里取两个集合的并集。
	switch t {
	case headers.ICMP4DstUnreach, headers.ICMP4Redirect,
		headers.ICMP4TimeExceed, headers.ICMP4ParamProblem:
		return true
	}
	switch t {
	case headers.ICMP6DstUnreach, headers.ICMP6PktTooBig,
		headers.ICMP6TimeExceed, headers.ICMP6ParamProblem:
		return true
	}
	return false
}
