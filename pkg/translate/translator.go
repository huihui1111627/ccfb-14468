// Package translate 实现 RFC 7915 定义的 IP/ICMP 逐字段无状态翻译。
//
// 翻译器本身不保存任何连接状态：地址映射由调用方（CE/BR）以函数形式注入，
// 同一条报文无论何时到达，翻译结果完全一致。这正是集中式 NAT64 表项一满
// 全网瘫痪问题的解法——边界设备上不存在"表"。
package translate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"ivat/pkg/headers"
)

// ErrDrop 表示报文按规则必须静默丢弃（含无对应物的 ICMP 类型）。
type ErrDrop struct{ Reason string }

func (e *ErrDrop) Error() string { return "丢弃报文: " + e.Reason }

// ErrICMP 表示需要向源端回送差错报文。
type ErrICMP struct {
	V6Type uint8 // v4→v6 方向时应回的 ICMPv6 类型
	V4Type uint8 // v6→v4 方向时应回的 ICMPv4 类型
	Code   uint8
	MTU    uint32 // 仅 PTB/FragNeeded 有意义
	Reason string
}

func (e *ErrICMP) Error() string { return "需要回送差错: " + e.Reason }

// AddrMapper 把一个地址族的地址翻译成另一个地址族。
// 返回 ok=false 表示地址不属于本翻译域，报文应按普通路由转发或丢弃。
type AddrMapper func(addr netip.Addr) (mapped netip.Addr, ok bool)

// Config 控制翻译行为。
type Config struct {
	// V6MTU 是 IPv6 侧路径 MTU（骨干），V4MTU 是 IPv4 侧（户内）。
	V6MTU int
	V4MTU int
	// ChecksumNeutral 为 true 时地址布局是校验和中立的，
	// 传输层校验和逐字节保持，不做增量更新。
	ChecksumNeutral bool
	// TTLDelta 每经过一次翻译对 TTL/HopLimit 的额外折损（默认 0，
	// 正常的逐跳递减由路由节点完成）。
	TTLDelta uint8
}

// Translator 是无状态翻译器。
type Translator struct {
	cfg Config
}

func New(cfg Config) *Translator {
	if cfg.V6MTU == 0 {
		cfg.V6MTU = 1500
	}
	if cfg.V4MTU == 0 {
		cfg.V4MTU = 1500
	}
	return &Translator{cfg: cfg}
}

// V4ToV6 把完整 IPv4 报文翻译成 IPv6 报文。
// mapSrc/mapDst 分别翻译源、目的地址。
func (t *Translator) V4ToV6(packet []byte, mapSrc, mapDst AddrMapper) ([]byte, error) {
	return t.V4ToV6WithInner(packet, mapSrc, mapDst, mapSrc, mapDst)
}

// V4ToV6WithInner 支持为 ICMP 内层引用报文提供独立映射。
func (t *Translator) V4ToV6WithInner(packet []byte, mapSrc, mapDst,
	innerMapSrc, innerMapDst AddrMapper) ([]byte, error) {
	h, ihl, err := headers.ParseIPv4(packet)
	if err != nil {
		return nil, err
	}
	src6, ok := mapSrc(h.Src)
	if !ok {
		return nil, &ErrDrop{Reason: "源 IPv4 不在翻译域内"}
	}
	dst6, ok := mapDst(h.Dst)
	if !ok {
		return nil, &ErrDrop{Reason: "目的 IPv4 不在翻译域内"}
	}
	payload := packet[ihl:]

	// 长度字段：IPv4 TotalLength 含头，IPv6 PayloadLength 不含头。
	// 分片报文在 RFC 7915 下需要插入分片扩展头，本仿真对非原子分片
	// 采用"重组在 CE 完成"的约束：链路只产生 DF 原子报文，
	// 收到带 MF/偏移的报文按 RFC 7915 §3.2 处理（见 fragment.go）。
	if h.IsFragment() && !h.DF() {
		return t.v4FragmentToV6(h, payload, src6, dst6)
	}

	// PMTU 检查（RFC 7915 §3.1）：IPv6 最小 MTU 1280。
	if len(packet) > t.cfg.V6MTU {
		if h.DF() {
			return nil, &ErrICMP{
				V6Type: headers.ICMP6PktTooBig, Code: 0,
				MTU:    uint32(t.cfg.V6MTU),
				Reason: fmt.Sprintf("报文 %d 字节超过 v6 MTU %d 且 DF 置位", len(packet), t.cfg.V6MTU),
			}
		}
		// 允许分片的 v4 报文：v6 侧由发送方负责分片，这里按 PTB 促使其缩小
		return nil, &ErrICMP{
			V6Type: headers.ICMP6PktTooBig, Code: 0,
			MTU:    uint32(t.cfg.V6MTU),
			Reason: "v6 路径不允许中间设备分片",
		}
	}

	nh, ok := protoV4ToV6(h.Protocol)
	if !ok {
		return nil, &ErrDrop{Reason: fmt.Sprintf("协议号 %d 无法映射", h.Protocol)}
	}

	outPayload, err := t.translatePayloadV4ToV6(payload, h, src6, dst6, nh, innerMapSrc, innerMapDst)
	if err != nil {
		return nil, err
	}

	v6 := &headers.IPv6Header{
		// TOS/DSCP 逐位保留：v4 TOS 整个字节即 DSCP(6)+ECN(2)，
		// v6 TrafficClass 字段位定义相同。
		TrafficClass: h.TOS,
		// v4 没有流标签字段，置 0。
		FlowLabel:  0,
		Length:     uint16(len(outPayload)),
		NextHeader: nh,
		// TTL→HopLimit，逐字拷贝后再扣翻译折损。
		HopLimit: decrement8(h.TTL, t.cfg.TTLDelta),
		Src:      src6,
		Dst:      dst6,
	}
	return headers.BuildIPv6(v6, outPayload), nil
}

// V6ToV4 把完整 IPv6 报文翻译成 IPv4 报文。
// 内层 ICMP 引用报文默认复用外层映射；需要独立语义时用 V6ToV4WithInner。
func (t *Translator) V6ToV4(packet []byte, mapSrc, mapDst AddrMapper) ([]byte, error) {
	return t.V6ToV4WithInner(packet, mapSrc, mapDst, mapSrc, mapDst)
}

// V6ToV4WithInner 与 V6ToV4 相同，但 ICMP 差错体内层引用报文
// 使用单独的映射函数（内外层地址角色不同时必须区分）。
func (t *Translator) V6ToV4WithInner(packet []byte, mapSrc, mapDst,
	innerMapSrc, innerMapDst AddrMapper) ([]byte, error) {
	h, err := headers.ParseIPv6(packet)
	if err != nil {
		return nil, err
	}
	src4, ok := mapSrc(h.Src)
	if !ok {
		return nil, &ErrDrop{Reason: "源 IPv6 不在翻译域内"}
	}
	dst4, ok := mapDst(h.Dst)
	if !ok {
		return nil, &ErrDrop{Reason: "目的 IPv6 不在翻译域内"}
	}
	if h.NextHeader == 44 { // 分片扩展头走专门路径
		return t.V6FragmentToV4(packet, mapSrc, mapDst)
	}
	payload := packet[headers.V6HeaderLen:]

	proto, ok := protoV6ToV4(h.NextHeader)
	if !ok {
		return nil, &ErrDrop{Reason: fmt.Sprintf("下一首部 %d 无法映射", h.NextHeader)}
	}

	outPayload, err := t.translatePayloadV6ToV4(payload, h, src4, dst4, proto, innerMapSrc, innerMapDst)
	if err != nil {
		return nil, err
	}

	// PMTU：v4 侧 MTU 通常更小。超长且无法在 v4 DF 语义下通过时回 Frag Needed。
	totalLen := headers.V4MinHeaderLen + len(outPayload)
	if totalLen > t.cfg.V4MTU {
		return nil, &ErrICMP{
			V4Type: headers.ICMP4DstUnreach, Code: headers.ICMP4FragNeededDF,
			MTU:    uint32(t.cfg.V4MTU),
			Reason: fmt.Sprintf("翻译后 %d 字节超过 v4 MTU %d", totalLen, t.cfg.V4MTU),
		}
	}

	// v6 原子报文翻译成 v4 时 DF 置位（RFC 7915：v6 不依赖中间分片，
	// 源端自己做 PMTUD，翻译后仍要求对端不分片）。
	v4 := &headers.IPv4Header{
		TOS:         h.TrafficClass, // DSCP/ECN 同样逐位保留
		TotalLength: uint16(totalLen),
		// v6 没有分片 ID；原子报文 DF=1 时 ID 无意义，填 0。
		ID:        0,
		FlagsFrag: headers.V4FlagDF,
		TTL:       decrement8(h.HopLimit, t.cfg.TTLDelta),
		Protocol:  proto,
		Src:       src4,
		Dst:       dst4,
	}
	return headers.BuildIPv4(v4, outPayload), nil
}

func decrement8(v, delta uint8) uint8 {
	if v > delta {
		return v - delta
	}
	return 0
}

// translatePayloadV4ToV6 处理传输层与 ICMP，返回新的 v6 负载。
func (t *Translator) translatePayloadV4ToV6(payload []byte,
	outer *headers.IPv4Header, src6, dst6 netip.Addr, nh uint8,
	innerMapSrc, innerMapDst AddrMapper) ([]byte, error) {
	switch outer.Protocol {
	case headers.ProtoTCP, headers.ProtoUDP:
		return t.fixTransportV4ToV6(payload, outer.Protocol, outer.Src, outer.Dst, src6, dst6)
	case headers.ProtoICMPv4:
		return t.translateICMPV4ToV6(payload, outer, src6, dst6, innerMapSrc, innerMapDst)
	default:
		// 无传输层校验和的协议（GRE、SCTP 自带 CRC-C 等）原样透传
		return append([]byte(nil), payload...), nil
	}
}

func (t *Translator) translatePayloadV6ToV4(payload []byte,
	outer *headers.IPv6Header, src4, dst4 netip.Addr, proto uint8,
	innerMapSrc, innerMapDst AddrMapper) ([]byte, error) {
	switch outer.NextHeader {
	case headers.ProtoTCP, headers.ProtoUDP:
		return t.fixTransportV6ToV4(payload, outer.NextHeader, outer.Src, outer.Dst, src4, dst4)
	case headers.ProtoICMPv6:
		return t.translateICMPV6ToV4(payload, outer, src4, dst4, innerMapSrc, innerMapDst)
	default:
		return append([]byte(nil), payload...), nil
	}
}

// fixTransportV4ToV6 在 v4→v6 方向重算 TCP/UDP 校验和。
// v4 UDP 允许校验和为 0（发送方选择不计算）；v6 强制要求 UDP 校验和，
// 此时必须从 0 开始完整计算（RFC 7915 §4.7.2）。
func (t *Translator) fixTransportV4ToV6(seg []byte, proto uint8,
	src4, dst4, src6, dst6 netip.Addr) ([]byte, error) {
	out := append([]byte(nil), seg...)
	if t.cfg.ChecksumNeutral {
		// 校验和中立布局：伪头部的反码和保持不变，校验和字段原样保留。
		// 唯一例外是 v4 UDP 校验和为 0 的情况，v6 不允许 0，需补算。
		if proto == headers.ProtoUDP && binary.BigEndian.Uint16(out[headers.UDPChecksumPos():]) == 0 {
			return t.recomputeUDP(out, src6, dst6)
		}
		return out, nil
	}
	csumPos, err := transportChecksumPos(proto, len(out))
	if err != nil {
		return nil, err
	}
	oldCsum := binary.BigEndian.Uint16(out[csumPos:])
	if proto == headers.ProtoUDP && oldCsum == 0 {
		return t.recomputeUDP(out, src6, dst6)
	}
	// RFC 1624 增量更新：新校验和 = 旧校验和 + 新旧伪头部字差。
	oldPseudo := headers.PseudoHeaderV4(src4.As4(), dst4.As4(), proto, len(out))
	newPseudo := headers.PseudoHeaderV6(src6.As16(), dst6.As16(), proto, len(out))
	newCsum := headers.UpdateChecksum16(oldCsum,
		headers.SumWords16(oldPseudo), headers.SumWords16(newPseudo))
	binary.BigEndian.PutUint16(out[csumPos:], newCsum)
	return out, nil
}

func (t *Translator) fixTransportV6ToV4(seg []byte, nh uint8,
	src6, dst6, src4, dst4 netip.Addr) ([]byte, error) {
	out := append([]byte(nil), seg...)
	if t.cfg.ChecksumNeutral {
		// 反向同样中立；v4 UDP 允许保留计算出的校验和（置 0 也合法，这里保留）。
		return out, nil
	}
	csumPos, err := transportChecksumPos(nh, len(out))
	if err != nil {
		return nil, err
	}
	oldCsum := binary.BigEndian.Uint16(out[csumPos:])
	oldPseudo := headers.PseudoHeaderV6(src6.As16(), dst6.As16(), nh, len(out))
	newPseudo := headers.PseudoHeaderV4(src4.As4(), dst4.As4(), nh, len(out))
	newCsum := headers.UpdateChecksum16(oldCsum,
		headers.SumWords16(oldPseudo), headers.SumWords16(newPseudo))
	// v4 UDP 允许 0，但翻译路径上保留真实值更利于排障。
	binary.BigEndian.PutUint16(out[csumPos:], newCsum)
	return out, nil
}

func (t *Translator) recomputeUDP(seg []byte, src6, dst6 netip.Addr) ([]byte, error) {
	pseudo := headers.PseudoHeaderV6(src6.As16(), dst6.As16(), headers.ProtoUDP, len(seg))
	csum := headers.TransportChecksum(pseudo, seg, headers.UDPChecksumPos())
	binary.BigEndian.PutUint16(seg[headers.UDPChecksumPos():], csum)
	return seg, nil
}

func transportChecksumPos(proto uint8, segLen int) (int, error) {
	switch proto {
	case headers.ProtoTCP:
		if segLen < headers.TCPMinLen {
			return 0, errors.New("TCP 段过短")
		}
		return headers.TCPChecksumPos(), nil
	case headers.ProtoUDP:
		if segLen < headers.UDPLen {
			return 0, errors.New("UDP 段过短")
		}
		return headers.UDPChecksumPos(), nil
	default:
		return 0, fmt.Errorf("协议 %d 无传输层校验和", proto)
	}
}
