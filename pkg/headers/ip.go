package headers

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// 协议号
const (
	ProtoICMPv4 = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// IPv4 头固定部分长度与各字段偏移（RFC 791）。
const (
	V4MinHeaderLen = 20
	v4OffVersion   = 0
	v4OffTOS       = 1
	v4OffTotalLen  = 2
	v4OffID        = 4
	v4OffFlagsFrag = 6
	v4OffTTL       = 8
	v4OffProto     = 9
	v4OffChecksum  = 10
	v4OffSrc       = 12
	v4OffDst       = 16
)

// IPv4 分片标志位。
const (
	V4FlagReserved = 0x8000
	V4FlagDF       = 0x4000
	V4FlagMF       = 0x2000
	V4FragOffMask  = 0x1fff
)

// IPv4Header 是解析后的 IPv4 头（选项保留在 RawOptions 中）。
type IPv4Header struct {
	TOS          uint8
	TotalLength  uint16
	ID           uint16
	FlagsFrag    uint16
	TTL          uint8
	Protocol     uint8
	Src          netip.Addr
	Dst          netip.Addr
	HeaderLength int // 含选项的实际头长
	RawOptions   []byte
}

// DF / MF / 分片偏移访问器。
func (h *IPv4Header) DF() bool           { return h.FlagsFrag&V4FlagDF != 0 }
func (h *IPv4Header) MF() bool           { return h.FlagsFrag&V4FlagMF != 0 }
func (h *IPv4Header) FragOffset() uint16 { return h.FlagsFrag & V4FragOffMask }
func (h *IPv4Header) IsFragment() bool {
	return h.FlagsFrag&(V4FlagMF|V4FragOffMask) != 0
}

// ParseIPv4 从原始报文解析 IPv4 头，返回头对象与头长。
func ParseIPv4(packet []byte) (*IPv4Header, int, error) {
	if len(packet) < V4MinHeaderLen {
		return nil, 0, errors.New("IPv4 报文短于最小头长")
	}
	if packet[0]>>4 != 4 {
		return nil, 0, errors.New("版本字段不是 4")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < V4MinHeaderLen || ihl > len(packet) {
		return nil, 0, errors.New("IHL 非法")
	}
	h := &IPv4Header{
		TOS:          packet[v4OffTOS],
		TotalLength:  binary.BigEndian.Uint16(packet[v4OffTotalLen:]),
		ID:           binary.BigEndian.Uint16(packet[v4OffID:]),
		FlagsFrag:    binary.BigEndian.Uint16(packet[v4OffFlagsFrag:]),
		TTL:          packet[v4OffTTL],
		Protocol:     packet[v4OffProto],
		Src:          netip.AddrFrom4([4]byte(packet[v4OffSrc : v4OffSrc+4])),
		Dst:          netip.AddrFrom4([4]byte(packet[v4OffDst : v4OffDst+4])),
		HeaderLength: ihl,
	}
	if ihl > V4MinHeaderLen {
		h.RawOptions = packet[V4MinHeaderLen:ihl]
	}
	return h, ihl, nil
}

// BuildIPv4 构造完整 IPv4 报文（头 + 负载），自动计算头校验和。
// 不支持选项（仿真终端不产生选项）。
func BuildIPv4(h *IPv4Header, payload []byte) []byte {
	total := V4MinHeaderLen + len(payload)
	out := make([]byte, total)
	out[0] = 0x45 // version 4, IHL 5
	out[v4OffTOS] = h.TOS
	binary.BigEndian.PutUint16(out[v4OffTotalLen:], h.TotalLength)
	binary.BigEndian.PutUint16(out[v4OffID:], h.ID)
	binary.BigEndian.PutUint16(out[v4OffFlagsFrag:], h.FlagsFrag)
	out[v4OffTTL] = h.TTL
	out[v4OffProto] = h.Protocol
	src := h.Src.As4()
	dst := h.Dst.As4()
	copy(out[v4OffSrc:v4OffSrc+4], src[:])
	copy(out[v4OffDst:v4OffDst+4], dst[:])
	csum := Checksum(out[:V4MinHeaderLen])
	binary.BigEndian.PutUint16(out[v4OffChecksum:], csum)
	copy(out[V4MinHeaderLen:], payload)
	return out
}

// IPv6 头固定 40 字节（RFC 8200）。
const (
	V6HeaderLen  = 40
	v6OffVersion = 0
	v6OffTC      = 0 // 流量类别跨字节
	v6OffFlow    = 1
	v6OffLen     = 4
	v6OffNH      = 6
	v6OffHop     = 7
	v6OffSrc     = 8
	v6OffDst     = 24
)

// IPv6Header 是解析后的 IPv6 基本头。本仿真不产生扩展头，
// 遇到扩展头按 nextHeader 链跳过（仅用于识别）。
type IPv6Header struct {
	TrafficClass uint8
	FlowLabel    uint32
	Length       uint16 // 有效载荷长度
	NextHeader   uint8
	HopLimit     uint8
	Src          netip.Addr
	Dst          netip.Addr
}

// ParseIPv6 解析 IPv6 基本头。
func ParseIPv6(packet []byte) (*IPv6Header, error) {
	if len(packet) < V6HeaderLen {
		return nil, errors.New("IPv6 报文短于 40 字节")
	}
	if packet[0]>>4 != 6 {
		return nil, errors.New("版本字段不是 6")
	}
	h := &IPv6Header{
		TrafficClass: (packet[0]&0x0f)<<4 | (packet[1] >> 4),
		FlowLabel:    uint32(packet[1]&0x0f)<<16 | uint32(packet[2])<<8 | uint32(packet[3]),
		Length:       binary.BigEndian.Uint16(packet[v6OffLen:]),
		NextHeader:   packet[v6OffNH],
		HopLimit:     packet[v6OffHop],
		Src:          netip.AddrFrom16([16]byte(packet[v6OffSrc : v6OffSrc+16])),
		Dst:          netip.AddrFrom16([16]byte(packet[v6OffDst : v6OffDst+16])),
	}
	return h, nil
}

// BuildIPv6 构造完整 IPv6 报文（基本头 + 负载）。
func BuildIPv6(h *IPv6Header, payload []byte) []byte {
	out := make([]byte, V6HeaderLen+len(payload))
	out[0] = 0x60 | (h.TrafficClass >> 4)
	out[1] = (h.TrafficClass&0x0f)<<4 | uint8(h.FlowLabel>>16)&0x0f
	out[2] = uint8(h.FlowLabel >> 8)
	out[3] = uint8(h.FlowLabel)
	binary.BigEndian.PutUint16(out[v6OffLen:], h.Length)
	out[v6OffNH] = h.NextHeader
	out[v6OffHop] = h.HopLimit
	src := h.Src.As16()
	dst := h.Dst.As16()
	copy(out[v6OffSrc:v6OffSrc+16], src[:])
	copy(out[v6OffDst:v6OffDst+16], dst[:])
	copy(out[V6HeaderLen:], payload)
	return out
}
