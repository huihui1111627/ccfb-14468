// Package encap 实现 MAP-E 封装模式（RFC 7597 §5.4）：
// 户内 IPv4 报文不加翻译，整体作为 IPv6 单播报文的负载封装进骨干；
// 对端 CE（同域互访）或 BR（出域）解封装后再处理。
//
// 与翻译模式（MAP-T）共用同一套 maprule 地址编码，因此 BR 同样无状态：
// 从外层 IPv6 目的地址即可解出目的户的 IPv4 与 PSID。
package encap

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"ivat/pkg/headers"
)

// Encap 把完整 IPv4 报文封装进 IPv6（proto=41）。
// outerSrc/outerDst 是由 maprule 算出的隧道端点 IPv6 地址。
func Encap(v4Packet []byte, outerSrc, outerDst netip.Addr, hopLimit uint8) ([]byte, error) {
	if len(v4Packet) < headers.V4MinHeaderLen {
		return nil, errors.New("待封装报文不是合法 IPv4 报文")
	}
	h, _, err := headers.ParseIPv4(v4Packet)
	if err != nil {
		return nil, err
	}
	v6 := &headers.IPv6Header{
		TrafficClass: h.TOS, // 外层沿用内层 DSCP/ECN
		FlowLabel:    0,
		Length:       uint16(len(v4Packet)),
		NextHeader:   41, // IPv6 封装 IPv4 的协议号
		HopLimit:     hopLimit,
		Src:          outerSrc,
		Dst:          outerDst,
	}
	return headers.BuildIPv6(v6, v4Packet), nil
}

// Decap 解封装：校验外层 NextHeader=41，返回内层 IPv4 报文。
func Decap(v6Packet []byte) ([]byte, *headers.IPv6Header, error) {
	h, err := headers.ParseIPv6(v6Packet)
	if err != nil {
		return nil, nil, err
	}
	if h.NextHeader != 41 {
		return nil, nil, errors.New("NextHeader 不是 41，非 MAP-E 封装报文")
	}
	inner := v6Packet[headers.V6HeaderLen:]
	if len(inner) < headers.V4MinHeaderLen {
		return nil, nil, errors.New("封装负载短于 IPv4 最小头长")
	}
	if _, _, err := headers.ParseIPv4(inner); err != nil {
		return nil, nil, err
	}
	return inner, h, nil
}

// IsEncap 判断报文是否为 MAP-E 封装。
func IsEncap(v6Packet []byte) bool {
	if len(v6Packet) <= headers.V6HeaderLen {
		return false
	}
	return v6Packet[6] == 41
}

// FragmentID 按 RFC 7597 §5.4.2 从内层 IPv4 头派生封装分片标识，
// 使隧道分片在对端可还原。本仿真骨干不产生分片，保留接口完整性。
func FragmentID(innerV4 []byte) uint32 {
	if len(innerV4) < headers.V4MinHeaderLen {
		return 0
	}
	id16 := binary.BigEndian.Uint16(innerV4[4:6])
	return uint32(id16)
}
