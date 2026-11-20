package translate

import (
	"encoding/binary"
	"net/netip"

	"ivat/pkg/headers"
)

// IPv6 分片扩展头（RFC 8200 §4.5）固定 8 字节：
//
//	NextHeader(1) | Reserved(1) | Offset(13b)+Res(2b)+M(1b) | Identification(4)
const (
	v6FragHeaderLen = 8
	v6FragOffM      = 0x00000001
	v6FragOffShift  = 3
)

// v4FragmentToV6 处理带偏移或 MF 的非原子 IPv4 分片（RFC 7915 §3.2）。
//
// 仿真终端默认只发 DF 原子报文，这里仍给出完整实现以便路径上的异常输入
// 也能被正确翻译：
//   - v4 的 16 位分片 ID 映射到 v6 分片 ID 的低 16 位（高 16 位置 0）；
//   - 13 位分片偏移两协议定义相同，逐位保留，M 位保留；
//   - 插入分片扩展头，NextHeader 链指向真实传输协议。
func (t *Translator) v4FragmentToV6(h *headers.IPv4Header, payload []byte,
	src6, dst6 netip.Addr) ([]byte, error) {
	realNH, ok := protoV4ToV6(h.Protocol)
	if !ok {
		return nil, &ErrDrop{Reason: "分片报文协议号无法映射"}
	}
	frag := make([]byte, v6FragHeaderLen)
	frag[0] = realNH
	frag[1] = 0
	offM := uint32(h.FragOffset()) << v6FragOffShift
	if h.MF() {
		offM |= v6FragOffM
	}
	binary.BigEndian.PutUint32(frag[2:6], offM)
	// v4 ID 只有 16 位，放在 v6 32 位 ID 的低半。
	binary.BigEndian.PutUint32(frag[4:8], uint32(h.ID))

	newPayload := make([]byte, v6FragHeaderLen+len(payload))
	copy(newPayload, frag)
	copy(newPayload[v6FragHeaderLen:], payload)

	v6 := &headers.IPv6Header{
		TrafficClass: h.TOS,
		Length:       uint16(len(newPayload)),
		NextHeader:   44, // 分片扩展头协议号
		HopLimit:     decrement8(h.TTL, t.cfg.TTLDelta),
		Src:          src6,
		Dst:          dst6,
	}
	return headers.BuildIPv6(v6, newPayload), nil
}

// V6FragmentToV4 供 V6ToV4 路径在检测到分片扩展头时调用。
// 本仿真的 v6 侧不主动产生分片（PTB 驱动源端收缩），
// 该函数保证外部输入的 v6 分片仍可翻译成等价 v4 分片。
func (t *Translator) V6FragmentToV4(packet []byte, mapSrc, mapDst AddrMapper) ([]byte, error) {
	h, err := headers.ParseIPv6(packet)
	if err != nil || h.NextHeader != 44 {
		return nil, &ErrDrop{Reason: "不是 v6 分片报文"}
	}
	payload := packet[headers.V6HeaderLen:]
	if len(payload) < v6FragHeaderLen {
		return nil, &ErrDrop{Reason: "v6 分片头不完整"}
	}
	realProto := payload[0]
	offM := binary.BigEndian.Uint32(payload[2:6])
	id := binary.BigEndian.Uint32(payload[4:8])
	fragPayload := payload[v6FragHeaderLen:]

	src4, ok := mapSrc(h.Src)
	if !ok {
		return nil, &ErrDrop{Reason: "源 IPv6 不在翻译域内"}
	}
	dst4, ok := mapDst(h.Dst)
	if !ok {
		return nil, &ErrDrop{Reason: "目的 IPv6 不在翻译域内"}
	}
	proto, ok := protoV6ToV4(realProto)
	if !ok {
		return nil, &ErrDrop{Reason: "分片内层协议无法映射"}
	}

	var flagsFrag uint16
	off := uint16(offM >> v6FragOffShift)
	flagsFrag |= off & headers.V4FragOffMask
	if offM&v6FragOffM != 0 {
		flagsFrag |= headers.V4FlagMF
	}
	// v6 分片来自源端分片，翻译后允许 v4 网络分片，DF 不置位。

	v4 := &headers.IPv4Header{
		TOS:         h.TrafficClass,
		TotalLength: uint16(headers.V4MinHeaderLen + len(fragPayload)),
		ID:          uint16(id), // 取低 16 位
		FlagsFrag:   flagsFrag,
		TTL:         decrement8(h.HopLimit, t.cfg.TTLDelta),
		Protocol:    proto,
		Src:         src4,
		Dst:         dst4,
	}
	return headers.BuildIPv4(v4, fragPayload), nil
}

// HandleFragment 是供 V6ToV4 主流程使用的分片分派入口。
func (t *Translator) HandleFragment(packet []byte, mapSrc, mapDst AddrMapper) ([]byte, bool, error) {
	h, err := headers.ParseIPv6(packet)
	if err != nil {
		return nil, false, err
	}
	if h.NextHeader == 44 {
		out, err := t.V6FragmentToV4(packet, mapSrc, mapDst)
		return out, true, err
	}
	return nil, false, nil
}
