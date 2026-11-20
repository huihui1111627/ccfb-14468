package translate

import (
	"encoding/binary"
	"net/netip"

	"ivat/pkg/headers"
)

// translateICMPV4ToV6 翻译 ICMPv4 报文。差错报文里套着一份触发差错的
// 原始报文头，必须里外两层都翻译（RFC 7915 §5.2）：
//   - 外层：类型/代码按映射表改，校验和重建，MTU 字段按头长差调整；
//   - 内层：作为完整 IP 报文再走一遍翻译，使地址、协议号、传输端口全部更新，
//     这样终端协议栈收到差错报文后才能把它匹配回自己的 socket。
//
// depth 用于防止嵌套环（实际最多一层）。
func (t *Translator) translateICMPV4ToV6(seg []byte, outer *headers.IPv4Header,
	src6, dst6 netip.Addr, innerMapSrc, innerMapDst AddrMapper) ([]byte, error) {
	msg, err := headers.ParseICMP(seg)
	if err != nil {
		return nil, err
	}
	mapping := mapICMPv4ToV6(msg.Type, msg.Code)
	if mapping.Drop {
		return nil, &ErrDrop{Reason: mapping.Reason}
	}

	// Echo 类：ID/Seq 原样保留（RFC 7915 §6），只改类型、重建校验和。
	if msg.Type == headers.ICMP4EchoRequest || msg.Type == headers.ICMP4EchoReply {
		msg.Type = mapping.Type
		msg.Code = 0
		out := headers.BuildICMP(msg)
		csum := icmpV6Checksum(out, src6, dst6)
		binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], csum)
		return out, nil
	}

	// 差错类：内层引用报文按它自身的地址语义翻译（由调用方注入映射），
	// 使地址、协议号、传输端口全部更新，终端才能把差错匹配回 socket。
	if _, ihl, perr := headers.ParseIPv4(msg.Body); perr == nil && len(msg.Body) >= ihl {
		inner6, ierr := t.V4ToV6(msg.Body, innerMapSrc, innerMapDst)
		if ierr == nil {
			// ICMPv6 差错报文整体不得超过 1280：减去 v6 头(40) 与 ICMP 通用头(8)
			maxInner := 1280 - headers.V6HeaderLen - 8
			if len(inner6) > maxInner {
				inner6 = inner6[:maxInner]
			}
			msg.Body = inner6
		}
	}

	msg.Type = mapping.Type
	msg.Code = mapping.Code

	// MTU 调整（RFC 7915 §5.2.4）：v6 PTB 的 MTU = v4 MTU - 头长差(20)，
	// 且不得小于 IPv6 最小 MTU 1280。
	if mapping.Type == headers.ICMP6PktTooBig {
		mtu := headers.MTU(msg.Rest)
		adjusted := uint32(0)
		if mtu >= headers.V4MinHeaderLen {
			adjusted = mtu - headers.V4MinHeaderLen
		}
		if adjusted < 1280 {
			adjusted = 1280
		}
		headers.SetMTU(&msg.Rest, adjusted, true)
	}

	out := headers.BuildICMP(msg)
	csum := icmpV6Checksum(out, src6, dst6)
	binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], csum)
	return out, nil
}

// translateICMPV6ToV4 是反向翻译，内层报文同样要再翻一次。
func (t *Translator) translateICMPV6ToV4(seg []byte, outer *headers.IPv6Header,
	src4, dst4 netip.Addr, innerMapSrc, innerMapDst AddrMapper) ([]byte, error) {
	msg, err := headers.ParseICMP(seg)
	if err != nil {
		return nil, err
	}
	mapping := mapICMPv6ToV4(msg.Type, msg.Code)
	if mapping.Drop {
		return nil, &ErrDrop{Reason: mapping.Reason}
	}

	if msg.Type == headers.ICMP6EchoRequest || msg.Type == headers.ICMP6EchoReply {
		msg.Type = mapping.Type
		msg.Code = 0
		out := headers.BuildICMP(msg)
		csum := headers.Checksum(out) // ICMPv4 校验和只覆盖报文本身
		binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], csum)
		return out, nil
	}

	// 翻译内层引用报文（v6→v4），映射由调用方按内层地址语义注入。
	if _, perr := headers.ParseIPv6(msg.Body); perr == nil {
		inner4, ierr := t.V6ToV4(msg.Body, innerMapSrc, innerMapDst)
		if ierr == nil {
			// ICMPv4 差错报文内层最长 576 字节（RFC 1812 建议），
			// 但至少保留到传输层端口，便于 socket 匹配。
			if len(inner4) > 576 {
				inner4 = inner4[:576]
			}
			msg.Body = inner4
		}
	}

	msg.Type = mapping.Type
	msg.Code = mapping.Code

	if msg.Type == headers.ICMP4DstUnreach && msg.Code == headers.ICMP4FragNeededDF {
		// v6 PTB MTU 是 v6 负载口径；v4 MTU 含 20 字节 v4 头，加回去。
		mtu := headers.MTU(msg.Rest)
		adjusted := mtu + headers.V4MinHeaderLen
		if adjusted > uint32(t.cfg.V4MTU) {
			adjusted = uint32(t.cfg.V4MTU)
		}
		headers.SetMTU(&msg.Rest, adjusted, false)
	}

	out := headers.BuildICMP(msg)
	csum := headers.Checksum(out)
	binary.BigEndian.PutUint16(out[headers.ICMPChecksumPos():], csum)
	return out, nil
}

// icmpV6Checksum 计算带 IPv6 伪头部的 ICMPv6 校验和（RFC 4443 §2.3）。
func icmpV6Checksum(msg []byte, src6, dst6 netip.Addr) uint16 {
	pseudo := headers.PseudoHeaderV6(src6.As16(), dst6.As16(), headers.ProtoICMPv6, len(msg))
	return headers.TransportChecksum(pseudo, msg, headers.ICMPChecksumPos())
}
