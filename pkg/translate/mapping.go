package translate

import (
	"ivat/pkg/headers"
)

// translateProto 实现 RFC 7915 §3.3 的协议号映射。
// TCP(6)、UDP(17) 逐字保留；ICMPv4(1) 翻译成 ICMPv6(58)，反之亦然。
// 其余协议号在两个地址族中含义一致（如 SCTP 132、GRE 47），原样保留。
func protoV4ToV6(proto uint8) (uint8, bool) {
	switch proto {
	case headers.ProtoICMPv4:
		return headers.ProtoICMPv6, true
	case headers.ProtoICMPv6:
		return 0, false // v4 侧不可能出现 ICMPv6
	default:
		return proto, true
	}
}

func protoV6ToV4(nh uint8) (uint8, bool) {
	switch nh {
	case headers.ProtoICMPv6:
		return headers.ProtoICMPv4, true
	case headers.ProtoICMPv4:
		return 0, false
	default:
		return nh, true
	}
}

// ICMPMapping 是一条 ICMP 类型/代码的翻译结果。
type ICMPMapping struct {
	Type   uint8
	Code   uint8
	Drop   bool // 该类型在目标地址族没有对应物，丢弃
	Reason string
}

// mapICMPv4ToV6 按 RFC 7915 §4.3 / §5 的表把 ICMPv4 差错报文映射到 ICMPv6。
// 第二个返回值为 true 表示该类型无对应物，必须丢弃（如 Redirect、源抑制）。
func mapICMPv4ToV6(typ, code uint8) ICMPMapping {
	switch typ {
	case headers.ICMP4EchoRequest:
		return ICMPMapping{Type: headers.ICMP6EchoRequest, Code: 0}
	case headers.ICMP4EchoReply:
		return ICMPMapping{Type: headers.ICMP6EchoReply, Code: 0}
	case headers.ICMP4DstUnreach:
		switch code {
		case headers.ICMP4NetUnreach, headers.ICMP4HostUnreach,
			headers.ICMP4NetProhibited, headers.ICMP4HostProhibited,
			headers.ICMP4AdminProhibited:
			// 网络/主机不可达与管理禁止统一落到 NoRoute / AdminProhibited
			if code == headers.ICMP4AdminProhibited ||
				code == headers.ICMP4NetProhibited || code == headers.ICMP4HostProhibited {
				return ICMPMapping{Type: headers.ICMP6DstUnreach, Code: headers.ICMP6AdminProhibited}
			}
			return ICMPMapping{Type: headers.ICMP6DstUnreach, Code: headers.ICMP6NoRoute}
		case headers.ICMP4ProtoUnreach:
			// IPv6 没有"协议不可达"，按 RFC 7915 映射为参数问题（下一首部类型不可识别）
			return ICMPMapping{Type: headers.ICMP6ParamProblem, Code: 1}
		case headers.ICMP4PortUnreach:
			return ICMPMapping{Type: headers.ICMP6DstUnreach, Code: headers.ICMP6PortUnreach}
		case headers.ICMP4FragNeededDF:
			// 需要分片且 DF 置位 → IPv6 的 Packet Too Big
			return ICMPMapping{Type: headers.ICMP6PktTooBig, Code: 0}
		default:
			return ICMPMapping{Type: headers.ICMP6DstUnreach, Code: headers.ICMP6NoRoute}
		}
	case headers.ICMP4TimeExceed:
		// 0=TTL 超时 → 跳数限制超时；1=重组超时，v6 同码
		mapped := uint8(headers.ICMP6HopLimitExceeded)
		if code == 1 {
			mapped = headers.ICMP6ReassemblyTime
		}
		return ICMPMapping{Type: headers.ICMP6TimeExceed, Code: mapped}
	case headers.ICMP4ParamProblem:
		// 参数问题整体映射；指针字段需要按头布局重定位（本仿真只处理指针=0 的常见情形）
		return ICMPMapping{Type: headers.ICMP6ParamProblem, Code: 0}
	case headers.ICMP4Redirect:
		// RFC 7915 明确：ICMPv4 Redirect 在 IPv6 语义不对应，丢弃
		return ICMPMapping{Drop: true, Reason: "ICMPv4 Redirect 在 IPv6 无对应类型"}
	default:
		// 未知/信息类（如源抑制、时间戳）无对应物，丢弃
		return ICMPMapping{Drop: true, Reason: "ICMPv4 类型在 ICMPv6 中无对应物"}
	}
}

// mapICMPv6ToV4 是反向映射。
func mapICMPv6ToV4(typ, code uint8) ICMPMapping {
	switch typ {
	case headers.ICMP6EchoRequest:
		return ICMPMapping{Type: headers.ICMP4EchoRequest, Code: 0}
	case headers.ICMP6EchoReply:
		return ICMPMapping{Type: headers.ICMP4EchoReply, Code: 0}
	case headers.ICMP6DstUnreach:
		switch code {
		case headers.ICMP6NoRoute:
			return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4HostUnreach}
		case headers.ICMP6AdminProhibited, headers.ICMP6PolicyFail, headers.ICMP6RejectRoute:
			return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4AdminProhibited}
		case headers.ICMP6BeyondScope:
			return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4HostUnreach}
		case headers.ICMP6AddrUnreach:
			return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4HostUnreach}
		case headers.ICMP6PortUnreach:
			return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4PortUnreach}
		default:
			return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4HostUnreach}
		}
	case headers.ICMP6PktTooBig:
		// Packet Too Big → 需要分片且 DF 置位（代码 4）
		return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4FragNeededDF}
	case headers.ICMP6TimeExceed:
		mapped := uint8(0)
		if code == headers.ICMP6ReassemblyTime {
			mapped = 1
		}
		return ICMPMapping{Type: headers.ICMP4TimeExceed, Code: mapped}
	case headers.ICMP6ParamProblem:
		// RFC 7915：v6 参数问题反向没有稳定对应物（代码 1 还原为协议不可达，其余丢弃）
		if code == 1 {
			return ICMPMapping{Type: headers.ICMP4DstUnreach, Code: headers.ICMP4ProtoUnreach}
		}
		return ICMPMapping{Drop: true, Reason: "ICMPv6 参数问题（代码0/2）在 ICMPv4 无稳定对应物"}
	default:
		return ICMPMapping{Drop: true, Reason: "ICMPv6 类型在 ICMPv4 中无对应物"}
	}
}
