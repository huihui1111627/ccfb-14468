package headers

import (
	"encoding/binary"
	"errors"
)

// ICMPv4 类型（RFC 792）。
const (
	ICMP4EchoReply    = 0
	ICMP4DstUnreach   = 3
	ICMP4Redirect     = 5
	ICMP4EchoRequest  = 8
	ICMP4TimeExceed   = 11
	ICMP4ParamProblem = 12
)

// ICMPv4 目的不可达代码。
const (
	ICMP4NetUnreach      = 0
	ICMP4HostUnreach     = 1
	ICMP4ProtoUnreach    = 2
	ICMP4PortUnreach     = 3
	ICMP4FragNeededDF    = 4
	ICMP4NetProhibited   = 9
	ICMP4HostProhibited  = 10
	ICMP4AdminProhibited = 13
)

// ICMPv6 类型（RFC 4443 / RFC 7915）。
const (
	ICMP6DstUnreach   = 1
	ICMP6PktTooBig    = 2
	ICMP6TimeExceed   = 3
	ICMP6ParamProblem = 4
	ICMP6EchoRequest  = 128
	ICMP6EchoReply    = 129
)

// ICMPv6 目的不可达代码。
const (
	ICMP6NoRoute         = 0
	ICMP6AdminProhibited = 1
	ICMP6BeyondScope     = 2
	ICMP6AddrUnreach     = 3
	ICMP6PortUnreach     = 4
	ICMP6PolicyFail      = 5
	ICMP6RejectRoute     = 6
)

// ICMPv6 超时代码。
const (
	ICMP6HopLimitExceeded = 0
	ICMP6ReassemblyTime   = 1
)

const (
	icmpOffType   = 0
	icmpOffCode   = 1
	icmpOffCsum   = 2
	icmpOffRest   = 4
	icmpHeaderLen = 8 // 通用差错报文前 8 字节
)

// ICMPMessage 是解析后的 ICMP/ICMPv6 报文。
type ICMPMessage struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	// Rest 是类型/代码之后的 4 字节（如 Echo 的 ID/Seq，或差错报文的 MTU 指针）。
	Rest [4]byte
	// Body 是 8 字节通用头之后的全部内容（差错报文里是被引用的原始报文）。
	Body []byte
}

func ParseICMP(b []byte) (*ICMPMessage, error) {
	if len(b) < icmpHeaderLen {
		return nil, errors.New("ICMP 报文短于 8 字节")
	}
	m := &ICMPMessage{
		Type:     b[icmpOffType],
		Code:     b[icmpOffCode],
		Checksum: binary.BigEndian.Uint16(b[icmpOffCsum:]),
		Body:     append([]byte(nil), b[icmpHeaderLen:]...),
	}
	copy(m.Rest[:], b[icmpOffRest:icmpOffRest+4])
	return m, nil
}

// BuildICMP 构造完整 ICMP/ICMPv6 报文，校验和由调用方按协议版本计算
// （ICMPv4 只覆盖报文本身；ICMPv6 还要带 IPv6 伪头部）。
func BuildICMP(m *ICMPMessage) []byte {
	out := make([]byte, icmpHeaderLen+len(m.Body))
	out[icmpOffType] = m.Type
	out[icmpOffCode] = m.Code
	binary.BigEndian.PutUint16(out[icmpOffCsum:], m.Checksum)
	copy(out[icmpOffRest:icmpOffRest+4], m.Rest[:])
	copy(out[icmpHeaderLen:], m.Body)
	return out
}

func ICMPChecksumPos() int { return icmpOffCsum }

// EchoID / EchoSeq 用于 Echo 报文的 Rest 字段。
func EchoID(rest [4]byte) uint16  { return binary.BigEndian.Uint16(rest[0:2]) }
func EchoSeq(rest [4]byte) uint16 { return binary.BigEndian.Uint16(rest[2:4]) }
func SetEchoID(rest *[4]byte, id uint16) {
	binary.BigEndian.PutUint16(rest[0:2], id)
}
func SetEchoSeq(rest *[4]byte, seq uint16) {
	binary.BigEndian.PutUint16(rest[2:4], seq)
}

// MTU 从 Packet Too Big / Frag Needed 的 Rest 字段取 MTU。
func MTU(rest [4]byte) uint32 {
	// ICMPv6 PTB：整个 4 字节即 MTU；
	// ICMPv4 Frag Needed：低 2 字节为 MTU，高 2 字节为 0。
	v := binary.BigEndian.Uint32(rest[:])
	return v
}

// SetMTU 写入 MTU 字段。
func SetMTU(rest *[4]byte, mtu uint32, v6 bool) {
	if v6 {
		binary.BigEndian.PutUint32(rest[:], mtu)
	} else {
		rest[0], rest[1] = 0, 0
		binary.BigEndian.PutUint16(rest[2:4], uint16(mtu))
	}
}
