package headers

import (
	"encoding/binary"
	"errors"
)

// 传输层端口字段偏移（TCP/UDP 头两个字节一致）。
const (
	OffSrcPort = 0
	OffDstPort = 2
)

// UDP 头固定 8 字节（RFC 768）。
const (
	UDPLen     = 8
	udpOffLen  = 4
	udpOffCsum = 6
)

// UDPHeader 是解析后的 UDP 头。
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func ParseUDP(b []byte) (*UDPHeader, error) {
	if len(b) < UDPLen {
		return nil, errors.New("UDP 段短于 8 字节")
	}
	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(b[OffSrcPort:]),
		DstPort:  binary.BigEndian.Uint16(b[OffDstPort:]),
		Length:   binary.BigEndian.Uint16(b[udpOffLen:]),
		Checksum: binary.BigEndian.Uint16(b[udpOffCsum:]),
	}, nil
}

// BuildUDP 把 UDP 头与 payload 拼成完整段。
func BuildUDP(h *UDPHeader, payload []byte) []byte {
	out := make([]byte, UDPLen+len(payload))
	binary.BigEndian.PutUint16(out[OffSrcPort:], h.SrcPort)
	binary.BigEndian.PutUint16(out[OffDstPort:], h.DstPort)
	binary.BigEndian.PutUint16(out[udpOffLen:], h.Length)
	binary.BigEndian.PutUint16(out[udpOffCsum:], h.Checksum)
	copy(out[UDPLen:], payload)
	return out
}

// UDPChecksumPos 返回校验和字段在段内的偏移。
func UDPChecksumPos() int { return udpOffCsum }

// TCP 头最小 20 字节（RFC 9293）。
const (
	TCPMinLen     = 20
	tcpOffSeq     = 4
	tcpOffAck     = 8
	tcpOffDataOff = 12
	tcpOffFlags   = 13
	tcpOffWindow  = 14
	tcpOffCsum    = 16
	tcpOffUrg     = 18
)

// TCP 标志位。
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// TCPHeader 是解析后的 TCP 头（选项原样保留）。
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8 // 头长度（字节）
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	RawOptions []byte
}

func ParseTCP(b []byte) (*TCPHeader, error) {
	if len(b) < TCPMinLen {
		return nil, errors.New("TCP 段短于 20 字节")
	}
	do := int(b[tcpOffDataOff]>>4) * 4
	if do < TCPMinLen || do > len(b) {
		return nil, errors.New("TCP 数据偏移非法")
	}
	h := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(b[OffSrcPort:]),
		DstPort:    binary.BigEndian.Uint16(b[OffDstPort:]),
		Seq:        binary.BigEndian.Uint32(b[tcpOffSeq:]),
		Ack:        binary.BigEndian.Uint32(b[tcpOffAck:]),
		DataOffset: uint8(do),
		Flags:      b[tcpOffFlags],
		Window:     binary.BigEndian.Uint16(b[tcpOffWindow:]),
		Checksum:   binary.BigEndian.Uint16(b[tcpOffCsum:]),
		Urgent:     binary.BigEndian.Uint16(b[tcpOffUrg:]),
	}
	if do > TCPMinLen {
		h.RawOptions = b[TCPMinLen:do]
	}
	return h, nil
}

// BuildTCP 构造完整 TCP 段。
func BuildTCP(h *TCPHeader, payload []byte) []byte {
	do := int(h.DataOffset)
	if do == 0 {
		do = TCPMinLen
	}
	out := make([]byte, do+len(payload))
	binary.BigEndian.PutUint16(out[OffSrcPort:], h.SrcPort)
	binary.BigEndian.PutUint16(out[OffDstPort:], h.DstPort)
	binary.BigEndian.PutUint32(out[tcpOffSeq:], h.Seq)
	binary.BigEndian.PutUint32(out[tcpOffAck:], h.Ack)
	out[tcpOffDataOff] = uint8(do/4) << 4
	out[tcpOffFlags] = h.Flags
	binary.BigEndian.PutUint16(out[tcpOffWindow:], h.Window)
	binary.BigEndian.PutUint16(out[tcpOffCsum:], h.Checksum)
	binary.BigEndian.PutUint16(out[tcpOffUrg:], h.Urgent)
	copy(out[TCPMinLen:do], h.RawOptions)
	copy(out[do:], payload)
	return out
}

func TCPChecksumPos() int { return tcpOffCsum }
