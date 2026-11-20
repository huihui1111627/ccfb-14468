// Package headers 提供 IPv4/IPv6/ICMP/ICMPv6/TCP/UDP 原始报文头的
// 解析、构造与校验和工具。所有整数在报文上均为网络字节序（大端）。
package headers

import (
	"encoding/binary"
)

// Checksum 计算 RFC 1071 网际校验和（输入按 16 位字求和取反码）。
// odd 个字节时末尾补 0。
func Checksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n&1 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// PseudoSum 对一段数据连同伪头部各 16 位字做反码和，
// 返回的是"和"（未取反），便于多个来源拼接。
func PseudoSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)&1 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// FoldSum 把 32 位反码和折叠成 16 位并取反，得到校验和。
func FoldSum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// PseudoHeaderV4 构造 IPv4 传输层校验和的伪头部：
// src(4) | dst(4) | 0 | proto | TCP/UDP 长度。
func PseudoHeaderV4(src, dst [4]byte, proto uint8, transportLen int) []byte {
	b := make([]byte, 12)
	copy(b[0:4], src[:])
	copy(b[4:8], dst[:])
	b[9] = proto
	binary.BigEndian.PutUint16(b[10:12], uint16(transportLen))
	return b
}

// PseudoHeaderV6 构造 IPv6 传输层校验和的伪头部：
// src(16) | dst(16) | 长度 | 下一首部。
func PseudoHeaderV6(src, dst [16]byte, nextHeader uint8, transportLen int) []byte {
	b := make([]byte, 40)
	copy(b[0:16], src[:])
	copy(b[16:32], dst[:])
	binary.BigEndian.PutUint32(b[32:36], uint32(transportLen))
	b[39] = nextHeader
	return b
}

// TransportChecksum 重新计算 TCP/UDP 校验和（v4/v6 通用）。
// transport 包含完整传输层段（含头与数据），checksumPos 指向校验和字段，
// 计算时该字段按 0 处理。
func TransportChecksum(pseudo, transport []byte, checksumPos int) uint16 {
	sum := PseudoSum(pseudo)
	saved := binary.BigEndian.Uint16(transport[checksumPos:])
	binary.BigEndian.PutUint16(transport[checksumPos:], 0)
	sum += PseudoSum(transport)
	binary.BigEndian.PutUint16(transport[checksumPos:], saved)
	return FoldSum(sum)
}

// UpdateChecksum16 按 RFC 1624 增量更新校验和：
// 地址变化时只需用旧值和新旧 16 位字之差调整，不必重扫整个报文。
// oldWords/newWords 是变化字段按 16 位字的反码和（未取反）。
func UpdateChecksum16(oldChecksum uint16, oldWords, newWords uint32) uint16 {
	// RFC 1624 式(3)：HC' = ~(~HC + ~m + m')，其中 m/m' 是旧/新字段的折叠和。
	oldFolded := fold32(oldWords)
	newFolded := fold32(newWords)
	sum := uint32(^oldChecksum) + uint32(^oldFolded) + uint32(newFolded)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func fold32(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// SumWords16 对任意字节切片求 16 位字反码和（未取反）。
func SumWords16(b []byte) uint32 { return PseudoSum(b) }
