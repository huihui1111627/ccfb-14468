package headers

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestChecksumSelfConsistent(t *testing.T) {
	// 自洽性：对数据求校验和后，把校验和两字节接到数据末尾，
	// 接收方对「数据 + 校验和」整体再算必为 0（RFC 1071 校验规则）。
	data := []byte("1234567890") // 偶数字节
	csum := Checksum(data)
	withSum := make([]byte, 0, len(data)+2)
	withSum = append(withSum, data...)
	withSum = append(withSum, byte(csum>>8), byte(csum))
	if got := Checksum(withSum); got != 0 {
		t.Fatalf("含校验和的整体校验和应为 0，实际 %#x", got)
	}
}

func TestChecksumOddLengthPadsZero(t *testing.T) {
	// 奇数字节按末尾补 0 处理，结果应与显式补 0 相同。
	odd := []byte("123456789")
	even := append([]byte("123456789"), 0)
	if Checksum(odd) != Checksum(even) {
		t.Fatal("奇数字节未按补 0 规则处理")
	}
}

func TestIncrementalUpdateMatchesFullRecompute(t *testing.T) {
	src4 := netip.MustParseAddr("192.0.2.1")
	dst4 := netip.MustParseAddr("198.51.100.10")
	src6 := netip.MustParseAddr("2001:db8:ffff::1")
	dst6 := netip.MustParseAddr("64:ff9b::c633:640a")

	seg := BuildUDP(&UDPHeader{SrcPort: 5000, DstPort: 8000, Length: 13}, []byte("abcde"))
	oldPseudo := PseudoHeaderV4(src4.As4(), dst4.As4(), ProtoUDP, len(seg))
	oldCsum := TransportChecksum(oldPseudo, seg, UDPChecksumPos())
	binary.BigEndian.PutUint16(seg[UDPChecksumPos():], oldCsum)

	newPseudo := PseudoHeaderV6(src6.As16(), dst6.As16(), ProtoUDP, len(seg))
	// 增量更新
	inc := UpdateChecksum16(oldCsum, SumWords16(oldPseudo), SumWords16(newPseudo))
	// 完整重算
	full := TransportChecksum(newPseudo, seg, UDPChecksumPos())
	if inc != full {
		t.Fatalf("增量校验和 %#x 与重算 %#x 不一致", inc, full)
	}
}

func TestPseudoHeaderLengths(t *testing.T) {
	if got := len(PseudoHeaderV4([4]byte{}, [4]byte{}, ProtoTCP, 100)); got != 12 {
		t.Fatalf("v4 伪头部长度 %d", got)
	}
	if got := len(PseudoHeaderV6([16]byte{}, [16]byte{}, ProtoTCP, 100)); got != 40 {
		t.Fatalf("v6 伪头部长度 %d", got)
	}
}
