package maprule

import (
	"net/netip"
	"testing"
)

func testRule(t *testing.T, neutral bool) *Rule {
	r := &Rule{
		RuleIPv4Prefix:  netip.MustParsePrefix("192.0.2.0/29"),
		EALen:           3 + 6, // 3 位 v4 后缀 + 6 位 PSID
		PSIDOffset:      6,
		PSIDLen:         6,
		ChecksumNeutral: neutral,
		DomainID:        1,
		Name:            "test",
	}
	if neutral {
		r.RuleIPv6Prefix = netip.MustParsePrefix("64:ff9b::/64")
	} else {
		r.RuleIPv6Prefix = netip.MustParsePrefix("2001:db8:ffff::/64")
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("规则校验失败: %v", err)
	}
	return r
}

func TestPortSetSkipsWellKnown(t *testing.T) {
	for _, psid := range []uint16{0, 1, 17, 63} {
		set, err := ExpandPortSet(psid, 6, 6)
		if err != nil {
			t.Fatal(err)
		}
		if len(set) == 0 {
			t.Fatalf("PSID %d 端口集为空", psid)
		}
		for _, p := range set {
			if p < WellKnownPortBoundary {
				t.Fatalf("PSID %d 端口集含知名端口 %d", psid, p)
			}
			got, _ := (&Rule{PSIDOffset: 6, PSIDLen: 6}).PSIDFromPort(p)
			if got != psid {
				t.Fatalf("端口 %d 反解 PSID=%d，期望 %d", p, got, psid)
			}
		}
	}
}

func TestPortSetsDisjoint(t *testing.T) {
	seen := map[uint16]uint16{} // port -> 第一个声明它的 PSID
	for psid := 0; psid < 64; psid++ {
		set, err := ExpandPortSet(uint16(psid), 6, 6)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range set {
			if owner, clash := seen[p]; clash {
				t.Fatalf("端口 %d 同时属于 PSID %d 和 %d", p, owner, psid)
			}
			seen[p] = uint16(psid)
		}
	}
	// k=a=6 时 64 个端口集恰好覆盖 1024..65535 全部端口（每户 1008 个）
	if len(seen) != 65536-1024 {
		t.Fatalf("覆盖端口数 %d，期望 %d", len(seen), 65536-1024)
	}
}

func TestRFC7597Example(t *testing.T) {
	// RFC 7597 §5.1.1 公式：P = i·16 + 7；i=1,2 → 1031、1047。
	set, err := ExpandPortSet(7, 6, 4)
	if err != nil {
		t.Fatal(err)
	}
	if set[0] != 1031 || set[1] != 1047 {
		t.Fatalf("RFC 示例端口不符: %d,%d", set[0], set[1])
	}
	r := &Rule{PSIDOffset: 6, PSIDLen: 4}
	if p, _ := r.PSIDFromPort(1031); p != 7 {
		t.Fatalf("1031 反解 PSID=%d，期望 7", p)
	}
}

func TestPortSetFormulaSmallOffset(t *testing.T) {
	// offset=4 时 j=1 会产生 16..31 的端口，必须被知名端口过滤剔除
	set, err := ExpandPortSet(1, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range set {
		if p < WellKnownPortBoundary {
			t.Fatalf("小 offset 下漏放知名端口 %d", p)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, neutral := range []bool{false, true} {
		r := testRule(t, neutral)
		v4 := netip.MustParseAddr("192.0.2.5")
		for _, psid := range []uint16{0, 1, 33, 63} {
			v6, err := r.EncodeIPv6(v4, psid)
			if err != nil {
				t.Fatal(err)
			}
			gotV4, gotPSID, ok := r.DecodeIPv6(v6)
			if !ok {
				t.Fatalf("neutral=%v: 解码失败 %s", neutral, v6)
			}
			if gotV4 != v4 || gotPSID != psid {
				t.Fatalf("neutral=%v: 往返不一致 (%s,%d)!=(%s,%d)",
					neutral, gotV4, gotPSID, v4, psid)
			}
		}
	}
}

func TestBRStatelessResolve(t *testing.T) {
	r := testRule(t, false)
	v4 := netip.MustParseAddr("192.0.2.2")
	psid := uint16(21)
	v6, err := r.EncodeIPv6(v4, psid)
	if err != nil {
		t.Fatal(err)
	}
	// 取该户端口集任一端口，BR 仅凭规则从 (v4, port) 反算
	set, _ := r.Expand(psid)
	for _, port := range set {
		got, gotPSID, err := r.ResolveV4ToV6(v4, port)
		if err != nil {
			t.Fatal(err)
		}
		if got != v6 || gotPSID != psid {
			t.Fatalf("BR 反算错误: %s != %s", got, v6)
		}
	}
}

func TestSubscriberCount(t *testing.T) {
	r := testRule(t, false)
	subs, err := EnumerateSubscribers(r)
	if err != nil {
		t.Fatal(err)
	}
	// /29 → 8 个 v4 地址，每地址 64 户 = 512 户
	if len(subs) != 8*64 {
		t.Fatalf("户数 %d，期望 512", len(subs))
	}
	if got := SubscribersPerIPv4(r); got != 64 {
		t.Fatalf("每地址户数 %d，期望 64", got)
	}
	// k=a=6：每户 (65536-1024)/64 = 1008 个端口
	if got := PortsPerSubscriber(r); got != (65536-1024)/64 {
		t.Fatalf("每户端口数 %d，期望 %d", got, (65536-1024)/64)
	}
}

func TestCountyScale(t *testing.T) {
	// 全县 200 个公网 v4 地址、PSIDLen=10 → 每地址 1024 户
	r := &Rule{
		RuleIPv6Prefix:  netip.MustParsePrefix("2001:db8:ffff::/64"),
		RuleIPv4Prefix:  netip.MustParsePrefix("198.51.0.0/24"),
		EALen:           8 + 10,
		PSIDOffset:      6,
		PSIDLen:         10,
		ChecksumNeutral: false,
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	subs, _ := EnumerateSubscribers(r)
	// /24 有 256 地址；取其中 200 个即 200*1024=204800 户，超过十万用户/台设备的规模
	if got := SubscribersPerIPv4(r); got != 1024 {
		t.Fatalf("每地址户数 %d，期望 1024", got)
	}
	if len(subs) != 256*1024 {
		t.Fatalf("总承载 %d 户", len(subs))
	}
	set, _ := r.Expand(777)
	for _, p := range set {
		if p < WellKnownPortBoundary {
			t.Fatal("端口集含知名端口")
		}
	}
}
