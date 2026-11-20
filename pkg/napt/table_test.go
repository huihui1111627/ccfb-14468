package napt

import (
	"testing"
)

func TestNAPTAllocatesOnlyWithinPortSet(t *testing.T) {
	set := []uint16{2000, 3000, 4000}
	tab := NewTable(set)
	ip := [4]byte{10, 0, 0, 1}
	remote := [4]byte{198, 51, 100, 10}

	m1, err := tab.Allocate(ProtoUDP, ip, 5000, remote, 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := tab.AssertPortInSet(m1.ExternalPt); err != nil {
		t.Fatalf("外部端口不在端口集: %v", err)
	}
	// 同一五元组再分配应复用同一映射
	m1b, _ := tab.Allocate(ProtoUDP, ip, 5000, remote, 80)
	if m1b.ExternalPt != m1.ExternalPt {
		t.Fatal("相同五元组未复用外部端口")
	}
	// 不同内部连接分配不同外部端口
	m2, _ := tab.Allocate(ProtoUDP, ip, 5001, remote, 80)
	if m2.ExternalPt == m1.ExternalPt {
		t.Fatal("不同连接分到相同外部端口")
	}
	// 入向反查
	back, err := tab.LookupInbound(ProtoUDP, m1.ExternalPt, remote, 80)
	if err != nil || back.InternalPt != 5000 {
		t.Fatalf("入向反查失败: %v", err)
	}
	// 端点无关回退：对端不匹配时仍能按外部端口找到
	if _, ok := tab.LookupByExternal(ProtoUDP, m1.ExternalPt); !ok {
		t.Fatal("外部端口直查失败")
	}
}

func TestNAPTPortExhaustion(t *testing.T) {
	tab := NewTable([]uint16{2000}) // 只有一个外部端口
	ip := [4]byte{10, 0, 0, 1}
	remote := [4]byte{1, 2, 3, 4}
	if _, err := tab.Allocate(ProtoTCP, ip, 1000, remote, 80); err != nil {
		t.Fatal(err)
	}
	if _, err := tab.Allocate(ProtoTCP, ip, 1001, remote, 80); err != ErrNoPort {
		t.Fatalf("端口耗尽应返回 ErrNoPort，实际 %v", err)
	}
}

func TestNAPTReleaseReclaimsPort(t *testing.T) {
	tab := NewTable([]uint16{2000})
	ip := [4]byte{10, 0, 0, 1}
	remote := [4]byte{1, 2, 3, 4}
	m, _ := tab.Allocate(ProtoUDP, ip, 1000, remote, 80)
	tab.Release(m)
	if _, err := tab.Allocate(ProtoUDP, ip, 1001, remote, 80); err != nil {
		t.Fatalf("释放后端口应可再分配: %v", err)
	}
}
