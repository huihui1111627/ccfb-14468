// Command sim 是无状态地址族转换方案的验收程序：
// 在仿真网络上跑 UDP/TCP/ICMP/PMTU/同域互访等应用流量，
// 逐项核对内容一致性、端口集归属与不相交、差错报文与 traceroute、
// 封装/翻译两种模式，并给出一个公网 v4 地址承载户数的统计。
package main

import (
	"flag"
	"fmt"
	"os"

	"ivat/cmd/sim/acceptance"
)

func main() {
	mode := flag.String("mode", "all", "运行模式: mapt | mape | all")
	shared := flag.Int("shared", 4, "仿真使用的共享公网 v4 地址数")
	perV4 := flag.Int("per-v4", 16, "每个 v4 地址挂的户数")
	psidLen := flag.Int("psid-len", 6, "PSID 位数 k（决定每地址户数=2^k）")
	psidOffset := flag.Int("psid-offset", 6, "PSID 偏移 a（6 时跳过知名端口段）")
	hosts := flag.Int("hosts-per-ce", 2, "每户 LAN 内终端数（验证户内 NAPT44）")
	neutral := flag.Bool("checksum-neutral", true, "是否采用校验和中立地址布局")
	flag.Parse()

	cfg := acceptance.Config{
		SharedV4Count:   *shared,
		CEPerV4:         *perV4,
		PSIDLen:         *psidLen,
		PSIDOffset:      *psidOffset,
		ChecksumNeutral: *neutral,
		HostsPerCE:      *hosts,
		V6LinkMTU:       1400,
		V4LinkMTU:       1500,
	}
	modes := []string{"mapt", "mape"}
	if *mode != "all" {
		modes = []string{*mode}
	}
	fail := 0
	for _, m := range modes {
		cfg.Mode = m
		report, err := acceptance.Run(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "模式 %s 装配失败: %v\n", m, err)
			fail++
			continue
		}
		fmt.Print(report.String())
		if !report.AllPassed() {
			fail++
		}
	}
	if fail > 0 {
		fmt.Printf("❌ %d 个模式存在验收失败项\n", fail)
		os.Exit(1)
	}
	fmt.Println("✅ 全部验收项通过")
}
