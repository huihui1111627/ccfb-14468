# 广电县网 IPv4↔IPv6 无状态地址族转换仿真

面向「骨干已升级 IPv6、户内机顶盒/老电视仅支持 IPv4、全县公网 IPv4 地址仅 200 余个、
集中式转换设备表项一满全县断播」场景的无状态转换方案，基于 **MAP-T（RFC 7599/7915，翻译模式）**
与 **MAP-E（RFC 7597，封装模式）** 思想用 Go 实现，并提供完整网络/终端仿真与验收。

## 核心设计：边界设备为什么不会再"表满"

集中式 NAT64/NAT44 为每条连接保存一条状态，十万户集中在一台设备上，表项耗尽即全网故障。
本方案把映射从「查表」变为「算数」：

- 一个公网 IPv4 地址按端口切成 `2^k` 个**端口集**，每个端口集由 **PSID**（k 位）标识，分配给一户；
- 每户的 IPv6 地址由 `规则前缀 + IPv4 后缀 + PSID` 按位拼出；
- 边界设备（BR）收到 IPv4 报文时，从目的端口低 k 位直接反解 PSID，
  配合目的 IPv4 当场算出目的户 IPv6——**无连接表、无状态、结果与到达时间无关**，
  因此不存在"表满"这一故障面。
- 唯一的有状态部分是每户 CE 内部的 NAPT44，且外部端口只能取自本户端口集；
  单台 CE 只记自家连接，表满最多影响一户。

容量：`PSIDLen=10` 时一个公网 IPv4 带 1024 户，200 个地址可承载 **204,800 户**，
超过原单机十万用户规模（见 `pkg/maprule` 测试）。

## 目录结构

| 路径 | 职责 |
|---|---|
| `pkg/maprule` | 端口集算法（RFC 7597 公式、跳过知名端口）、规则、IPv6 编解码、BR 无状态反查 |
| `pkg/headers` | IPv4/IPv6/TCP/UDP/ICMP 报文头解析构造、RFC 1071/1624 校验和（含增量更新） |
| `pkg/translate` | RFC 7915 逐字段翻译、协议号/ICMP 类型代码映射、嵌套 ICMP、分片、PMTU |
| `pkg/napt` | CE 侧端口集内有状态 NAPT44（含外部端口直查索引、超时回收） |
| `pkg/encap` | MAP-E 封装（IPv4-in-IPv6，proto 41）与解封装 |
| `pkg/stack` | 仿真终端迷你 IPv4 协议栈（UDP/TCP/ICMP、PMTU 缓存、回显钩子） |
| `pkg/sim` | CE、BR、IPv6 接入云、IPv4 外网的进程内网络仿真与拓扑装配 |
| `cmd/sim` | 验收程序：跑应用流量并逐项断言 |
| `cmd/web` | 规则计算页面：输入一户参数，展示地址/端口集的位级推演与 BR 反算 |

## 七条需求的落点

1. **端口集切分**：`maprule.ExpandPortSet` 按 `P = i·2^k + PSID` 展开，
   显式跳过 `<1024` 知名端口；不同 PSID 低 k 位不同，集合天然不相交。
2. **IPv6 拼装与无状态反查**：`Rule.EncodeIPv6` / `DecodeIPv6` / `ResolveV4ToV6`，
   BR 仅凭一条规则从 `(目的 IPv4, 目的端口)` 算户地址。
3. **转发映射/基本映射、同域直通**：CE `chooseDstV6` 识别同域目的后直接把报文送到对端 CE，
   验收显示该路径 BR 收发增量为 0。
4. **逐字段翻译**：TOS/DSCP 逐位保留、TTL↔HopLimit、协议号映射、长度按头口径转换；
   传输层校验和默认走 RFC 1624 增量更新，校验和中立布局（64:ff9b::/64）下逐字节不变。
5. **嵌套 ICMP**：里外两层分别翻译，类型/代码按 RFC 7915 对应改写；
   Redirect、部分 Param-Problem 等无对应物的类型按规范丢弃；MTU 按 20/40 字节头长差折算。
6. **MTU/分片**：IPv6 不分片，超限回 Packet Too Big / Frag Needed；
   v4 非原子分片经 v6 分片扩展头翻译；验收确认 PMTU 正确收敛。
7. **封装+翻译双模式 + 户内端口复用**：MAP-T 与 MAP-E 各跑一套验收；
   CE 的 NAPT44 在本户端口集内做有状态复用。

## 运行

```bash
# 全量单元测试（含竞态检测）
go test ./...
go test -race ./...

# 两种模式的端到端验收（11 项断言）
go run ./cmd/sim -mode all
# 也可单独：-mode mapt | -mode mape
# 可调参数：-shared 共享地址数 -per-v4 每户数 -psid-len k -psid-offset a -hosts-per-ce n

# 规则计算页面
go run ./cmd/web -addr :8080
# 浏览器打开 http://localhost:8080，输入一户参数查看位级推演与 BR 反算演示
```

## 验收项（`cmd/sim/acceptance`）

UDP/TCP 两端内容逐字节一致、NAPT 多主机共享、端口全部落在本户端口集且户间不相交、
同域互访不绕 BR、ping 跨地址族、traceroute 跳数超时、PMTU 收敛、端口不可达端到端还原，
并输出"一个公网 IPv4 带多少户"的容量统计。
