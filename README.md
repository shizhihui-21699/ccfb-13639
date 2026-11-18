# sct — Go 并发安全缺陷系统性探测工具

针对请求处理代码的**确定性并发测试（systematic concurrency testing）**框架。它不靠压测碰运气，
而是主动控制 goroutine 调度顺序，系统性地探索请求交错，把导致**越权、重复扣减、check-use 不一致**
的执行顺序找出来，并给出可稳定复现的调度序列。

## 为什么 `go test -race` 解决不了这两类事故

线上那两个事故——优惠券并发重复核销、权限撤销后请求仍穿过检查——共同特征是：

- 每一次单独的 map/字段读写都有锁保护，**没有 data race**，`-race` 完全沉默；
- 缺陷在**两次加锁调用之间的间隙**：check（读）和 use（写）不构成一个原子决策，
  另一个请求可以在间隙里改变共享状态。这是**原子性违反（atomicity violation）/ TOCTOU**。

本工具换了一个维度：不检测内存竞争，而是**枚举/采样调度交错，再用业务预言机判定结果是否合法**。

## 核心机制

### 1. 协作式插桩 + 全局调度器（`sct/scheduler.go`）

业务代码在语义关键点主动出让控制权，同一时刻只有一个 goroutine 运行，全局 `Controller`
决定下一个谁跑。插桩 API（无 controller 时全部是 no-op，**同一份代码可直接上生产**）：

| API | 含义 |
|---|---|
| `Tick(ctx, point)` | 普通语义点（检查后、写回前…），一次调度决策点 |
| `OpenWindow(ctx, point, resource, observed)` | check/use 对的"检查"侧，记录观测值 |
| `CloseWindow(ctx, point, resource)` | "使用"侧，正常提交 |
| `CancelWindow(ctx, point, resource)` | 检查失败、提前返回 |
| `Mutate(ctx, point, resource, newVal)` | 对共享资源的写，会干扰其他 goroutine 打开的窗口 |

**插桩位置准则**：tick 要放在锁/临界区**外面**。锁内的 tick 会把交错强行串行化，反而藏住 bug。

### 2. 五类调度策略（`sct/strategies.go`）

| 策略 | 做法 | 适用 |
|---|---|---|
| **Random** | 每个决策点在存活 goroutine 中均匀随机（确定性 PCG，seed 可复现） | 基线、fuzz |
| **PCT** | 随机优先级 + 在 d-1 个随机点强制降优先级抢占。对需要 d 次精确抢占的 bug 有概率下界 `1/(n·k^(d-1))` | 深抢占缺陷，深度 d 可调 |
| **DFS（有界穷举）** | 跨 run 的里程表枚举 gid 序列，深度 D 内覆盖各种前缀，尾部确定性收尾 | 小规模 goroutine 的近穷举 |
| **Script** | 手工钉住关键攻击前缀（如"两个请求都过 check 再提交"），剩余决策交 fallback | 编码已知事故、CI 回归 |
| **Replay** | 喂入历史 schedule，逐决策原样重放 | 稳定复现、回归门禁 |

### 3. 三类预言机（在 workload 的 `Oracle` 里）

- **状态不变量**：单用途券最多核销一次、余额不得为负；
- **TOCTOU 窗口**：某个 check/use 窗口打开期间，资源被别的 goroutine `Mutate` 过即标记 `Interfered`；
- **可串行化 + 事件顺序**：例如两笔 60 扣款在余额 100 上不可能有合法串行排列；
  "撤销在使用之后"是合法串行顺序，预言机通过 trace 的事件序号判定，**不会误报**。

### 4. 确定性与稳定复现

- goroutine 进入按 gid 0→n-1 严格排序（不依赖 OS 线程调度）；
- 每个决策的 gid 记入 `schedule`，`ReplayDecider` 逐决策比对，重放出**逐事件一致**的 trace；
- 每个 bug 归并时优先保留**已验证通过的最短 schedule**；
- 重放遇到代码路径变更会明确报 `replay mismatch`，提示需要重新分诊。

## 覆盖度怎么衡量（`sct.Coverage`）

单一数字会骗人，所以同时报告五个互补维度：

1. **点覆盖 `PointsReached / PointsTotal`**：workload 自己声明的插桩点中实际到达的比例。
   分母按 workload 收窄，未到达的点意味着死代码或预算不足。
2. **点边覆盖 `EdgesSeen`**：同 goroutine 内 point→point 转移的并集（分支/路径覆盖）。
3. **goroutine 切换边 `SchedEdgesSeen / SchedEdgesTotal`**：观测到的 gA→gB 切换有序对，
   全集为 n·(n-1)。**这才是真正衡量"交错空间探索了多少"的指标。**
4. **危险窗口 `WindowsOpened / WindowsInterfered`**：打开的 check/use 窗口数，及其中
   被他人写干扰的数量——直接对应 TOCTOU 的可达危险构型。
5. **相异 schedule 数 `DistinctSchedules / TotalRuns`**：trace 形状去重后的占比，
   低占比说明策略在重复探索同一交错，该换策略或加 seed。

策略效果用 **kill matrix**（每个策略产出违规的 run 数）横向对比，而不是只看总 bug 数。

## 目录结构

```
sct/                 框架核心：调度器、策略、探索引擎、预言机接口、覆盖度、报告
sampleservice/       示例服务，每个缺陷都有 buggy / atomic 两版（无 data race）
  coupon.go          单用途券重复核销（两次独立加锁的 check/use）
  permission.go      权限撤销 TOCTOU（检查与特权操作之间被 revoke）
  account.go         余额丢失更新（读-改-写分离）
  workloads.go       三个并发场景 + 预言机 + 手工攻击脚本
cmd/sct-demo/        一键跑全部 策略 × 场景 × 模式，打印覆盖度与 kill matrix
```

## 使用

```bash
go test -race ./...          # 全套测试（含重放确定性、CI 回归门禁、无 race 断言）
go run ./cmd/sct-demo        # 完整探测活动，JSON 报告写入 reports/
```

### 接到你自己的服务

1. 在 DAO/handler 的 check 与 use 处插入 `sct.OpenWindow/CloseWindow/Mutate/Tick`（生产环境 no-op）；
2. 实现 `sct.Workload`：`Setup` 每次造全新状态、`Worker` 是一个请求、`Oracle` 判定终态；
3. `sct.Explore(w, w.Points(), cfg)` 跑活动，读 `Report.Bugs`，每个 bug 自带 schedule；
4. 把 `bug-*.json` 固化进仓库，CI 里用 `sct.Replay` 重放——修复后该 schedule 变干净或 mismatch，门禁转绿。

## 已验证的行为（测试保证）

- 三个 buggy 场景在 random/dfs/script 下必被抓到，且每个 bug `ReplayOK`；
- 三个 atomic 修复版在所有策略下零误报（包括手工攻击脚本）；
- 重放 trace 与原始 trace 逐事件一致；
- buggy 代码在 `-race` 下无 data race 报警，证明本工具抓的是 race detector 看不见的原子性缺陷；
- PCT 命中率随抢占深度 d 上升（实测 d2→d4 梯度），符合理论预期。

## 边界与取舍

- **协作式而非运行时抢占**：只能在插桩点切换，覆盖度取决于插桩密度；好处是无运行时魔改、可上生产。
- **有界而非无限穷举**：Go 无法快照/回滚 goroutine，穷举靠跨 run 的里程表，n 和深度上去后 n^D 爆炸，
  靠 PCT 的概率保证和 script 定向攻击补规模。
- **预言机需要业务知识**：不变量和资源命名要人工声明，这是把"交错"翻译成"缺陷"的必要投入。
