# README_AGENT.md — Exuvia（蝉蜕）项目协作文档

> **本文档的读者是 AI（LLM Agent），不是人类。**
> 用途：当你在本仓库进行二次开发、续写、重构或修 bug 时，先读完本文档。
> 它记录了项目的全貌、进度、已拍板的决定、以及**故意反直觉的设计**——后者尤其重要：
> 有些设计看起来像缺陷或可以"顺手优化"，实际上是用数轮讨论换来的结论。破坏它们 = 破坏项目。
>
> 本文档本身是协议的一部分（与三条协议数据流同级）。**修改本文档需要人类维护者确认**，
> 尤其是第 7、8 节（原则与决策日志）。

---

## 0. 三十秒版

Exuvia 是一个**面向 AI Agent 的 Android 通用脱壳 / 代码恢复流水线**，主攻新一代企业级加固壳。

- **输入**：一个加壳 APK
- **输出**：可续作的 handoff 工作区（剖析产物 + 欠账清单 + 证据切片 + 验证工具 + 报告索引）
- **形态**：Rust 单二进制（Linux musl / Windows exe），**不携带任何 Python 发行物**——系统 python3 是前提假设（IDA 模式）；灵魂是一个单文件 SKILL.md
- **本体论**：躯体（单二进制，内含全部自身代码）· 灵魂（SKILL.md 单文件）· 接口（三条协议数据流：handoff / goal / proposal）
- **名字**：Exuvia（蝉蜕）——壳留在原地，代码恢复生命
- **口号**：*"Separate the shell from what lives inside."*

**项目当前状态：v0.1 代码面已补全（38 测试 CI 全绿）；第一战（真实加固样本）实测进行中，已产出 4 个实战修正。**
- 契约层：六协议物 fixture 双向锚定（goal/proposal/report/debt/workpackage/evidence）、serde 类型即格式、错误码公开表、fence 空（生长规则就位）；
- 卡点两类：method-native-stub（ACC_NATIVE stub + JNI 符号定位 + 方法体切片）与 encrypted-payload（三机械来源：坏 DEX 文件 / so 内明文 DEX 扫描命中 / assets ELF 零命中负事实）+ 解密例程候选机械定位（JNI_OnLoad / init_array 双路径：PT_DYNAMIC 运行时视角优先）；
- 外循环闭合且留痕：`exuvia packed.apk → next --goal → [LLM 解卡点] → unpack merge（四层闸门 + 沙箱双锚 + 销账）→ validate`；merge 拒绝时 attempts.log 记 merge-rejected + 被认领卡点 attempts 递增；recovered DEX 形状产物归档 workspace/<debt_id>/recovered.dex；
- 实战修正（真实样本驱动，全部机械规则、零厂商特判）：#1 DEX 解析器按规范对齐（method_id 8B / type_list u16）；#2 assets ELF 纳入清点与符号查表；#3 so 内明文 DEX 机械扫描；#4 PT_DYNAMIC 运行时视角双路径 + ELF64 全架构符号 + 导出符号清单进 facts；
- 第一战已测绘（attempts.log 诚实台账，三轮留痕）：壳形态 = dex 尾部密文载体 + so 内嵌段 + interpreter 化控制流 + RegisterNatives 动态注册；解密链已解至 RC4 变体（KSA/PRGA 全解、unicorn 与 python 复现交叉验证一致）+ zlib 解压实锤（112B z_stream 的 inflateInit_）；key 常量确认在只读段（真静态）；**终局结论（六路静态 + 两路黑盒 + 双架构对照收敛）：该技术族把 DynCryptor 的调用现场（真实密文指针/长度）作为纯运行时事实——轨道 A 与函数级轨道 B 在此结构性到界，免费档即需轨道 C 的运行时事实（§9 VMP 条款的预判被提前命中）**。产品路径确认：轨道 C 按设计保持用户侧能力（§3.1），本项目的交付职责 = 把卡点与验证回流定义到机械可判（hook 剧本作为工作包 guidance 附件——**fence 首条族知识候选，待维护者确认**）；ELF32 记为候选修正；
- CLI 契约表全兑现：--version / --profile / --goal / --json / --resume、next、schema --dump、unpack validate / merge；
- handoff 结构落盘完整：REPORT.json + REPORT.md、debt.json、evidence/<debt_id>/{manifest.json, <name>.bin}、attempts.log、workspace/；
- ci/verify（cargo workspace member，不进发行物）：register 语料登记 + check 原包对账——比对逻辑公开、样本私有；
- 终点定义已拍板：行为一致的可运行 APK（§2.1）+ 忠实还原原则；
- **下一步：解外层密钥（解压链深层 / 函数级黑盒模拟收尾）→ 纯函数 decrypt → proposal → merge → ci-verify 对账**；其后 so 符号定位（capstone 测量）、repack 四组件逐件生长。

---

## 1. 项目身份

| 项 | 值 |
|---|---|
| 名称 | Exuvia（中文名：蝉蜕） |
| 维护者 GitHub | https://github.com/Huai-Tian |
| 许可证 | **AGPL3**（选它而非 GPL3 是故意的：堵住"封装成付费 API 不开源修改"的口子） |
| 定位 | 非商业、安全研究用途、**通用脱壳** |
| 战略主攻 | **新一代企业级加固壳**——成本高、无先例、且没有同行（旧壳赛道拥挤，后期才适配） |

**与 REA 的关系**：REA（Reverse Engineer Anything）等分析层工具是**下游消费者**。Exuvia 解决"代码被藏起来了怎么先拿回来"，REA 解决"没有源码怎么理解"。

**法律姿态（不可妥协）**：本项目不针对任何特定加固厂商。壳的**识别**可以做（行业惯例），但指纹、SOP、处理器一律按**技术族**命名（如"整体加密-单段型"、"JNI 翻译习语"），**永不写厂商名**。参考 BlackDex 的声明措辞。零样本政策：仓库中永远不出现真实商业 App 的加壳样本；CI 语料 = **私有持有的"原包 + 加固包"对**，仓库只放 hash 清单与获取指南；比对逻辑（`ci/verify/` 工具）公开，样本本体不公开——公开方法，私有数据。

---

## 2. 问题定义与立项依据

**成本模型**：所有混淆/加固都只是提高成本，没有绝对不可破解。当前破解成本 = 分析员时间 + LLM token 费用。

**价值定位（精确表述，勿混淆）**：任何 LLM 工作流都能在第一次分析后沉淀 SOP 降低**第二次**的成本——那是 LLM 生态的通用能力，不是本项目的差异化。**本项目降低的是第一次分析的成本**：把机械性分析全部交给零 token 的确定性二进制，把智能需求压缩到卡点最小集外包给外部 LLM。

**零学习曲线（项目哲学）**：不负责把第一个 APK 的经验传递给第二个 APK。要做的是**让第一个 APK 被服务得像有经验总结加成后的第二个 APK 一样**——判断力通过架构注入（结构化起点、预置常识、卡点工作包、双锚验证），而不是靠历史积累。性能从第一次就达到峰值。新代壳没有历史可依赖；依赖经验积累的产品在那片战场价值趋零，本架构的价值恰与历史无关。

**实证依据**（接手者应知道的三个事实）：
1. Carleton 大学 2025 年论文（12,341 App 测评）：现存开源脱壳器（BlackDex、frida-dexdump 等）面对现代商业加固**已全部失效**——赛道有空窗。
2. FreeBuf 2026-10 MiniMax 静态脱壳实测：LLM 纯静态可脱壳，首例约 2 小时 / 80M token；沉淀为 SOP 后同类样本"游刃有余"。**贵的是首次探索，不是解密本身。**
3. 360SRC 的 VMP 分析文章：JNI trace 蒸馏后交 LLM 可还原 VMP 方法，简单函数可完美还原。

**已接受的宿命**：这是猫鼠游戏。工具火了之后壳厂商会加反 Exuvia 检测——但本架构不靠知识库吃饭（判断力在架构里，不在积累里），新壳出现就是又一次"像第二次一样的第一次"。

### 2.1 终点定义（产品验收的最终形态）

Exuvia 的终点：**行为一致（behavioral parity）的可安装、可运行 APK**。不追求字节级一致——字节只是手段，行为才是验收。

- `recovered`（原始字节可得：一/二代壳）：恢复原始字节是达成行为一致的**最可靠手段**（字节回来了，行为天然一致）；
- `equivalent`（原始字节不存在：四代壳）：等效实现 + 行为差分覆盖证明；
- 两条路径服务于**同一个终点标准**：装上就能跑，可感知行为与原包一致。
- 验收线随之统一为**行为验证**（装机运行对比）；原包字节对账降级为 `ci/verify/` 的内部开发指标，不是产品验收标准。

**终点合成阶段 `repack`**（debt 清零或 goal 满足后触发；四组件按三次法则逐件生长，不预写）：

```
① DEX writer     还原/等效的方法体 → 合法 DEX（现有 parser 的镜像工程）
② 重组器          资源搬运 + Manifest 修复（loader 移除、Application 还原）——AXML 解析届时上桌
③ zipalign+自签  系统装机的硬前提（v2/v3）
④ 运行验证       装机冒烟（可作为卡点外包给下游）
```

**签名自校验条款（已拍板：忠实还原原则）**：Exuvia 是恢复器，不是 patcher。签名自校验逻辑与任何其他逻辑**同等对待**——`recovered` 忠实恢复，`equivalent` 忠实等价其机器码行为（含校验分支）。自签重包若因校验逻辑退出，这是忠实还原的**正确表现**，不是产品失败："行为一致"验收携带环境谓词（原厂签名物理不可复制，此项差异如实标注，不算还原缺陷）。恒真 patch 属于使用者的修改行为，永远不在 Exuvia 的功能面——这条线同时是"研究恢复"与"破解"的法律分界线。

---

## 3. 架构

### 3.0 本体论：躯体 · 灵魂 · 接口

```
躯体  = exuvia 单二进制（Linux musl + Windows exe）
        · 轨道 A 引擎、闸门与判定、编排
        · 内嵌 Python 胶水 runner（字符串资源，stdin 喂给系统 python3，零落盘）
灵魂  = SKILL.md 单文件
        · 方法论 · 格式示例（示例 = CI fixture）· profile fence · 族知识 guidance
接口  = 三条协议数据流：handoff / goal / proposal
        · 无独立 schema 文件：机器事实源 = Rust serde 类型；语义解释 = SKILL 格式章节
        · 机器可读形式按需派生：exuvia schema --dump
```

release = 两个平台二进制 + SKILL.md + checksums。**纯文件，无目录**。仓库同构：`src/`（Rust 单工程）、`SKILL.md`、`trackb/`（轨道 B 用户侧 Python 工具）、`ci/`、`README_AGENT.md`、`LICENSE`。

**零发行纪律（结构三次法则）**：生态已有的东西一概不发行——系统有 python3 就不捆运行时；PyPI 有 qiling/frida 就不打包依赖；serde 类型能定义格式就不放 schema 文件；单文件装得下的判断就不拆目录。任何新结构元素（文件/目录/发行物）需要"同一需要出现过三次"的实证，不接受"将来可能有用"。

### 3.1 三轨道

```
轨道A 静态分析   —— 解包、指纹、so 切片、解密例程定位与离线复现
轨道B 模拟执行   —— qiling/Unicorn 离线跑 so 里的解密函数（用户侧按需安装）
轨道C 定点动态   —— 仅对指定方法注入调用/trace（VMP 类的最后手段）
```

优先级永远 A > B > C。**新代壳战略下，轨道 B/C 是主路径而非推迟项**（roadmap 期工程化），L2/L3 从"可选层"升格为主交付物。轨道 B/C 的重依赖（qiling、unicorn、frida）不进发行物，用户侧安装，缺席 = `unavailable`（功能级语义，与 jadx/ghidra 同类）；**核心闸门依赖的系统 python3 缺失 = `installation-broken`（拒绝运行）**。

**轨道 B 工具已落地（`trackb/`，用户侧 Python 工具——第一战实战催生）**：`so_emulator.py`（so 黑盒执行器：ELF64 映射 + RELATIVE/GOT 重定位 + bionic libc 语义层 + 可选 JNI 假表 + RegisterNatives 捕获，零样本参数全 CLI 化）、`crypto_recon.py`（容器熵定位 / ECB 指纹 / AES 指令扫描 / RC4 变体族已知明文双过滤扫描）、`selftest.py`（合成 fixture 自检，零样本纪律）。工具本体是产品的一部分随仓库分发；unicorn/capstone 由使用侧安装。

### 3.2 分层交付（每个方法声明它到达的层级）

| 层级 | 产物 | 成本 | 说明 |
|---|---|---|---|
| L1 | 骨架 DEX：类/方法签名齐全，方法体为 native stub 指向原 so | 极低 | **性价比最高**，App 结构立刻可导航（jadx 可开） |
| L2 | 伪代码还原：Ghidra headless + JNI 语义标注 + trace 交叉验证 | 中 | **主交付物**（新代壳战略） |
| L3 | 可重编译源码：语义还原 + 差分验证 | 高 | VMP 的"等价语义"归宿 |

覆盖率报告按 L1/L2/L3 分层统计。

### 3.3 v0.1 MVP 竖切（窄而完整，勿扩大）

```
安装校验（python3 probe · SKILL fence 校验）
→ APK 解包 → 壳指纹（技术族命名）→ so 函数切分 → 解密例程候选定位
→ 切片与常量扫描喂卡点外包 → 离线解密 → DEX 修复 → L1 骨架
→ debt 清单 → handoff + 静态脱壳脚本
```

- 目标壳：**一代壳（整体加密）作为协议自检的脚手架**——用最便宜的壳把 handoff / 闸门 / 回流 / resume 整条流水线打通；产品叙事从第一天立在新代壳上。**主攻方向和工程第一步是两件事，后者为前者服务。**
- 验收语料：20 个"原包 + 加固包"对（私有持有），原包即 ground truth。
- **静态脱壳脚本本身是一等交付物**：可复现、可审计、自验证，是 handoff 里最强的证据形式。

---

## 4. 剖析包与 handoff 契约（项目灵魂）

### 4.1 两段式目标

**第一阶段无 goal**：`exuvia packed.apk` 全量机械分析，产出**剖析包**（= handoff v1）。剖析包是"goal 作者的地图"——类清单、native stub 分布、难度信号都在其中。

**goal 是格式化的（不是自然语言）**：

```json
{
  "$schema": "exuvia.goal",
  "targets": [
    { "kind": "method", "class": "com.example.LoginManager", "method": "sign" },
    { "kind": "category", "profile": "network-entrypoints" }
  ],
  "levels": { "default": "L2" },
  "tracks": ["A", "B"],
  "accepts_equivalent": true,
  "stop": "targets-satisfied"
}
```

- **语义定位发生在消费侧**（人或下游 LLM 读剖析包元数据后写 goal.json），工具只执行格式化目标——**系统里没有任何一个环节是"二进制假装懂语义"的**，语义只存在于协议物的生产侧。
- goal 的每个字段必须机械可判定；类目引用 profile fence 里定义的 API 集合（查表，非语义魔法）。
- stop 条件 = targets 全部销账的**事实**（audit trail 记"验证通过"，不承诺"语义正确"——工具连"还原质量"都不做终审）。

### 4.2 handoff 结构

```
handoff/
├── workspace/        # 已完成产物：dex、修复结果、符号、切片（按方法组织）
├── debt.json         # 欠账清单：事实 + 难度信号 + 分类（blocked-solvable / out-of-scope）
├── evidence/         # 证据切片：JNI trace、opcode 流、反编译片段（按方法索引，manifest 带 hash 锚定）
├── attempts.log      # 尝试日志（按"将来会被重新阅读并蒸馏"的标准记录）
├── verify/           # 验证工具：差分测试脚本、动态对账 hook
└── REPORT.md + .json # 人类可读摘要 + 机器可读索引
```

debt 语义不变：**事实 + 难度信号**，不给"预估成本"字段（价格由下游 AI 估）。分类标注：`blocked-solvable`（可外包的卡点）vs `out-of-scope`（轨道 C / L3 范畴——**新代壳战略下这是"主战场地图"而非残渣**）。

### 4.3 卡点外包循环（全流程唯一烧 token 处）

```
exuvia next --goal goal.json   → 工作包（切片 + manifest + 按 goal 注入 guidance；建议排序，不替用户决定）
外部 LLM 解卡点                 → proposal 包（唯一 token 消耗处）
exuvia unpack merge proposal/  → 四层闸门 → 销账 → exuvia --resume 批量推进（0 token）
```

循环的驱动者永远在外部（人或编排 Agent）——**核心绝不内置 LLM 调用**，工具是确定性二进制，不知道也不该知道 token。

**proposal 包格式**（JSON 清单 + 独立产物文件，避免长代码的转义地狱）：

```
proposal/
├── proposal.json    # 指针 + 声明 + hash（不含时间戳等影响产物字节的环境字段）
├── artifacts/       # 算法代码 / 还原的方法体（自然文件格式）
└── tests/           # .in / .out 测试对
```

**四层闸门**：

| 层 | 检查 | 失败时 |
|---|---|---|
| ① 语法与格式 | Rust serde 类型解析，未知字段拒绝 | 结构化错误码 + 定位 |
| ② 对账 | **范围闸**：只能认领 debt 中存在且未锁定的条目，不得触碰 workspace 已有产物；hash 与切片匹配 | 拒绝，报不匹配详情 |
| ③ 语义验证 | **判定权在 Rust**（见 4.4）：结构断言 × 沙箱测试对 | 报差异（实际 vs 期望） |
| ④ 结果 | 通过 → 销账落盘；失败 → 结构化错误回 LLM 修复重提（小循环，几十 token） | 机器可读，报错是给 Agent 看的 |

### 4.4 语义验证与 Python 执行（安全核心）

**不发行任何 Python**。系统 python3 是前提（IDA 模式）。胶水 runner 以字符串资源住在 Rust 二进制内，**通过 stdin 喂给沙箱中的 `python3 -I -`，零落盘**——无缓存管理、无平台路径差异、无"自我释放执行"模式（安全工具不得长得像恶意软件，会被分析机上的 AV/EDR 盯上）。

**三防线**：

1. **隔离注入**：`-I` 隔离模式（忽略 PYTHONPATH / 用户 site-packages / sitecustomize 自动加载）+ 最小环境变量表。installation 阶段 probe（stdin 喂已知输入校验解释器真实性——顺带挡掉 Windows 的假 python.exe）。
2. **判定权不外包**：runner 是纯执行器（加载 entry、喂 .in、吐**原始输出**），**对比与判定是 Rust 的确定性代码**；退出码 / 超时 / 资源熔断由 OS 沙箱直接报告 Rust。python 层无权宣布"通过"。
3. **双锚**：结构断言（解密产物是合法 DEX、magic 正确、类数对账 L1 骨架）**永驻 Rust 可信侧**；数值测试对走沙箱。两个锚永不同时依赖不可信层——防 proposal 撒谎（自洽错误），也防环境撒谎（被污染的 python）。

OS 沙箱按平台分文件实现（单一接口 `run_sandboxed(code, args)`）：Linux = setrlimit + 网络 namespace + chroot 最小 rootfs + seccomp 白名单（musl 静态无碍，系统调用层）；Windows = Job Object + 受限 token + AppContainer（可选加强）。配套：entry 签名收窄为纯函数 `decrypt(data, key) -> bytes`、import 白名单、超时熔断。

**威胁模型边界（文档声明，勿越）**：`-I` 挡现实注入面；stdlib 被直接篡改 = 系统已 root 级沦陷 = 超出任何分析工具的防线（IDA/Ghidra 同样死），"一次性快照环境"声明兜底。

---

## 5. CLI 契约

**默认体验 = 拖入即用**：`exuvia packed.apk` → 剖析包。全程零提问（非交互是硬约束，任何交互式 prompt 都直接杀死 Agent 场景）。

| 参数 / 命令 | 语义 |
|---|---|
| `--version` | 版本 + 支持的协议版本 |
| `--profile <file>` | **覆盖** SKILL fence 内嵌的默认判断（判断外置通道；默认判断长在 SKILL.md 的 profile fence 里） |
| `--goal <file>` | 格式化目标文件（goal.json，见 4.1）。**自然语言 goal 已被推翻，勿改回** |
| `--json` | CLI 就是 API（不做 MCP 的代价） |
| `--resume` | 幂等、可断点续跑 |
| `exuvia next --goal <file>` | 打包当前最值得外包的卡点工作包（按 goal 相关性建议排序，工具不做终审） |
| `exuvia schema --dump <name>` | 按需派生机器可读格式（handoff/goal/proposal；无静态 schema 文件） |
| `unpack validate <dir>` | 下游自检 handoff |
| `unpack merge <dir>` | proposal 回流（四层闸门） |

**不存在 `--baseline`**：原包对账是仓库内 CI 工具（`ci/verify/`），不是产品功能。产品面上永远只有加固包这一个输入——用户手里不需要有任何他不该有的东西。

**退出码二分语义**：

- `installation-broken`：系统 python3 缺失 / 版本不符 / probe 失败、SKILL.md fence 不可提取或不可解析——**拒绝运行**。自身组件没有"缺席"状态，只有"装坏了"状态；**不存在降级模式**。
- `unavailable`：jadx / ghidra / qiling 等外部能力缺席——降级标注进 REPORT，相关层级照常标注，不 fail。这个词只属于外部工具。
- 有 L1 即返回 0（欠账是正常产出不是失败）；只有连 L1 骨架都产不出来才非零。**别用退出码惩罚架构上鼓励的行为。**

**Agent 人体工学**：`--json` 全覆盖、稳定退出码、无 TTY 假设、幂等、机器可读的错误输出（报错是给 Agent 看的）、格式文档与示例随 SKILL.md 分发。

---

## 6. 接口与灵魂先于代码

**第一个 commit 是 spec，不是源码**：

1. **SKILL.md**：30 秒版 → 工作流决策树 → 格式章节与示例（**示例 = CI golden fixture**）→ profile fence（TOML 代码块，info string 为 `toml profile`）→ 族知识 guidance → 版本锚点。SKILL 版本 = 文档内容 + fence 快照的联合版本。
2. **三条协议**（handoff / goal / proposal）：格式的初始事实源 = SKILL 格式章节，实现期翻译为 serde 类型，此后**双向锚定**——SKILL 示例必须能被 serde 类型解析通过，CI 强制执行。
3. **默认 profile**：就在 SKILL fence 里（判断外置 = fence + `--profile` 覆盖通道）。

**schema 文件不存在（勿新增）**：schema 是视图不是实体——格式的机器事实源是 serde 类型，语义解释在 SKILL 格式章节，`--dump` 按需派生。两份独立描述必然漂移；**文档即测试**（SKILL 示例 = CI fixture）比 schema 文件的单向声明强得多。

---

## 7. 设计原则（⚠️ = 反直觉，最容易被"好心破坏"）

1. **⚠️ 工具不做终审，且不做任何语义理解。** 方法层：debt 只给事实和难度信号；工具层：判断进 fence、不确定度一等输出；生态层：goal 的语义定位在消费侧。**系统里没有任何一个环节是"二进制假装懂语义"的**——每一处需要理解的位置，都被一道格式化接口推给了有智能的那一侧。

2. **⚠️ 无学习曲线，不负责经验传递。** 没有提炼流水线、没有指纹库自动增长、没有"第二次便宜"的机制承诺。判断力通过架构注入每一次第一次（结构化起点 / 预置常识 / 卡点工作包 / 双锚验证）。沉淀是 LLM 生态自己的事；attempts.log 和 proposal 历史按"将来会被重新阅读"的标准记录，下游想蒸馏随时可以，但**工具不做提炼厂**。指纹与族知识只作为 SKILL fence 的**显式配置**存在（版本化、可 diff、随 release 发布），社区贡献走清洗规则。

3. **⚠️ 判定权不外包。** 执行可以发生在不可信环境（沙箱 python3），"通过"两个字只有 Rust 有资格说。双锚永不同时依赖不可信层。这是对"proposal 撒谎"（自洽错误）和"环境撒谎"（被污染的 python）的双重防线。

4. **⚠️ 静态优先，不选 Frida 路线是故意的。** Frida 把主战场放在对方防御最强的地方。dump 核心写成与注入方式无关的纯模块，MVP 是纯静态轨。

5. **⚠️ MCP 不做。** 引擎和集成层分离是生态常态（Ghidra/JADX 从没做过 MCP server，被第三方 wrap 是荣誉）。社区 PR 的 MCP wrapper 收进 `contrib/` 单独维护。

6. **⚠️ SKILL 是灵魂且是单文件。** 方法论、格式示例、profile、guidance 全在一个文件里——profile 以 fence 嵌入（参数值与参数解释必须同地生长，消除漂移）。guidance 按 goal 注入工作包（按需抽取，不撑爆上下文）。修改 fence 追加族知识 = minor（清洗规则 + CI）；修改方法论 = major（人工确认）。

7. **⚠️ 参数极少，结构也极少。** 参数三次法则；**结构同样三次法则**——任何新文件/目录/发行物需要"同一需要出现三次"的实证。不重复发行生态已有的任何东西（运行时、依赖、格式描述、配置目录）。每个被砍掉的候选结构（--baseline / sop-distill / schema 文件 / py 目录 / runtime 捆绑）都死于同一个测试：**它在为假想的场景付费**。

8. **技术族命名，永不写厂商名。** 内部研究逐厂商看，产出的 SOP、指纹、处理器按技术命名；社区贡献必须清洗厂商名。

9. **交付物是"可续作状态"，不是"完成度"。** 停止条件由格式化目标决定；很多方法对目标无关，全脱完是浪费。

10. **验证闭环先于功能扩张。** 语料 = 私有"原包+加固包"对（自己加固自己的 App，完全合法）；比对逻辑公开（`ci/verify/`），样本不公开。主验收指标 = **未知新样本的首次卡点密度**；CI 必含故意构造的未知技术族样本——**零样本是主线场景，不是异常路径**（指纹未命中 = 产品高光时刻）。

11. **敌意输入与脏环境预期。** 分析机常态是脏的：python 环境可能被污染（`-I` 防注入）、proposal 可能恶意（纯函数接口 + import 白名单 + OS 级隔离）、APK 必然敌意（唯一进口 Rust）。文档写清"在一次性快照环境中运行"。

**v0.1 验收线**：20 个原包+加固包对、类级恢复 ≥90%、产物可解析率（jadx 能开）、与原包 DEX 的字节一致性（`ci/verify/` 内部指标）、下游 AI 拿 handoff 完成 3 个规定任务（"找到 Application 子类"、"列出网络请求入口"、"恢复指定方法"）、未知族样本的卡点密度达标。

---

## 8. 决策日志（已被推翻的方案——别改回去）

| 曾计划 | 现结论 | 推翻原因 |
|---|---|---|
| Frida 形态 MVP | 纯静态轨 MVP | Frida 被厂商盯着打；静态路线已被 MiniMax/Huli 实测验证 |
| debt.json 给欠账"标价" | 只给事实 + 难度信号 | 确定性二进制不知道 token 成本。**不要过度承诺工具给不了的东西** |
| v0.1 做 MCP server | 不做 MCP | 见 7.5 |
| GPL3 | AGPL3 | 非商业定位下堵商业化包装的口子 |
| 名字候选 molt / cicada / unearth | Exuvia | 撞名与法律姿态（含 crack/break/unlock 的词全排除） |
| Python 作为可选卫星层 | 演进至**零发行** | 链条：可选→绑定→py/目录→内嵌释放→stdin 喂入。**绑定 ≠ 捆绑**：绑定的本质是版本锁死 + 前提假设；"自我释放执行"会被 AV/EDR 盯上 |
| 捆绑 Python 运行时（runtime/） | 依赖系统 python3 | 分析机 python3 是基础设施级前提（IDA 模式）；捆绑全负担零收益，是"重复发行生态已有物" |
| 自然语言 goal（如"搞清支付签名算法"） | goal.json 格式化 | Rust 读不懂自然语言，其消费必然走私 LLM 或硬编码启发式进二进制——确定性死亡 |
| `--baseline <apk>` 产品接口 | 不提供 | 真实用户没有原包；法律姿态（不引导不当获取）；分析者信任。对账是 `ci/verify/` 的内部职责 |
| 自研一代壳模拟器做 CI 语料 | 私有"原包+加固包"对 | **循环论证**：模拟器要先验理解壳，而理解壳正是要产出的东西 |
| 提炼流水线 / sop-distill / 经验传递机制 | 彻底取消（非遗留债务） | LLM 生态自己会沉淀第二次的便宜；差异化在第一次。指纹 = 显式配置而非系统记忆（运行时自动积累 = 行为随历史漂移 = 确定性死亡） |
| 独立 schema 文件 | 不存在 | schema 是视图不是实体；schema 文件与实现是两份必然漂移的描述；文档即测试（SKILL 示例 = CI fixture）替代单向声明 |
| profiles/ 目录、多 profile 文件 | 单文件 fence 嵌入 SKILL.md | 判断是文档量级不是数据库量级；参数值与参数解释必须同地；文件系统拆分在为假想的未来付费 |
| "引擎缺失时降级运行" | installation-broken / unavailable 二分 | 绑定组件没有"缺席"状态只有"装坏了"状态；unavailable 只属于外部工具 |
| v0.1 "一行 Python 都没有" | v0.1 即依赖系统 python3 | merge 闸门的语义验证层就是 python3 沙箱，而 merge 是 v0.1 契约的一部分——"纯 Rust MVP"与"卡点外包是核心协议"不能同时成立 |
| L2/L3 是可选层 | 主交付物 | 新代企业壳战略：原始字节码不存在，交付"等价语义" |
| 轨道 B/C 是推迟项 | 主路径（roadmap 期工程化） | 同上；四代壳处理原则从边界条款升格为主战场规则 |
| 签名自校验恒真 patch（候选立场之一） | 忠实还原原则（恒真永久排除） | Exuvia 是恢复器不是 patcher；恒真是使用者的篡改行为，不属于工具功能；此线同时是"研究恢复"与"破解"的法律分界 |
| 目标壳从一代壳起步 = 产品定位 | 一代壳 = 协议自检脚手架 | **主攻方向（新代企业壳）与工程第一步（便宜壳打通协议）是两件事**；验收语料直接用真实"原包+加固包"对 |
| 终点 = 字节级一致（隐含理解） | 行为一致的可运行 APK（§2.1） | 字节只是手段，行为才是验收；recover 是最可靠手段，equivalent 是直接实现；原包字节对账降为 ci/verify 内部指标 |

**语义等效还原（通用恢复策略，非四代壳专属）**：每个方法有两条产出路径——`recovered`（还原原始字节）与 `equivalent`（读 L2 反编译的机器码，写出功能等效实现）。路径选择按**成本比较**，判断者是下游 LLM（工具只给难度事实，不做终审）；goal 的 `accepts_equivalent` 字段声明目标是否接受等效销账，proposal 的 `claims[].kind` 路由闸门验证（recovered → 结构断言×字节测试；equivalent → 行为差分）。**差分证明的是覆盖行为上的等价，不是全面等价**——audit trail 只记事实。

---

## 9. 范围边界（诚实清单，勿过度承诺）

静态/模拟**解决不了**的（进 debt 清单，标注 out-of-scope / 需轨道C）：
- key 从设备环境派生（IMEI、build fingerprint——模拟可伪造枚举但组合爆炸）
- 网络拉取的 payload
- 流式拼装的 DEX
- VMP 的完整语义还原（轨道 C 定点动态 + L3"等价语义"范畴）

**四代壳（VMP/dex2c）处理原则**：原始字节码从不存在于内存，dump 原理上无解。"汇编分析还原同等功能"不是退而求其次，是换了一个正确的问题定义：交付物从"原始字节"变成"等价语义"（.NET 的 OldRod 反虚拟化是先例）。残留物是机器翻译的汇编，有固定习语（JNI 边界调用、寄存器约定、模板化控制流）——精度可以很高，且"同等功能"对分析场景是低标准（要的是 API 序列和逻辑，不是指令级一致）。

---

## 10. Roadmap（工程顺序）

- **v0.1**：一代壳脚手架打通全协议（next / merge / resume / validate）+ 闸门沙箱（双平台）+ `ci/verify` 原包对账 + 语料生成脚本
- **其后**：轨道 B 工程化（qiling 适配 JNI 环境）、轨道 C、L2/L3 主交付物化、多 Android 版本适配、evasion、指纹 diff 工具化
- **永久不做**：MCP（社区 contrib）、经验传递机制（哲学级取消）、指纹库自动增长（显式配置 only）、`--baseline` 产品接口

---

## 11. 术语表

| 术语 | 含义 |
|---|---|
| handoff / 剖析包 | 交付给下游的可续作工作区；第一阶段的 handoff 即剖析包（goal 作者的地图） |
| debt / 欠账 | 未完成方法的事实+难度信号+分类（blocked-solvable / out-of-scope）；正常产出，不是失败 |
| goal.json | 格式化目标（选择器 · 层级 · 轨道 · 停止条件），消费侧语义定位后产出，工具机械消费 |
| proposal | 外部 LLM 的回流包：清单 + 产物 + 测试对，过四层闸门 |
| 工作包 | next 打包的卡点外包单元：切片 + manifest + guidance |
| 闸门 | merge 的四层校验（语法格式 / 对账 / 语义 / 结果）；判定权在 Rust |
| 双锚 | 结构断言（Rust 可信侧）× 数值测试对（沙箱执行）——两锚永不同时依赖不可信层 |
| guidance | SKILL fence 里写给 LLM 的族知识（战术指引）；next 按目标注入工作包 |
| fence | SKILL.md 内的 TOML 代码块（info string: `toml profile`），可执行判断的容器 |
| installation-broken / unavailable | 自身组件损坏（拒绝运行）/ 外部能力缺席（降级标注）——严格二分 |
| 卡点外包 | 把智能缺口压缩成工作包交给外部 LLM 的循环模式；全流程唯一烧 token 处 |
| 语义等效还原 | 产出路径 `equivalent`：读机器码写功能等效实现，按成本比较选择；差分验证覆盖行为等价 |
| 行为一致 | 终点标准：装机运行、可感知行为与原包一致；字节一致仅是 recover 的副产品 |
| repack | 终点合成阶段：方法体 → DEX → 重组 → 自签 → 可运行 APK；四组件按三次法则生长 |
| 零学习曲线 | 不依赖历史积累，性能从第一次即峰值 |
| 结构三次法则 | 新文件/目录/发行物需"同一需要出现三次"的实证 |
| 躯体 / 灵魂 / 接口 | 二进制（含内嵌 runner）/ SKILL.md 单文件 / 三条协议数据流 |
| 轨道 A/B/C | 静态 / 模拟执行 / 定点动态 |
| L1/L2/L3 | 骨架 DEX / 伪代码还原 / 可重编译源码 |
| 技术族命名 | 按加固技术特征（而非厂商）命名指纹与 SOP |
| 一代壳~四代壳 | 整体加密 / 方法抽取 / 动态解密+SO混淆 / VMP·dex2c |

---

## 12. 给接手 Agent 的行为准则

1. **动手前**：读完本文档；对照第 8 节确认你要做的事不在"已推翻"清单里——那里 17 条，每条都是数轮讨论换来的结论。
2. **写代码时**：判断逻辑进 SKILL fence，不硬编码；每个判断写 audit trail；不确定就输出不确定度；**判定权永远在 Rust**。
3. **想加东西时**：参数过三次法则；**结构也过三次法则**（新文件/目录/发行物）；先问"这是不是接口或灵魂的变更"——是的话先改 SKILL.md 再写代码。
4. **想"优化"时**：对照第 7 节 ⚠️ 条目。如果你觉得某条原则"明显更好"，大概率它已经在第 8 节被推翻过一次。
5. **涉及 Python 时**：不发行、不落盘、不判定。stdin 喂入 `-I` 模式沙箱执行，胶水 runner 是二进制内嵌资源。
6. **修改本文档**：可以补充事实和进度；修改原则/决策日志需要人类维护者确认。
7. **交付给下一个 Agent 时**：更新本文档的"当前状态"，像 debt.json 一样诚实记录你做了什么、什么没做完、为什么。
