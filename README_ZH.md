# Exuvia

简体中文 | [English](README.md) | [AI 协作文档](README_AGENT.md)

## 📖 介绍

**Exuvia**（蝉蜕）是一个**面向 AI Agent 的 Android 通用脱壳 / 代码恢复流水线**，主攻新一代企业级加固壳。

一个 Rust 单二进制承担全部机械工作、**零 token 消耗**——解包、清点、熵测量、DEX 解析、JNI 符号定位、解密例程候选定位、证据切片——并把每一处真正的智能缺口压缩成**卡点工作包**，外包给外部 LLM 求解。工具本体不调用任何模型，也不假装理解：每一处需要判断的位置，都被一道格式化接口推给了真正拥有智能的那一侧。回流的解法同样不被"外包判断"——结构断言驻留在 Rust 可信侧，数值测试对跑在加固过的 `python3 -I` 沙箱里，而"通过"这两个字只有 Rust 有资格说。

本体论是刻意的：**躯体**（单二进制，内嵌沙箱执行器——全程零落盘）、**灵魂**（单文件 SKILL.md：方法论、同时充当 CI golden fixture 的格式示例、profile fence）、**接口**（三条协议数据流：handoff / goal / proposal）。schema 文件不存在——serde 类型即格式；`exuvia schema --dump` 按需派生机器可读视图。

**零学习曲线是设计出来的**：Exuvia 不依赖经验积累。对未知壳的第一次分析即以峰值性能运行——判断力通过架构注入（结构化起点、预置常识、按卡点打包的工作包、双锚验证），而不是靠随历史生长的指纹库。新代壳出现之时，就是又一次"像第二次一样的第一次"。

> **使用 AI 助手（Copilot / Claude / GPT 等）参与本项目的二次开发？** 请先阅读 [README_AGENT.md](README_AGENT.md)——它专为 AI 编写，包含本项目大量**反直觉的设计决策与红线约束**，跳过它直接改代码极可能把已被刻意推翻的决策改回去。

## ✨ 功能特性

- **拖入即得地图——零提问、零 token**
  `exuvia packed.apk` 产出完整剖析包：`REPORT.json` + `REPORT.md`（人类可读半边）、`debt.json`（诚实的欠账清单）、`evidence/`（hash 锚定的字节切片）、`workspace/`、`attempts.log`。非交互是硬约束——任何交互式提问都会直接杀死 Agent 场景。

- **两类卡点，全部机械判定**
  `method-native-stub`：每个 `ACC_NATIVE` stub 被机械定位——JNI 短名与 mangled 签名推导 → dynsym 查表 → 方法体从 `.so` 中切出（VA 经 PT_LOAD 映射为文件偏移）。`encrypted-payload`：每个"声称是 DEX 但字节不是 DEX"的文件自动成为卡点——无熵阈值，只有机械事实——附 64 KiB 头部切片、以事实形式列出的 asset 原始熵、以及机械定位的解密例程候选（`JNI_OnLoad` 符号表命中、`.init_array` 段位置）。

- **卡点外包循环——全流程唯一烧 token 处**
  `exuvia next --goal goal.json` 打包卡点工作包（范围闸数据源 + 证据引用 + 族知识引导）。外部 LLM 返回 `proposal/` 包：一个纯函数解密实现 + 测试对，且期望值必须来自独立格式事实（DEX magic），绝不许来自提交者自己的输出。循环的驱动者永远在工具之外。

- **四层 merge 闸门，判定权在 Rust**
  ① 语法/格式（serde 解析，未知字段拒绝）→ ② 对账（范围闸：只认领工作包内的 debt id；hash 字节精确；`accepts_equivalent` 路由）→ ③ 语义（**双锚**：可信侧结构断言解析 DEX × 沙箱内字节测试——两锚永不同时依赖不可信层）→ ④ 销账：归档产物、移除欠账、追加 `attempts.log`。拒绝以 `code + detail + hint` 结构化输出给 Agent 读，并对被认领的卡点递增 `attempts`。

- **merge 即得 L1**
  `recovered` 产物的输出呈 DEX 形状时，归档为 `workspace/<debt_id>/recovered.dex`——立即可用 jadx 打开导航。

- **加固沙箱，零落盘**
  胶水执行器以字符串资源内嵌于二进制，经 stdin 喂给 `python3 -I`——不释放任何文件到磁盘（安全工具不得长得像恶意软件，否则会被分析机上的 AV/EDR 盯上）。环境清空；CPU 10 秒 / 地址空间 512 MB / fd 64 的 rlimit 兜底 5 秒软超时；文本级 import 白名单防误用。

- **敌意输入加固**
  任何 size/offset 字段先对照数据长度校验、再谈分配——DEX 解析器经过"伪造 126 GB 分配攻击"的实战检验。损坏的 DEX 是*事实*（`magic_ok`/`parse_ok`），永远不是整次剖析的崩溃。

- **产物字节确定**
  无时间戳、debt 稳定排序、熵保留 3 位小数：相同输入产出逐字节相同的剖析包。确定性是协议级要求而非锦上添花——CI 的 fixture 双向锚定依赖它。

- **CLI 就是 API（刻意不做 MCP）**
  输出全程 JSON，结构化错误码表公开在 SKILL.md §5；退出码只有两个语义世界——`installation-broken`（自身组件损坏：拒绝运行，退出码 2）与 `unavailable`（外部能力缺席：降级标注，绝不失败）。`--profile` 覆盖 SKILL fence 内嵌的默认判断；`--resume` 幂等跳过重复剖析；`--json` 连 `--version` 也机器可读。

- **诚实的欠账，厂商中性的命名**
  debt 条目只含事实与难度信号，没有成本预估（确定性二进制不知道 token 价格，价格由你估）。指纹、SOP、处理器一律按**技术族**命名（"整体加密-单段型"、"JNI 翻译习语"）——永不写厂商名，这是设计，也是对社区贡献的强制要求。

## 📐 卡点外包循环

```
exuvia packed.apk ──► handoff/   (REPORT.json+md · debt.json · evidence/ · workspace/)
        │                          全部机械工作，零 token
        │
        │   读 REPORT + debt，写 goal.json             （语义定位
        ▼    ——也是你的；工具只匹配机械事实                 也是你的）
  exuvia next --goal goal.json ──► workpackage.json      （范围闸数据源）
        │
        │   解工作包：纯函数解密实现
        ▼    + 来自独立事实的测试对                      唯一烧 token 处
  外部 LLM ──► proposal/
        │
        ▼
  exuvia unpack merge proposal/
        │   ① serde  ② 范围+hash  ③ 双锚语义  ④ 销账
        ▼
  欠账销账 · workspace/<debt_id>/recovered.dex ──► validate，或进入下一轮
```

每个卡点两条产出路径，按成本比较选择（你的比较）：`recovered`（还原原始字节）vs `equivalent`（写出功能等效实现）——后者要求 goal 里 `accepts_equivalent`，且过的是行为差分而非字节测试。

## 🚀 快速开始

从源码构建（暂无 release 二进制——计划中的发行形态是两平台二进制 + SKILL.md + checksums，仅此而已）：

```bash
cargo build --release
```

前置：PATH 上有系统 `python3`。它是 merge 闸门语义验证的沙箱执行器——设计上的*绑定*组件（IDA 式前提），绝不捆绑；缺失或伪造 = `installation-broken`，工具拒绝运行而不是降级。

```bash
# 1) 剖析（零 token）
exuvia packed.apk

# 2) 读 handoff/REPORT.json + handoff/debt.json，然后写 goal.json。
#    语义定位是你的活；每个字段机械可判定：
cat > goal.json <<'EOF'
{
  "$schema": "exuvia.goal",
  "goal_version": 1,
  "targets": [{ "kind": "payload" }],
  "levels": { "default": "L2" },
  "tracks": ["A"],
  "accepts_equivalent": true,
  "stop": "targets-satisfied"
}
EOF

# 3) 打包卡点工作包（机械筛选，不排序，不评价）
exuvia next --goal goal.json

# 4) 外部 LLM 读工作包，产出 proposal/
#    （纯函数 bytes→bytes，测试对期望值来自独立格式事实）

# 5) 回流：四层闸门，双锚验证，Rust 侧判定
exuvia unpack merge proposal/

# 6) 下游对剖析包自检
exuvia unpack validate handoff/
```

## 🧩 CLI 参考

| 命令 / 参数 | 语义 |
|---|---|
| `exuvia packed.apk` | 拖入即用剖析 → handoff/ |
| `--resume` | 幂等：剖析包的 APK sha256 一致时跳过重剖析 |
| `--profile <file>` | 覆盖 SKILL.md fence 内嵌的默认判断（TOML；解析失败 = installation-broken） |
| `--json` | 输出本就恒 JSON；此 flag 连 `--version` 也 JSON 化 |
| `--version` | 版本 + 支持的协议版本 |
| `exuvia next --goal <file>` | 打包卡点工作包（范围闸数据源） |
| `exuvia schema --dump <handoff\|goal\|proposal>` | 按需派生机器可读格式视图（无静态 schema 文件） |
| `exuvia unpack merge <dir>` | proposal 回流：四层闸门 → 销账 |
| `exuvia unpack validate <dir>` | 剖析包自检（下游消费前跑） |

退出码：**2** = `installation-broken`（自身组件；拒绝运行——不存在降级模式）；**1** = merge 拒绝，stderr 上是结构化的 `code + detail + hint`；**0** = 成功——**带欠账的剖析包也是成功**（欠账是交付物，不是失败）。

## ⚙️ 环境要求

- **操作系统**：Linux x64（当前 CI 基线）。Windows exe 是计划中的发行目标；OS 级沙箱当前只实现 Linux rlimit，Windows Job Object 路径排在 release 工程期。
- **构建**：Rust stable（edition 2024）。
- **运行**：系统 `python3`（沙箱验证层——绑定，绝不捆绑）；无需 root；默认预期敌意输入，建议在可弃置的一次性快照环境中分析。
- **不发行也不需要任何其他运行时**：流水线不携带任何自有 Python 发行物。

## ⚠️ 项目状态

研究级，v0.1。协议全链（`packed.apk` → next → merge → validate）已实现，并在合成样本上毕业（36 项测试、CI 强制的 fixture↔serde 双向锚定、产物字节确定）。**尚未与真实加固样本交手**——真实一代壳的第一次剖析是下一个里程碑，其后的一切都预期会让这门工具学会谦逊。

诚实的范围边界——静态/模拟分析解决不了这些，欠账清单会如实标注而不是假装能解：设备环境派生的 key（IMEI、build fingerprint）、网络拉取的 payload、流式拼装的 DEX、VMP 的完整语义还原（最后一项属轨道 C / L3 范畴——交付"等价语义"，不是原始字节）。

终点按行为定义，不按字节：一台**行为一致（behavioral parity）的可安装、可运行 APK**。还原原始字节是一/二代壳最可靠的*手段*；原始字节不存在的四代壳，由等效实现顶上。

## 🚫 非商业声明

本项目由开发者出于个人兴趣与技术研究目的发起，具有**非商业**性质：

- **永久免费**：
本项目完全免费，**没有任何付费功能、会员、订阅或内购**。所有功能对所有用户完全开放。

- **无赞助渠道**：
作者**从未开设任何赞助渠道**，也**不接受任何形式的金钱捐赠**——以保持项目的中立性与纯粹性。

- **非营利目的**：
本项目不涉及任何商业运营，作者不会从中获取任何直接或间接的经济利益。

- **研究导向**：
本项目始终定位于**安全研究、加固对抗研究、软件测试与教育**——为社区提供研究工具，而非商业产品。任何对本项目的商业使用均为使用者个人行为，与本项目无关。

- **仅限 AGPL-3.0，无商业例外：**
本项目以 AGPL-3.0 条款提供（见 LICENSE），一切使用均须完整遵守该协议。
选 AGPL 而非 GPL 是**故意的**：堵住"封装成付费 API 不开源修改"的口子。
作者不提供、也不协商双许可、商业例外或专有再分发。
无视 AGPL 义务转售牟利属于侵犯著作权。

- **署名与声明完整性：**
再分发未修改的构建时，必须附带本声明并正确署名。禁止在再分发时移除、篡改或隐藏本非商业声明。

- **仅限官方渠道：**
请仅从本仓库（GitHub）或其他官方指定渠道获取本项目。任何其他来源的构建均为非官方、未经验证，使用者自负风险。

## ⚖️ 免责声明

- **用途限制**：
本项目仅供**安全研究、加固/壳对抗研究、审计你自己拥有或被授权测试的应用、以及学习交流**使用。
请勿将本项目用于任何非法用途（包括但不限于软件盗版、破解并再分发第三方应用、规避技术保护措施侵犯版权）。

- **只分析合法持有的样本。**
使用者须对所分析样本的合法持有自行负责。本项目不针对任何特定加固厂商：壳可以被*识别*（行业惯例），但指纹、SOP 与处理器一律按技术族命名——永不写厂商名，社区贡献遵循同一规则。

- **Exuvia 是恢复器，不是 patcher——这是设计，也是法律边界：**
Exuvia 还原或忠实复现行为，不做篡改。签名自校验逻辑与其他任何逻辑同等对待、忠实还原——恒真 patch 永不在功能面。这条线同时也是"研究恢复"与"破解"的分界线。

- **后果警示**：
脱壳与重打包**可能违反第三方软件的服务条款及你所在司法辖区的法律**。使用前请自行评估风险。开发者与贡献者**对由此产生的任何法律责任或其他后果概不负责**。

- **研究级质量**：
本流水线为研究级，尚未在真实加固样本上验证；结果可能不完整（欠账清单是交付物，不是失败）。请在适当隔离的环境中分析样本。

- **无担保**：
本软件按其许可证条款提供，**不附带任何明示或默示的担保**，包括但不限于适销性、特定用途适用性与非侵权性。

- **责任限制**：
在适用法律允许的最大范围内，**无论是否被告知可能性，作者或贡献者均不对因使用或无法使用本软件而产生的任何直接、间接、附带、特殊或后果性损害承担责任**。

- **用户责任**：
使用者须自行承担使用本项目所产生的一切法律责任。

- **最终解释权**：
本免责声明的最终解释权归本项目作者所有。

## 💬 联系方式

欢迎通过 GitHub Issues 提交问题、建议与 bug 报告。

## ⭐ 支持项目

如果你觉得本项目对你有帮助，或认可它在技术研究上的价值，欢迎在 GitHub 上点一个 ⭐。

你的支持能让更多人发现这个项目，也能让作者感受到持续维护的意义。

感谢你的认可。
