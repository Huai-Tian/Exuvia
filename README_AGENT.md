# README_AGENT.md — Exuvia（蝉蜕）项目协作文档

> **本文档的读者是 AI（LLM Agent），不是人类。**
> 用途：当你在本仓库进行二次开发、续写、重构或修 bug 时，先读完本文档。
> 它记录了项目的全貌、进度、已拍板的决定、以及**故意反直觉的设计**——后者尤其重要：
> 有些设计看起来像缺陷或可以"顺手优化"，实际上是用数轮讨论（或真机事故）换来的结论。破坏它们 = 破坏项目。
>
> 本文档本身是协议的一部分（与三条协议数据流同级）。**修改本文档需要人类维护者确认**，
> 尤其是第 7、8 节（原则与决策日志）。

---

## 0. 三十秒版

Exuvia 是一个**面向 AI Agent 的 Android 通用脱壳 / 修复流水线**，主攻新一代企业级加固壳。**两条产品线，一个二进制**：

- **产品线 a（脱壳外包循环）**：`exuvia packed.apk` → 剖析包（L1 骨架 + 欠账清单 + 证据切片），智能缺口压缩成工作包外包给 LLM，回流经四层闸门销账。零 token 机械层全在二进制内。
- **产品线 b（修复管线，SKILL §7）**：`exuvia repair packed.apk [dumped.dex]... -o out.apk [--dump <dex>]... [--extra-dex <dex>]... [--from-handoff]` → 单命令把第三方 dump 修成可安装可运行的 APK——壳的手术标记全清（wrapper Application、壳 dex、壳资产、织入字节码、native stub），v2 重签。**这是当前的主用例**：第三方 dump 服务遍地，但没人把 dump 修回可启动的 APK。三条 dex 通道不可互换：位置参数分诊后重打包为 classes.dex；`--dump` 只作还原来源、永不进成品；`--extra-dex` 原样直挂为 classes2..N（脱壳阶段闸门产物专用，不重序列化）。**源头通道 `--from-handoff`**：直接收集闸门产物（`handoff/workspace/*/recovered.dex`）进发货通道——sha256 去重、无显式位置参数时最大者提升为主 dex、其余保序直挂；脱壳到修复一条命令，无需手工搬文件。
- **形态**：Rust 单二进制（Linux musl / Windows exe），**不携带任何 Python 发行物**——系统 python3 是前提假设（IDA 模式）；修复管线的 Python 工具链以 `include_bytes!` 内嵌于二进制（编译时嵌入、运行时提取到临时目录，不改"不发行 Python"纪律——发行物是二进制，工具链是二进制的内嵌资源）；重依赖（dexlib2 jar / apktool.jar）用户侧安置，git 只发源码。
- **本体论**：躯体（单二进制，内含全部自身代码）· 灵魂（SKILL.md 单文件）· 接口（三条协议数据流：handoff / goal / proposal）+ 修复管线（SKILL §7 文档化）
- **名字**：Exuvia（蝉蜕）——壳留在原地，代码恢复生命
- **口号**：*"Separate the shell from what lives inside."*

**项目当前状态（2026-10-22，GitHub `1fdc8df`）：**

- **第一战（脱壳线，360 技术族）**：解密链已全解（变体 RC4 / SM4-CFB / 密钥派生 / 运行时表置换——全链坐标见 §0.5 事实表）；classes.dex 尾容器（1MB 原始 App 代码）的 key 确认为**运行时构造**——静态穷尽（588 RC4 参数组合 + SM4 全模式 + 材料格点全扫 = 0 命中）。这是脱壳线唯一剩余卡点，优先级低：修复线已绕过此需求。
- **修复战役**：**v12 产物真机双双成功**（12 轮交付、11 个根因、2 个产物、2 次真机成功）——两个不同脱壳器的 dump（56.al 紧凑重排 1.85MB / fulldump 内存展开 4.5MB）经同一修复管线产出均正常运行（Oppo/Android 15+/targetSdk 36）。五重验收门（verify_all.py）+ 修复工具链产品化。
- **第二战（dex2c 翻译族）**：**闭环 APK 维护者真机确认（2026-10-21/22）**——无 dump、无参照，从 JNI 语义重建方法体。工具链自动化已收官：dexcontainer.py 尾容器重建、jnitrace.py（`--init` 运行时预热 / `--seed-dex` clinit 静态域播种 / `--arms` 空值守卫双臂枚举）、TLS 字符串离线物化（so_emulator emutls 契约仿真）、trace2smali.py（`--sigs-dex` 空心 stub 签名自动提取）、verify_all V4 多 dex 并集修正。SKILL §8 族 2 入册。
- **产品化**：`exuvia repair` 子命令上线（Rust 壳 + 内嵌 Python——不重写 12 轮真机验证的工具链）；方法体**四来源体系**：`--dump`（第三方 dump，多来源互补，**生产主路径**）/ `--reference`（原包，**内部测试专用**）/ StubSafe **框架契约兜底** / dex2c 源（jnitrace→trace2smali，无 dump 可恢复，SKILL §7）。
- **契约层**：六协议物 fixture 双向锚定、SKILL_VERSION 1.10.0、CI 全绿。**锚点纪律（血泪教训）**：SKILL_VERSION 升版必须**同一 commit** 改 `src/version.rs`——1e5b601 只改文档导致锚点漂移、CI 连红（1fdc8df 修复）。
- 产品线 a 契约面：卡点两类（method-native-stub：ACC_NATIVE stub + JNI 符号定位 + 方法体切片；encrypted-payload：坏 DEX 文件 / 声明区域内未申报尾区 / so 内明文 DEX 扫描命中 / assets ELF 零命中负事实四机械来源）+ 解密例程候选机械定位（JNI_OnLoad / init_array 双路径：PT_DYNAMIC 运行时视角优先）。
- 外循环闭合且留痕：`exuvia packed.apk → next --goal → [LLM 解卡点] → unpack merge（四层闸门 + 沙箱双锚 + 销账）→ validate`；merge 拒绝时 attempts.log 记 merge-rejected + 被认领卡点 attempts 递增；recovered DEX 形状产物归档 workspace/<debt_id>/recovered.dex；洋葱二次分析 `analyze --dex` 回注解卡产物 → 下一层欠账地图。
- CLI 契约表全兑现：--version / --profile / --goal / --json / --resume、next、schema --dump、unpack validate / merge、analyze --dex、hunt（含变体 RC4 参数）、repair。
- 实战修正（真实样本驱动，全部机械规则、零厂商特判）：DEX 解析器按规范对齐（method_id 8B / type_list u16）；assets ELF 纳入清点与符号查表；so 内明文 DEX 机械扫描；PT_DYNAMIC 运行时视角双路径 + ELF64 全架构符号。
- ci/verify（cargo workspace member，不进发行物）：register 语料登记 + check 原包对账——比对逻辑公开、样本私有。
- 终点定义已拍板（2026-10 桌面化修订）：桌面三重验收（结构对账 + DEX 全量可解析 + 语义复原判定，§2.1）+ 忠实还原原则；真机只做最终确认，不进验收链。

## 0.5 战役档案（终态事实底座——接手 Agent 从这里继续）

> **🏁 里程碑：v12 修复产物真机双双成功（2026-10-21）**——两个不同脱壳器的 dump 经同一修复管线产出的 APK 均安装→启动→正常运行→无 crash（Oppo/Android 15+，targetSdk 36），跨脱壳器通用性验证通过。第二战 dex2c 闭环 APK 同月真机确认。

### 0.5.1 修复战役：12 轮真机反馈的根因 → 不变量（每一行都是一次交付事故的闭环）

| # | 根因 | 结晶（工具已吸收；方法论留档） |
|---|---|---|
| 1 | 交付管道二进制污染（文本化机制把 ≥0x80 字节替换为 U+FFFD；非管线缺陷） | **二进制交付物一律 tar.gz + SHA256SUMS**；签名层无辜时先怀疑传输 |
| 2 | R+ 安装门：resources.arsc 必须 STORED 且 4 字节对齐，Python zipfile 从不保证 | 写出循环内嵌 zipalign（extra 替换为纯 padding）+ arsc 强制 STORED |
| 3 | 签名器三 bug（算法 ID 错标 0x0101/0x0103、顶层摘要缺 0x5a 前缀、section 切分违规） | **签名/摘要类代码的验收判官必须是第三方独立实现**（同源互证三 bug 全存活过） |
| 4 | P8：重排 writer 把 type_list 拆两段写两条 map 条目 | ART 要求每类型恰好一条 map 条目；doctor P8 物理相邻验证 + 结构宽度 walk 合并 |
| 5 | P9：截短文件后 data_size 未同步 | **终态不变量**：任何改变文件长度的修复后统一 `data_size := file_size - data_off` |
| 6 | P10：壳把 annotation 区改写为工作态数据，dump 冻结 | **encoded_value 存在于 static_values + annotations 两处，修一处不等于修完**；外科式解除引用（off:=0 规范合法） |
| 7 | P11：ART 第三条扫描路径（map 声明区逐条 walk） | map 条目**删除式**修复（缺失合法、清零非法）——**对刚性判官，绕过要选最接近其原生容忍的形态** |
| 8 | 壳织入字节码（12 桥 + 2 探针）致 NoClassDefFoundError | deweave 字节级原位恢复；**否决合成 StubApp 桥接类**——还原包不得引入原包没有的类 |
| 9 | 内存态 dump 的 map 布局修补不可收敛（单点修复总撞下一层检查） | **布局错误必须整体重建**——dexlib2 DexPool 标准布局重序列化 |
| 10 | P11 初版用"count 清零"（ART 不认空壳条目） | 同 #7：改条目删除式 |
| 11 | 壳 native-stub 入口钩子：onCreate access_flags 加 native 位 + code_off 清零 | 方法级惰性解密不回填（32 个 fulldump dex 零命中实证）；Restore 语义级 merge → 方法体来源体系 |

**五重验收门**（trackb/verify_all.py，ALL GREEN 才 ship）：V1 zip 层（完整/对齐/arsc STORED）→ V2 病理层（doctor P0–P11 全 audit CLEAN）→ V3 严格层（dexlib2 完整反编译）→ V4 内容层（织入残留=0 + 组件自包含，多 dex 并集）→ V5 签名层（apksigtool 全验签）。**修复一次、本地全量验收、真机只做最终确认**——逐轮真机打地鼠不可规模化。

### 0.5.2 产品化拍板（修复战役收官 → `exuvia repair`）

- **形态**：Rust 壳 + `include_bytes!` 嵌入 Python 工具链（编译时嵌入/运行时提取 `<temp>/exuvia-repair/<hash>/`，幂等）——**不重写 12 轮真机验证的工具链**（重写引入新 bug 的风险 > 语言统一的收益）。
- **方法体来源体系**：`--dump` 多来源互补 = 生产主路径；`--reference` 原包 = 内部测试专用；无来源时 StubSafe 契约兜底（native + 生命周期名 = 壳抽取铁证 → 合成 `invoke-super` 契约等价体并清 native 位；**抽取+nop 填充族**（爱加密形态）的孪生铁证 = 框架载体类上的生命周期 nop 墙——指令仅 nop/零值 const/return 且 ≥1 nop——同样合成契约体；其余 native 保留 = lib/*.so 支撑的合法 JNI，**必要且无副作用的残留直接复用，不为等义而等义**；非生命周期墙同为保留——已是可验证空操作，唯来源真体能真填）；dex2c 族走第四来源（JNI trace → smali 合成，SKILL §7/§8 族 2）。
- **已知语义边界（如实）**：契约体保证"可安装、可启动、不崩"，但不含业务逻辑——onCreate 被抽取且无任何来源携带其方法体时产物白屏（信息论边界：该信息不在任何可得载体中）；恢复依赖来源。

### 0.5.3 脱壳线终态（360 技术族；容器 key = 唯一剩余卡点，低优先级）

- **壳形态（双 blob 架构）**：so 内嵌 blob（VA 0x30138, 836KB）= stage-2 interpreter 引擎（**已解密**：静态 key 变体 RC4 → inflate → 1.9MB 载荷）；classes.dex 尾容器（[0x4000:]，1MB）= 原始 App 代码（**未解密**：key 运行时构造）。
- **Stage-2 布局**：stage2_elf.so = payload[0x27d01:]（1.75MB 剥离 magic 的 ELF64）；payload 头部 163KB = XOR 0xCC 方法/符号映射表（24B/条）；代码区 [0x31000,0x1ab320) ≈ 1.5MB 全明文（GOT 由 Stage-1 微型 linker 运行时填充）；真加密区 [0x9470,0x31000) = 162KB（熵 7.999）；interpreter_wrap_* 六签名 JNI 桥。
- **容器解密链已定位**：SM4-ECB（Stage-2 VA：wrapper 0xd69b8 / init 0xd6d60 / crypt 0xd6e34 / block 0xd6e8c / key_exp 0xd6c1c）+ ZSTD 导入实锤（容器格式大概率 [u32 len][ZSTD(DEX)]）；容器双段结构（[0:8] XOR C6 头；段1 952,740B + 段2 51,280B，段2 @32 引用段1 头部 4B——密钥/校验/索引候选）。
- **容器 key = 纯运行时构造（终局负空间）**：静态穷尽全维度 0 命中——SM4-ECB/CFB × {MD5(cert)/MD5(pkg)/组合/hex}、RC4 变体全参数、rc4mat 4 材料源、壳工作区/RK/轮密钥/尾部全扫。**key 不存在于 dump/静态容器/壳工作区的任何位置。** 触发矩阵负空间：解密发生在 attachBaseContext（需先 RegisterNatives），不在 JNI_OnLoad/Workers 阶段——获取 key = 完整模拟 attachBaseContext 生命周期（工程量大）或真机运行时捕获。
- **模拟环境已固化**（so_emulator，unicorn 2.1.4）：`--chain '0x2c5b88;x0=VM,0x2c55fc,0x2c55ac' --java --utf8-file <pkgname> --sig-file <cert> --fs <apk> --load so_reloc_image:0x70000000 --poke 0x2e40d0:<base> --poke 0x2e4008:0x1234` → JNI_OnLoad 0x10004 ✓ + workers 生成 ✓ + init_array ✓ + SM4-CFB 运行时表自然解密 ✓（IV=MD5(pkg) 逐字节实证）。
- **战略决策（已拍板）**：修复线已闭环——容器解密是"追求字节级完美"的增强功能。优先级：产品化（已完成）> 更多壳样本 > 容器解密。

**语料**：`/workspace/corpus/`——`ssd-free-r1.orig.apk`（原包，v2 签名）、`ssd-free-r1.packed.apk`（加固包）、`extracted/`（壳 APK 解包：classes.dex + assets/libjiagu*.so 四架构）、`handoff/`（attempts.log——**先读它**；r 轮摘要以 git 提交信息与本文档为准）。

**全链技术事实表**（全部已验证；地址均为 libjiagu_a64.so VA）：

| 层 | 坐标 | 语义 | 状态 |
|---|---|---|---|
| Java 壳层 | com.tianyu.util.a.a(String) | per-char XOR-0x10 字符串解密 | 已解 |
| JNI 入口 | attachBaseContext→interface5/99/21 | RegisterNatives 动态注册 | 已测绘 |
| 签名验证 | 0x2c8f34（s2=MD5(证书) @0x2c8fec 输入 674B；s1=MD5(包名) @0x2c9000） | 运行时哈希 vs 内嵌期望 = 加固时原包签名 | **黑盒贯通**（喂真证书+包名） |
| MD5 | 0x2c5cfc | 标准 MD5 | hashlib 逐字节验证 |
| 变体 RC4（DynCryptor） | 0x7984（PRGA 0x6b7c，KSA 0x6a54） | i/j 种子 3/5、i+=2、j+=S[i]+1；静态 10B key `76565734239123535674`（so 偏移 0x1cc44+0x7456 锚） | **全解**（KSA 与 unicorn 快照逐字节双验证） |
| 第二 cryptor | __arm_c_1 @0x6f90 | 同款变体 PRGA + **动态 key**：[this+0x28] 材料、[this+0x30] 长度 | 消费侧全测绘 |
| key 材料格式 | 0x7184 预处理 | 14B 头：[6..7] keylen、[8..9] 旗标、[0xe] 移位；KSA key = 载荷+0x28 | 已解码 |
| **第二引擎** | 0x2c7298 = **国密 SM4 CFB（IV=s1=MD5(包名)，key 材料=s2=MD5(证书)）** | S-box @0x2caf00（与 GB/T 32907 标准表逐字节一致）；RK 由 0x2c677c 展开（s2 XOR 模板 @0x2e4010）；**标准 CFB 语义（反馈=输入块）**：块1=E(s1)、块n=E(前输入块) | **完全破解**（python 80B 全对） |
| IV 来源 | s1 = MD5(包名)，经 arg x1 从调用者栈 [sp+0x70] 拷入引擎 | `--watch-write` 取证写入者 0x2c6138-0x2c61a4（MD5 存储循环） | 钉死 |
| RK 固化 | s2 材料 → `--fn 0x2c677c --dump-mem` | 黑盒产物 128B（LE u32[32]），sm4recon 消耗时 `struct.unpack('<32I')` | 可直接复用 |
| 结构表落点 | [0x2e40d0] | interpreter 结构表指针；SM4 输出 memcpy 于此（0x2c584c）；后置 0x2c78fc = base64 解码；**运行时表 = 置换指针表**（[t+0x18]=值池偏移/[t+0x20]=count/表+0x24=索引字节/`pool[i]=pool[idx[i]]` 原地置换）；静态 0x2e8d00 区 = 模板（≠ 运行时表） | **已解**（影子副本装载 → 引擎自然解密） |
| 分发器 | 0x2c566c | [t+0x50]=count、[t+0x54+i*8]=偏移+基址重定位 | 已测绘 |
| interface 初始化 | __arm_a_1 @0xa94c | 0x9008→0x9140→0x9284→0x9bdc→0x9f84→0x9470 序列 | **已解**（dlopen 桥后装载链自然全通） |
| dlopen 遍历 | 0x567c（0x9008 内） | 微型 linker 自实现 dlopen 遍历 stage-2 的 6 个 DT_NEEDED 库；模拟器 dlopen stub 返 0 曾致 fallback 假象 | **已解**（dlopen/dlsym/dlclose 桥入产品） |
| **容器解密链**（stage-2 VA） | wrapper 0xd69b8 / init 0xd6d60 / crypt 0xd6e34 / block 0xd6e8c / key_exp 0xd6c1c | **SM4-ECB** 16 字节块循环 + ZSTD 解压导入；触发点在 attachBaseContext（需 RegisterNatives 先行） | 链路全测绘；**key = 运行时构造**（静态穷尽 0 命中） |

**分析路径命令手册**（黑盒入口全部现成；完整生命周期会话模式见 §0.5.3 模拟环境）：

```bash
# 1. 提取签名材料（sigx 与手工提取逐字节一致）
trackb/sigx.py ssd-free-r1.orig.apk --out sigs/          # cert_1.der
printf 'detect.screenshot\0' > pkgname.txt               # packageName

# 2. JNI_OnLoad 黑盒全链（签名验证贯通 → 返回 0x10004）
trackb/so_emulator.py extracted/assets/libjiagu_a64.so --fn 0x2c5b88 --java \
  --arg x0=0x620000030000 --sig-file sigs/cert_1.der --utf8-file pkgname.txt

# 3. SM4 离线解密（RK 先经黑盒固化；IV=s1=MD5(包名)，--iv 参数化）
trackb/so_emulator.py ... --fn 0x2c677c --arg x0=<out> --arg x1=<MD5(cert) 区> --dump-mem ...
trackb/sm4recon.py dec <密文> --rk rk.bin --iv <s1 hex>          # CFB 解密（反馈=输入块）
trackb/sm4recon.py scan <容器> --rk rk.bin --iv <s1 hex> --form all   # 块 1 常量 = E(s1) 全偏移扫描

# 4. 变体 RC4 参数空间搜索（第一战形态一行命令）
exuvia hunt --carrier <切片> --rc4 76565734239123535674 --rc4-stride 2 --rc4-seed 3:5 --rc4-jbias 1

# 5. 内存写/调用现场取证
--watch-write 2e40a0:100     # 写入者 PC+值
--watch 2c5830               # x0-x7 调用现场
```

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

### 2.1 终点定义（产品验收的最终形态；2026-10 桌面化修订）

Exuvia 的终点：**桌面可判定的代码恢复完成度**（桌面三重验收）。不追求字节级一致——字节只是手段；也不依赖装机运行——**真机/模拟器已从验收链摒弃**（成本高，且企业壳反检测使真机路线在主战场不可行；维护者拍板）。

桌面三重验收（全部机械可判或外包循环可判）：

1. **结构对账**：class/method coverage 对账（repack 产物 vs L1 骨架清点——ci/verify 与语料占位演练已达 100% 模式）；
2. **DEX 全量可解析**：recovered DEX 经 `exuvia analyze --dex` 全表 parse 自洽（magic/header/方法表零失败）；
3. **语义复原判定**：关键方法（goal 声明的 targets）由下游 LLM 按反编译证据判定语义复原——外包循环既有能力，工具不做终审。

- `recovered`（原始字节可得：一/二代壳）：恢复原始字节是达成验收的**最可靠手段**（字节回来了，结构对账天然全绿）；
- `equivalent`（原始字节不存在：四代壳）：等效实现 + 行为差分覆盖证明（差分在沙箱桌面跑，不上机）；
- 装机运行降级为**可选增强档**（用户自愿复核，不进交付必选链）；原包字节对账降级为 `ci/verify/` 的内部开发指标，不是产品验收标准。

**终点合成阶段 `repack`**（debt 清零或 goal 满足后触发；四组件按三次法则逐件生长，不预写）：

```
① DEX writer     还原/等效的方法体 → 合法 DEX（现有 parser 的镜像工程）
② 重组器          资源搬运 + Manifest 修复（loader 移除、Application 还原）——AXML 解析届时上桌
③ zipalign+自签  用户自愿装机时的硬前提（v2/v3；桌面验收不依赖）
④ 装机冒烟        可选增强档（用户自愿；不进桌面验收链）
```

**签名自校验条款（已拍板：忠实还原原则）**：Exuvia 是恢复器，不是 patcher。签名自校验逻辑与任何其他逻辑**同等对待**——`recovered` 忠实恢复，`equivalent` 忠实等价其机器码行为（含校验分支）。自签重包若因校验逻辑退出，这是忠实还原的**正确表现**，不是产品失败：装机复核（可选档）携带环境谓词（原厂签名物理不可复制，此项差异如实标注，不算还原缺陷）。恒真 patch 属于使用者的修改行为，永远不在 Exuvia 的功能面——这条线同时是"研究恢复"与"破解"的法律分界线。

**校验二分条款（维护者 2026-10-20 拍板，补充上一条款的归属范围）**：签名/环境校验按**归属层**二分——
- **App 层校验**（原包自己带的签名校验/环境校验）：App 自己的代码，**忠实还原对象**（上条款原文适用：自签退出是正确表现）；
- **壳层校验**（壳自身的签名校验/环境校验——第一战形态即此类：s1/s2 签名哈希喂壳内密钥派生）：**属于壳、不属于 App**。脱壳输出同功能 APK 时**随壳剥离**，不计入忠实还原范围，也无需等义复刻——壳的防御死在壳上，这是脱壳的定义而非 patch 行为。

终端交付物由此钉死：**同功能 APK**（repack 终点段产物）。原理上不可还原的方法（四代壳/VMP：原始字节码不存在），交付**等义判定**——从汇编反推功能相同的代码（L3 路径），"是否等义"与还原代码同为一等输出（工具不做语义终审，判定走下游 LLM 证据审）。

---

## 3. 架构

### 3.0 本体论：躯体 · 灵魂 · 接口

```
躯体  = exuvia 单二进制（Linux musl + Windows exe）
        · 轨道 A 引擎、闸门与判定、编排
        · 内嵌 Python 胶水 runner（字符串资源，stdin 喂给系统 python3，零落盘）
        · 内嵌修复工具链（include_bytes!，repair 子命令运行时提取）
灵魂  = SKILL.md 单文件
        · 方法论 · 格式示例（示例 = CI fixture）· profile fence · 族知识 guidance
接口  = 三条协议数据流：handoff / goal / proposal
        · 无独立 schema 文件：机器事实源 = Rust serde 类型；语义解释 = SKILL 格式章节
        · 机器可读形式按需派生：exuvia schema --dump
```

release = 两个平台二进制 + SKILL.md + checksums。**纯文件，无目录**。仓库同构：`src/`（Rust 单工程）、`SKILL.md`、`trackb/`（轨道 B 用户侧 Python 工具）、`tools/dexlib/`（Restore/StubSafe Java 源码）、`ci/`、`README_AGENT.md`、`LICENSE`。

**零发行纪律（结构三次法则）**：生态已有的东西一概不发行——系统有 python3 就不捆运行时；PyPI 有 qiling/frida 就不打包依赖；serde 类型能定义格式就不放 schema 文件；单文件装得下的判断就不拆目录。任何新结构元素（文件/目录/发行物）需要"同一需要出现过三次"的实证，不接受"将来可能有用"。

### 3.1 三轨道（2026-10 桌面化修订：真机/模拟器全面摒弃出验收链）

```
轨道A 静态分析   —— 解包、指纹、so 切片、解密例程定位与离线复现
轨道B 模拟执行   —— Unicorn 离线跑 so 里的解密函数（桌面级，trackb/ 工具）
轨道C 定点动态   —— 桌面级 mini-loader：Unicorn 模拟 linker + JNIEnv 桩跑 JNI_OnLoad，
                    截获 RegisterNatives 注册表（替代真机 hook 的运行时事实获取）
```

优先级永远 A > B > C。**新代壳战略下，轨道 B/C 是主路径而非推迟项**，L2/L3 从"可选层"升格为主交付物。轨道 B/C 的重依赖（unicorn、capstone）不进发行物，用户侧安装，缺席 = `unavailable`（功能级语义，与 jadx/ghidra 同类）；**核心闸门依赖的系统 python3 缺失 = `installation-broken`（拒绝运行）**。

**轨道 C 桌面化的第一级已内置**：`exuvia hunt`（L2 参数空间搜索器）——算法与 key 已知时（facts / LLM 复现），密文段起点/长度是机械可搜的有限空间。双谓词族：**流臂**（rc4 标准/变体、xor——keystream 从零对齐模型 × 全空间 offset × 判据链自决长度：zlib 流边界 / DEX file_size）；**块链容器臂**（aes-128-cbc-tail——trailer BE32 自述起点，头块长度 PKCS#7 + dex::parse 扫描自决，子容器长度前缀走查 + XOR 前缀剥离，与 trackb/dexcontainer.py 双实现互锚）。真机 frida hook 从主路径移除；**fence 族知识里的 hook 剧本重定义为桌面 Unicorn 桩剧本**（同一份截获逻辑，两种执行环境）。

**trackb/ 工具总表**（21 个 + protocol.md；工具本体随仓库分发 = 产品的一部分，重依赖用户侧安装）：

内嵌修复链（`include_bytes!` 随二进制发行，`exuvia repair` 运行时提取；含空壳填体四件 hollowfill/jnitrace/trace2smali/so_emulator）：

| 工具 | 职责 |
|---|---|
| repair_all.py | 单命令管线编排：doctor → clean → deweave → restore → stubsafe → surgery → zipalign → sign |
| dexdoctor.py | dump 病理分诊与急救（P0–P11：校验和/截断/map 布局/注解污染/type_list 分裂…） |
| dexclean.py | 壳/异源 class_def 清除（manifest 组件可达性，R8 混淆感知） |
| deweave.py | 壳织入字节码原位恢复（桥 invoke → 原框架调用 opcode 翻转；探针 → nop） |
| repair.py | 外科 + 装配（Manifest wrapper Application 移除、壳资产剥离、classes.dex 置换） |
| axmltool.py | 二进制 AXML 解析（Manifest 手术的基础件） |
| sign2.py | 最小 APK v2 签名器（RSASSA-PKCS1 + SHA2-256，python-cryptography） |
| hollowfill.py | 空壳自动填体编排（静态 JNI 表定位 → jnitrace → trace2smali → baksmali 拼接重组；jnitrace/trace2smali/so_emulator 随同内嵌） |

用户侧脱壳/分析工具：

| 工具 | 职责 |
|---|---|
| so_emulator.py | so 黑盒执行器（unicorn：ELF64 映射 + RELATIVE/GOT 重定位 + bionic libc 语义层 + JNI 假世界（RegisterNatives 捕获/SDK 喂值）+ --fs/--poke/--load 跨文件桥 + --sig-file/--utf8-file 喂值通道 + **emutls 契约仿真**（TLS 字符串离线物化）） |
| jnitrace.py | JNI 语义追踪器（fake JNIEnv + token world：`--init` 运行时预热 / `--seed-dex` clinit 静态域播种 / `--arms`/`--arms-max` 空值守卫双臂枚举）——dex2c 族方法体恢复的前半 |
| trace2smali.py | trace → smali 编译器（`--sigs`/`--sigs-dex` 签名来源；ART 校验三规则内建：hex jvalue=字面量、check-cast 对齐 receiver、4-bit 寄存器低刮擦带+invoke-interface）——dex2c 族的后半 |
| dexcontainer.py | 尾部容器 dex 重建（profile 驱动：[stub dex][加密头][dex 体][子容器]；per-dex sha1+adler 自校验 oracle，不可能假阳性） |
| disasm.py | 反汇编流生产器（PT_DYNAMIC 运行时视角符号解析，L2 evidence 标准附件，capstone 用户侧） |
| crypto_recon.py | 密文侦察（熵定位 / ECB 指纹 / AES 指令扫描 / hash-scan IV 扫描 / RC4 变体族扫描 / dxor Dalvik 字符串解密） |
| sigx.py | APK 签名链证书提取（喂 so_emulator --sig-file） |
| sm4recon.py | SM4 侦察/解密（GB/T 32907：CFB dec/enc、材料格点/zlib/dex 全偏移扫描、textbook rkexp） |
| elfrecon.py | 内嵌 ELF 恢复（从 dump/容器里捞完整 ELF） |
| fidelity.py | dump-vs-reference 保真报告（L0–L5；内部校准用"产业问题"度量） |
| verify_all.py | **五重验收门**（V1 zip / V2 病理 P0–P11 / V3 dexlib2 严格反编译 / V4 内容残留·多 dex 并集 / V5 apksigtool 验签） |
| repack.py | 终点合成装配器 v0（§2.1：恢复 DEX + 原 Manifest + 基准资源 → 未签名 APK） |
| exuvia_repair.py | task.json 协议版修复入口（protocol.md：unpacker ↔ repairer ↔ agent 交换格式 v1.0，pending_decisions 由 agent 填答续跑） |
| selftest.py | 合成 fixture 自检（零样本纪律） |

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
  "goal_version": 1,
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
| `--version` | 版本 + 支持的协议版本（skill/handoff/goal/proposal 四锚点） |
| `--profile <file>` | **覆盖** SKILL fence 内嵌的默认判断（判断外置通道；默认判断长在 SKILL.md 的 profile fence 里） |
| `--goal <file>` | 格式化目标文件（goal.json，见 4.1）。**自然语言 goal 已被推翻，勿改回** |
| `--json` | CLI 就是 API（不做 MCP 的代价） |
| `--resume` | 幂等、可断点续跑 |
| `exuvia next --goal <file>` | 打包当前最值得外包的卡点工作包（按 goal 相关性建议排序，工具不做终审） |
| `exuvia schema --dump <name>` | 按需派生机器可读格式（handoff/goal/proposal；handoff = report/debt/workpackage/evidence 联合视图；无静态 schema 文件） |
| `exuvia analyze --dex <file> [--out <dir>]` | 洋葱二次分析：解卡产物回注 → 下一层欠账地图（与 first_pass 协议同构；默认 handoff-2/） |
| `exuvia hunt --carrier <file> [--rc4 <hex>]... [--xor <hex>]... [--rc4-stride N --rc4-seed A:B --rc4-jbias N] [--aes-cbc <key>]... --aes-iv <iv> [--aes-xor-prefix 0x70 --aes-xor-key 0x66] [--out <dir>]` | L2 参数空间搜索：已知算法族 × 未知密文段参数 → 机械命中（hunt.json + hits/；变体 PRGA 参数修饰所有 --rc4 谓词；--aes-cbc 走 aes128cbc-tail-v1 容器臂：trailer 锚点 + 头块长度扫描自决 + 子容器走查，key/iv 支持 hex 或 16 字节 ASCII；负事实按谓词族诚实） |
| `exuvia repair <packed.apk> [dumped.dex]... -o <out.apk> [--dump <dex>]... [--extra-dex <dex>]... [--reference <dex>] [--from-handoff] [--allow-hollow]` | **产品线 b**：单命令 dump→可运行 APK 修复管线（SKILL §7）——doctor→clean→deweave→restore→stubsafe→surgery→zipalign→sign v2；JSON 输出全阶段统计；`--from-handoff` 源头通道把闸门产物（handoff/workspace/*/recovered.dex）直接收进发货通道；发货 dex 检出 native 生命周期桩（族 2 空壳）自动填体发货（hollowfill 四步：表定位→jnitrace→trace2smali→重组），`--allow-hollow` 仅分诊调试 |
| `unpack validate <dir>` | 下游自检 handoff |
| `unpack merge <dir>` | proposal 回流（四层闸门） |

`ci/verify/`（workspace member，不进发行物）：`ci-verify register <corpus-dir>` 语料登记 / `ci-verify check <orig.apk> <packed.apk> <handoff-dir>` 原包对账——内部开发指标，比对逻辑公开、样本私有。

**不存在 `--baseline`**：原包对账是仓库内 CI 工具，不是产品功能。产品面上永远只有加固包这一个输入——用户手里不需要有任何他不该有的东西。（repair 的 `--reference`/`--dump` 是方法体**还原来源**，不是对账基准——来源由用户自愿提供，来源缺失时 StubSafe 契约兜底，产物如实标注统计。）

**repair 的启动校验例外**：`exuvia repair` 跳过 SKILL fence 启动校验（`install::check`）——它是独立修复工具，不消费外包循环协议；系统 python3 仍是硬前提（内嵌工具链的运行时）。

**退出码二分语义**：

- `installation-broken`：系统 python3 缺失 / 版本不符 / probe 失败、SKILL.md fence 不可提取或不可解析——**拒绝运行**。自身组件没有"缺席"状态，只有"装坏了"状态；**不存在降级模式**。
- `unavailable`：jadx / ghidra / unicorn 等外部能力缺席——降级标注进 REPORT，相关层级照常标注，不 fail。这个词只属于外部工具。
- 有 L1 即返回 0（欠账是正常产出不是失败）；只有连 L1 骨架都产不出来才非零。**别用退出码惩罚架构上鼓励的行为。**

**Agent 人体工学**：`--json` 全覆盖、稳定退出码、无 TTY 假设、幂等、机器可读的错误输出（报错是给 Agent 看的）、格式文档与示例随 SKILL.md 分发。

---

## 6. 接口与灵魂先于代码

**第一个 commit 是 spec，不是源码**：

1. **SKILL.md**：30 秒版 → 工作流决策树 → 格式章节与示例（**示例 = CI golden fixture**）→ profile fence（TOML 代码块，info string 为 `toml profile`）→ 族知识 guidance → 版本锚点。SKILL 版本 = 文档内容 + fence 快照的联合版本。
2. **三条协议**（handoff / goal / proposal）：格式的初始事实源 = SKILL 格式章节，实现期翻译为 serde 类型，此后**双向锚定**——SKILL 示例必须能被 serde 类型解析通过，CI 强制执行（tests/skill_doc.rs）。
3. **默认 profile**：就在 SKILL fence 里（判断外置 = fence + `--profile` 覆盖通道）。

**schema 文件不存在（勿新增）**：schema 是视图不是实体——格式的机器事实源是 serde 类型，语义解释在 SKILL 格式章节，`--dump` 按需派生。两份独立描述必然漂移；**文档即测试**（SKILL 示例 = CI fixture）比 schema 文件的单向声明强得多。

**版本锚点三向绑定**：SKILL.md §9 锚点节 ↔ src/version.rs 常量 ↔ `exuvia --version` 输出。**升版纪律：SKILL_VERSION 变更必须同一 commit 修改 version.rs**（1e5b601 漂移致 CI 连红的教训——测试替文档站岗，红得正确）。

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
| 真机/模拟器为轨道 C 运行时事实的主路径 | 桌面化：L2 参数搜索内置（`exuvia hunt`）+ L3 桌面 mini-loader 候选 | 真机成本高且企业壳反检测使其在主战场不可行；算法与 key 已知时密文段参数是机械可搜的有限空间（判据链自决长度，零猜测） |
| 装机运行对比为验收线 | 桌面三重验收（结构对账 + DEX 全量可解析 + 语义复原判定） | 摆脱真机依赖；沙箱双锚哲学不变；装机降为用户自愿的可选增强档（真机只做最终确认，不做调试器） |
| 修复管线用 Rust 重写（候选立场之一） | **Rust 壳 + `include_bytes!` 嵌入 Python 工具链** | 12 轮真机验证的 Python 工具链重写 = 引入新 bug 的风险 > 语言统一收益；"不发行 Python"纪律不破（发行物是单二进制，工具链是其内嵌资源） |
| `--reference` 作为生产还原来源 | **`--reference` 内部测试专用；生产主路径 = `--dump`（第三方 dump/脱壳产物，多来源互补）** | 维护者拍板：生产场景没有原包；第三方 dump 是还原被抽取方法的最大助力（时机对了就携带解密后的方法体） |
| 无原包时"等义生成一切壳痕迹" | **契约兜底 + 必要残留直接复用** | 第一优先 = 移除壳的保护（hook 织入/签名检测/被抽取方法）；无生命周期契约的 native = lib/*.so 支撑的合法 JNI，无副作用复用即可——**不为等义而等义**（维护者拍板） |
| 契约等价体 = 完整还原 | **契约体只保证框架契约（可安装/可启动/不崩），不含业务逻辑——白屏边界如实标注** | 无来源时被抽取方法体不在任何可得载体（信息论边界）；伪造业务逻辑比白屏更糟（宁可白屏不可崩） |
| dex2c 翻译族"无 dump 不可恢复"（初判） | **JNI 语义即行为骨架：模拟执行原生函数记录 JNI 调用序列 → 直线 smali 体重建（jnitrace→trace2smali），全程桌面、无 dump、无参照** | 第二战实证毕业（维护者真机确认 2026-10-21/22）；方法体翻译出包≠信息消失，它活在 .so 的 JNI 边界的调用序列里 |
| SKILL 版本锚点只靠人工同步 | **SKILL_VERSION 升版必须同一 commit 改 src/version.rs**（CI 锚点测试强制执行） | 1e5b601 只升文档锚点（1.4.0）漏改常量（1.3.0）→ 每次 push 皆红；测试替文档站岗站得对，纪律写死 |
| encrypted-payload 三机械来源已足（盲区未自觉） | **第四机械来源：声明区域内未申报尾区**（良性 dex 的 file_size − (data_off+data_size) ≥ 0x70 → 卡点 + 尾区头切片）+ **hunt 块链容器臂**（aes-128-cbc-tail：trailer BE32 锚点、头块长度扫描自决、子容器走查；0x70 = dex 头最小量噪声地板） | 族 2 全链彩排实证：stub 把 file_size 抬高到整文件，尾容器对前三来源完全隐形——但 data_off+data_size 字段对如实自报边界（恰等于 trailer L）；同形态在族 1（360）样本回溯复现 = 跨族共用；块链谓词无 keystream 概念（链接态依赖前块），故 hunt 双臂分派 |

**语义等效还原（通用恢复策略，非四代壳专属）**：每个方法有两条产出路径——`recovered`（还原原始字节）与 `equivalent`（读 L2 反编译的机器码，写出功能等效实现）。路径选择按**成本比较**，判断者是下游 LLM（工具只给难度事实，不做终审）；goal 的 `accepts_equivalent` 字段声明目标是否接受等效销账，proposal 的 `claims[].kind` 路由闸门验证（recovered → 结构断言×字节测试；equivalent → 行为差分）。**差分证明的是覆盖行为上的等价，不是全面等价**——audit trail 只记事实。

---

## 9. 范围边界（诚实清单，勿过度承诺）

静态/模拟**解决不了**的（进 debt 清单，标注 out-of-scope / 需轨道C）：
- key 从设备环境派生（IMEI、build fingerprint——模拟可伪造枚举但组合爆炸；第一战容器 key 即此类运行时构造的实证案例）
- 网络拉取的 payload
- 流式拼装的 DEX
- VMP 的完整语义还原（轨道 C 定点动态 + L3"等价语义"范畴）

**四代壳处理原则**：原始字节码从不存在于内存，dump 原理上无解。两个亚型分别已有出路——**dex2c 翻译亚型**：方法体以 JNI C++ 形态活在壳 .so 里，JNI 调用序列 = 行为骨架，桌面模拟执行即可重建直线 smali 体（jnitrace→trace2smali，第二战毕业，SKILL §8 族 2）；**VMP 亚型**："汇编分析还原同等功能"不是退而求其次，是换了一个正确的问题定义——交付物从"原始字节"变成"等价语义"（.NET 的 OldRod 反虚拟化是先例）。残留物是机器翻译的汇编，有固定习语（JNI 边界调用、寄存器约定、模板化控制流）——精度可以很高，且"同等功能"对分析场景是低标准（要的是 API 序列和逻辑，不是指令级一致）。

---

## 10. Roadmap（工程顺序）

- **v0.1**：一代壳脚手架打通全协议（next / merge / resume / validate）+ 闸门沙箱（双平台）+ `ci/verify` 原包对账 + 语料生成脚本 ✅
- **已落地（v0.1 内追加）**：洋葱二次分析（`analyze --dex`）、轨道 C 桌面化第一级（`hunt` L2 参数空间搜索器，含变体 RC4 参数）
- **已落地（修复战役 + 产品化，2026-10）**：修复工具链（trackb/ 内嵌十一件：repair_all/dexdoctor/dexclean/deweave/repair/axmltool/sign2 + 空壳填体四件 hollowfill/jnitrace/trace2smali/so_emulator）+ 五重验收门 + `exuvia repair` 子命令（SKILL §7，--dump 多来源 / StubSafe 契约兜底）——**12 轮真机反馈闭环，v12 双产物真机成功**
- **已落地（第二战 dex2c，2026-10）**：dex2c 翻译族全链桌面工具链——dexcontainer（尾容器重建）/ jnitrace（--init/--seed-dex/--arms）/ so_emulator emutls TLS 物化 / trace2smali（--sigs-dex，ART 校验三规则）/ verify_all V4 多 dex 并集；闭环 APK 真机确认；SKILL §8 族 2 入册
- **其后**：轨道 B 工程化（qiling 适配 JNI 环境）、轨道 C 桌面化第二级（L3 桌面 mini-loader：Unicorn 模拟 linker + JNIEnv 桩）、L2/L3 主交付物化、多 Android 版本适配、evasion、指纹 diff 工具化、更多壳样本回归（修复管线的零样本泛化）、dex2c 多路径枚举增强（--arms 递归化）、容器解密（低优先级增强）
- **永久不做**：MCP（社区 contrib）、经验传递机制（哲学级取消）、指纹库自动增长（显式配置 only）、`--baseline` 产品接口、真机/模拟器进验收链（桌面化拍板，2026-10——真机只做最终确认）

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
| 桌面三重验收 | 终点标准（§2.1）：结构对账 + DEX 全量可解析 + 语义复原判定；装机降为可选增强档 |
| hunt / L2 参数空间搜索 | `exuvia hunt`：已知算法族（rc4/xor 流臂、aes-128-cbc-tail 块链容器臂）+ key × 未知密文段参数 → 全空间机械搜索；流臂判据链（zlib magic → inflate → DEX magic → 全表 parse）自决段长，容器臂链（trailer 锚点 → 结构判据 → 头块扫描 → 全表 parse）自决全部段参数；命中 = 机械事实（不销账），负事实按谓词族诚实落盘 |
| repack | 终点合成阶段：方法体 → DEX → 重组 → 自签 → 可运行 APK；四组件按三次法则生长（dexlib2 DexPool 标准布局重序列化已落地为 stubsafe/restore 阶段的序列化器） |
| repair / 修复管线 | 产品线 b（SKILL §7）：`exuvia repair` 单命令 dump→可运行 APK——doctor→clean→deweave→restore→stubsafe→surgery→zipalign→sign |
| 方法体来源 | 被壳抽取方法的还原载体：--dump（第三方 dump，生产主路径，多来源互补）/ --reference（原包，内部测试专用）/ StubSafe 契约兜底 / dex2c 源（JNI trace → smali） |
| StubSafe | 无来源时的兜底等义生成器（tools/dexlib/StubSafe.java）：native+框架生命周期名 = 壳抽取铁证 → 合成 invoke-super 契约体并清 native 位；框架载体类上的生命周期 nop 墙（抽取+nop 填充族孪生铁证）同样合成；其余 native 保留（合法 JNI 复用），非生命周期墙保留（可验证空操作）；兼作最终 DexPool 标准布局重序列化 |
| 五重验收门 | trackb/verify_all.py：V1 zip / V2 病理 P0–P11 / V3 dexlib2 严格反编译 / V4 内容残留·多 dex 并集 / V5 apksigtool 验签——ALL GREEN 才 ship |
| dex2c 翻译族 | 四代壳亚型：方法体被翻译为 JNI C++（常加 OLLVM 平坦化），原 Dalvik 不在包内；恢复 = JNI 语义 trace → smali 合成（第二战毕业，SKILL §8 族 2） |
| jnitrace / trace2smali | dex2c 恢复前后半：fake-Emulator JNI 调用序列追踪器（--init/--seed-dex/--arms）/ trace→smali 编译器（--sigs/--sigs-dex） |
| --seed-dex / --arms | jnitrace 自动化：`--seed-dex` 从任意 dump 扫描 clinit sput-object 目标并预置非空（设备真相，可推导）；`--arms`/`--arms-max` 枚举 token 空值守卫（CBZ/CBNZ——设备上环境相关的 JNI 结果）并对每个守卫产出一条强制翻臂 trace（单翻 v1，不递归） |
| emutls 契约仿真 | so_emulator 对 `__emutls_get_address`/`__cxa_thread_atexit` 的契约级模拟：TLS 编码字符串离线物化，不再依赖设备 |
| dexcontainer | 尾容器 dex 重建器（profile 驱动；per-dex sha1+adler oracle，不可能假阳性） |
| fidelity | dump 与参照的保真报告（L0–L5；内部校准度量） |
| task.json 协议 | trackb/protocol.md v1.0：unpacker ↔ repairer ↔ agent 的交换格式；pending_decisions 由 agent 填答后续跑（exuvia_repair.py 为入口） |
| 零学习曲线 | 不依赖历史积累，性能从第一次即峰值 |
| 结构三次法则 | 新文件/目录/发行物需"同一需要出现三次"的实证 |
| 躯体 / 灵魂 / 接口 | 二进制（含内嵌 runner 与修复工具链）/ SKILL.md 单文件 / 三条协议数据流 |
| 轨道 A/B/C | 静态 / 模拟执行 / 定点动态 |
| L1/L2/L3 | 骨架 DEX / 伪代码还原 / 可重编译源码 |
| 技术族命名 | 按加固技术特征（而非厂商）命名指纹与 SOP |
| 一代壳~四代壳 | 整体加密 / 方法抽取 / 动态解密+SO混淆 / VMP·dex2c |

---

## 12. 给接手 Agent 的行为准则

1. **动手前**：读完本文档；对照第 8 节确认你要做的事不在"已推翻"清单里——每条都是数轮讨论（或真机事故）换来的结论。
2. **写代码时**：判断逻辑进 SKILL fence，不硬编码；每个判断写 audit trail；不确定就输出不确定度；**判定权永远在 Rust**。
3. **想加东西时**：参数过三次法则；**结构也过三次法则**（新文件/目录/发行物）；先问"这是不是接口或灵魂的变更"——是的话先改 SKILL.md 再写代码。
4. **想"优化"时**：对照第 7 节 ⚠️ 条目。如果你觉得某条原则"明显更好"，大概率它已经在第 8 节被推翻过一次。
5. **涉及 Python 时**：不发行（发行物是单二进制）、不判定（"通过"只有 Rust 有资格说）。两类内嵌 Python 语义不同：merge 闸门的沙箱 runner = stdin 喂入 `python3 -I` **零落盘**；修复管线的工具链 = `include_bytes!` 内嵌、运行时提取到 `<temp>/exuvia-repair/<hash>/`（幂等）——两者的共同点是不随发行物携带任何 Python 发行物。
6. **改 SKILL.md 时**：fixture 与版本锚点是活契约（tests/skill_doc.rs 三向锚定）——改示例先想 serde 类型，**升 SKILL_VERSION 必须同一 commit 改 src/version.rs**（漂移 = 每次 push 皆红，1e5b601 实证）。
7. **跨环境交付文件时**：二进制交付物（dump/产物/补丁附件）一律 tar.gz + SHA256SUMS——文本化管道会把 ≥0x80 字节污染为 U+FFFD（根因 #1，一次签名层冤案的教训）。
8. **修改本文档**：可以补充事实和进度；修改原则/决策日志需要人类维护者确认。
9. **交付给下一个 Agent 时**：更新本文档的"当前状态"，像 debt.json 一样诚实记录你做了什么、什么没做完、为什么。
