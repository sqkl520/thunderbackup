# ThunderBackup 0.9.0-dist.1 · 使用说明

只读这一份文件就能完成：**装 → 跑 → 删干净**。下面每一个数字都是实测的，每一条承诺都对应包里某一行代码；
做不到的事写在第 7 节（`L-01`…`L-47`）与文末"遥测与判定的能力上限"两节里，没有藏在脚注中。

快速路径（复制粘贴即可，全部在 Windows PowerShell 5.1 里跑）：

```
cd <你解压本包的目录>
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -StoreRoot E:\ThunderBackup
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd doctor  -Config thunderbackup.config.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd once    -Config thunderbackup.config.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd once    -Config thunderbackup.config.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd status  -Config thunderbackup.config.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd verify  -Config thunderbackup.config.ps1 -Deep
```

---

## 1. 这是什么 / 这不是什么

**这是什么**：一个外部目录备份器。它周期性扫描你指定的下载目录，把文件复制进一个**内容寻址库**（blob 的名字就是它自己的
SHA-256），并给每个文件一个判定：`BACKUP`（有完成凭据）、`BACKUP_UNVERIFIED`（备份了，但本工具证明不了它写完）、
`WAIT`（本轮不动，下轮再看）、`SKIP`（不备份，理由逐条可查）。它跟着 NTFS 的文件身份走，所以迅雷把任务目录整体改名
之后，同一个文件的版本历史不会断（见 `L-10`）。

**这不是什么**（逐条对应代码，不是口号）：

- **不启动迅雷，不结束迅雷，不向迅雷发任何命令。** 包内没有任何迅雷进程控制路径；迅雷可以根本没在跑。
- **不写注册表。** 只读 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`
  和 `Registry::HKEY_CLASSES_ROOT`（后者用来确认 `.xltd`/`.td` 是迅雷的临时后缀）。`doctor` 第 [9] 节把前者的原始条数打回给你看，
  全程 `Access = read-only`。存储层源码里 `MoveFileExW` 的 `0x04/0x08/0x10/0x20` 标志是禁用的，原因见 `L-22`。
- **不装驱动、不装服务、不装任何二进制。** 包里只有 `.ps1` 与 `.md`；`build-check.ps1` 有一条门禁禁止 `.exe/.dll/.sys/.msi/.zip/.pdb` 进包。
- **不注入。** 没有 `CreateRemoteThread`/`VirtualAllocEx`/`WriteProcessMemory`/`SetWindowsHookEx` 之类调用；
  `build-check.ps1` 的 `contract` 门就是扫这个的。
- **不联网。** 没有任何网络 API；只调用系统自带的两个可执行文件：`fsutil.exe`（分配区间/USN 查询）与
  `certutil.exe`（仅在 `Add-Type` 被禁用时用来算哈希）。它们的存在在 `THIRD_PARTY_NOTICES.md` 里声明，并由 `doctor` 第 [12] 节打印出来。
- **不"读迅雷的任务库来判断完成"。** 这条路是故意没接的，理由与后果见第 6 节和 `L-02`。
- **写盘只落在这些地方**：① 你指定的备份库目录（`StoreRoot`：`blobs/ tx/ meta/ quarantine/ logs/ restore-undo/ store.json status.json skipped.log`）；
  ② 工具目录（`install.ps1` 复制的文件，默认 `%LOCALAPPDATA%\ThunderBackup`）；③ 你执行 `restore` 时指定的目标目录；
  ④ `doctor` 的一次性探针文件（32 MB，写在 `<StoreRoot>\logs`，不可写时退到工具目录 `var\`，再退到 `%TEMP%`，用完立刻删）；
  ⑤ `smoke_test.ps1` 的夹具目录（`%TEMP%\tb-smoke-<时间戳>`，默认结束即删）。
  **迅雷安装目录与被监视的下载目录，本工具一律只读**（并且拒绝把库放进它们里面，见 `L-30`）。

---

## 2. 前提条件

- **Windows PowerShell 5.1**（本次实测环境 `5.1.19041.7725`，`edition=Desktop`）。这台机器上没有 PowerShell 7（`pwsh`），
  本包也不依赖它：所有示例都用 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`。
- **语言模式 FullLanguage**。写路径需要 `Add-Type`（编译判据/存储层的 C# 探针）与 `New-Object IO.*`。
- 不需要任何第三方组件、包管理器、.NET SDK：只用系统自带的东西。
- **不需要管理员权限**：`install.ps1` 只写工具目录；只有你显式加 `-Schedule` 时才注册计划任务，
  而某些机器上那一步会失败——脚本会打印两条**不需要提升权限**的替代路径（换账户已有的调度器跑 `-Cmd once`，或自己在
  `taskschd.msc` 里粘命令行），文件本身照常装好。
- 磁盘：库的大小约等于你库里"不重复的字节数"，留 15% 余量；建议与下载目录同卷（跨卷时原子发布退化成复制+删除）。

**ConstrainedLanguage（CLM）机器的降级阶梯**——用散文说清楚，因为这里没有中间地带。
在 CLM 下（WDAC / AppLocker / Device Guard / 组策略都可能造成），`Add-Type`、`New-Object` 非核心类型、`[Convert]::`、`[math]::`、
以及 `Get-FileHash` 都不可用。这个包对此的态度是**把话说破**：

- **还能用的**：`-Cmd doctor`（能力报告照常跑，并明确打印 `DEGRADED-MODE`，告诉你哪些判据没了）；
  `-Cmd verify -Deep` 走系统自带的 `certutil.exe -hashfile`（外部进程，慢，但仍是逐字节重算，输出里会打 `DEGRADED: ...` 并声明它）；
  只读的判据降级层 `Get-FileObsCmdlet` 还能靠 `Get-Item` 保住**不需要 FileStandardInfo** 的那几条豁免
  （压缩/加密/offline/reparse/`eof<64KiB`/容器扩展名）。
- **不能用的**：空洞符号（G4 的核心输入）、`DeletePending`、`(VolumeSerial, FileId128)` 身份、"有没有持有者"探针——
  全部没了，于是**没有任何一条判据能给出完成结论**；写路径（`once`/`watch`）会直接拒绝运行并打印原因，
  而不是"跑一半、把 null 当成优雅降级"。`restore` 需要库已存在，因此也只在 FullLanguage 机器上有意义。
- 结论：CLM 机器上这台工具是**诊断与完整性复核器**，不是备份器。`doctor` 第 [1] 节每一轮都重新测语言模式，
  因为策略可以在跑到一半时生效；升级档位**不会**追溯批准已经落进 `needs-attention` 的条目。

---

## 3. 安装

```
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -StoreRoot E:\ThunderBackup
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -StoreRoot E:\ThunderBackup -Schedule
```

- `-StoreRoot <路径>`：备份库根目录，**唯一必填**。它会被写进工具目录里的那份 `thunderbackup.config.ps1`
  （只写自己那份配置，别处一个字节都不动），并保留该文件原有的 UTF-8 BOM。
- `-InstallDir <路径>`：工具目录，默认 `%LOCALAPPDATA%\ThunderBackup`。若目标已存在 `.ps1`，会要求你输入 `YES` 才覆盖
  （`-Unattended` 跳过提问）；备份库永远不在这个步骤里被触碰。
- `-Schedule`：**可选，默认不注册计划任务**。不加这个开关时，脚本明确打印
  `no scheduled task created (that is the default). Start it yourself with -Cmd once or -Cmd watch.`
  加了它，动作是 `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File <工具目录>\thunderbackup.ps1 -Cmd watch`，
  触发器是"登录时"，任务名默认 `ThunderBackup`（`-TaskName` 可改）。
- `-SkipDoctor`：跳过装完之后的自检（不建议）。默认收尾会用装好的那份重新跑一次 `-Cmd doctor -SkipProbes`，
  非 0 就直接把安装也判为非 0——**装完不自我验证的安装不叫装完**。
- 装之前有两道拒绝：`-InstallDir` 或 `-StoreRoot` 落在迅雷安装目录 / <download-root>根目录里 ⇒ 直接 `throw`，不写任何东西。

装完请打开 `%LOCALAPPDATA%\ThunderBackup\thunderbackup.config.ps1`（工具目录里的那份）检查两件事：`StoreRoot` 和 `WatchDirs`。
这份模板每个键都写了"填错会怎样"。

---

## 4. 第一次运行（四条，按顺序）

下面引用的都是**真实形态**的输出（同一次单文件夹具运行，文件 400000 字节；路径已折叠为 `…`，数值未改动）。

### 4.1 `-Cmd doctor`：这台机器现在能做哪些判断

```
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd doctor -Config thunderbackup.config.ps1
```

```
ThunderBackup 0.9.0-dist.1  cmd=doctor  config=…\thunderbackup.config.ps1  store=…\store
[1] LANGUAGE  ps=5.1.19041.7725 edition=Desktop lang=FullLanguage pid=10252
     native probe types: XldbProbe=True TbsM=True Win32Io=True | Get-FileHole live reading: returned but NOT-USABLE: eof<64KiB
     capability level (criteria.ps1 ladder: 0=cmdlets only, 1=+native probes, 2=+Thunder declaration): 1
     degraded criteria: C6.expect
     claim: preallocation detected via ABSOLUTE hole bytes (sign only, 1 cluster = 4096 B resolution); paused-with-final-name NOT decidable without TaskDb -> BACKUP_UNVERIFIED.
[2] WHAT THAT COSTS US  (this tool's own judgement set)
     Thunder declaration (G5 / level 2): NOT WIRED IN THIS PACKAGE, by choice. …
[10] HASHING  (measured on a 32 MB scratch file, this machine, this session)
       embedded C# SHA256.Create() = 117.9 MB/s | Get-FileHash cmdlet = 54.4 | certutil.exe = 86.9
       the tool uses: embedded C# SHA256.Create() (the store uses this)
[12] PACKAGE INTEGRITY  (11 lib files)
       parser errors=0  files with unsafe encoding=0
```

怎么读它：报告共 14 节，`[1]` 语言模式与探针类型、`[3]` 监视集合是**哪些键拼出来的**、`[4]` 每个目录所在卷的文件系统、
`[6]` 守卫自证（中文守卫字符串按码点校验，防止无 BOM 乱码导致"看起来在排除、其实没排除"）、`[9]` 待重启改名残留、
`[10]` 当场实测的哈希吞吐（所以第 10 节的数字每轮都可能不同）、`[13]` 配置**实际被读成了什么**、`[14]` doctor 明说自己答不了什么。
退出码：`0` = 报告完整（哪怕档位是降级的）；`2` = 仪表自相矛盾（见第 5 节）。想拿结构化结论加 `-Json`。

### 4.2 `-Cmd once`：跑一轮（先演练）

```
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd once -Config thunderbackup.config.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd once -Config thunderbackup.config.ps1
```

```
run run-20261022-210857-1 (ordinal 1): scanned=1 committed=1 deduped=0 wait=0 skipped=0 unchanged=0 ownGuarded=0 failedCommit=0
     criteria: READY_with_completion_act=0 READY_UNVERIFIED=1 WAIT=0 SKIP=0 CREDENTIAL-EXCLUDED=0 G4-not-applicable=0 gate-errors=0
     rename witnesses this pass=0
```

`READY_with_completion_act=0 / READY_UNVERIFIED=1` **是这台机器的正常结果，不是故障**——原因见第 6 节。
`-DryRun` 用同一套判据、同一个快照代码走一遍，但不写 blob、不写索引、不写观察状态，并打印
`DRY-RUN: no blob, no index, no state written.`
逐文件判定的原始行（配置里 `LogVerbose=$true`，或 `watch`）长这样：

```
{"Decision":"READY","Reason":"BACKUP_UNVERIFIED|HOLE_UNKNOWN,EXPECT_UNKNOWN,NO_GROWTH_WITNESS,NO_COMPLETION_ACT,G4_NA_TINY"}
```

### 4.3 `-Cmd status`：库里到底有什么、覆盖了多少

```
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd status -Config thunderbackup.config.ps1
```

```
store …\store
  id=2f643356968d4e37bf77633d851121e7 algo=SHA256 created=2026-10-22T21:37:21.9514975+08:00
  tracked files=1  referenced blobs=1  blob bytes=0.4 MB  free on store volume=43.9 GB
  completion acts (rename this process witnessed): 0;  BACKUP_UNVERIFIED: 1;  WAIT now: 0;  SKIP now: 0;  witness records kept: 0;  state entries=1 pruned=0 runs=1
  two different words, two different axes: the counts above mean "finished as far as this tool can prove";
       heads.verified means "the bytes in the blob still hash to their own name". Neither implies the other.
  watched roots (1):
    …\watch exists=True from=[config.WatchDirs]
```

两个"verified"是**两条正交的轴**，工具自己把这句话打在输出里：上面的计数说的是"本工具能否证明它写完了"，
`heads.verified` 说的是"库里的字节还配不配得上它自己的名字"。别混用。
如果 `tracked files=0` 而监视树里有文件，`status` 会打一条专门的 `*** ALARM …***`（防"静默零备份"，见 `L-25`）。
加 `-Deep` 会列出 15 条最需要人看的 `WAIT/SKIP` 及其理由；加 `-Json` 出结构。

### 4.4 `-Cmd verify -Deep`：库里的字节还对不对

```
powershell -NoProfile -ExecutionPolicy Bypass -File thunderbackup.ps1 -Cmd verify -Config thunderbackup.config.ps1 -Deep
```

```
verify: 1 head(s) checked, 0 corrupt, 0 missing, 0 with integrity-verified=false, 12 ms hashing, 0.3 MB read
fsck: {"Heads":1,"Checked":1,"Ok":1,"Corrupt":[],"Missing":[],"OrphanTx":0,"OrphanBlobs":0,"Deep":true}
```

不加 `-Deep` 只查存在性，并且会把这件事打出来：`NOTE: this checked EXISTENCE only. …only -Deep re-reads the bytes…`。
`-Deep` 的代价约按第 10 节的吞吐算：200 GB 的库 ≈ 25 分钟量级。`-Limit N` 抽样。
这条命令的价值由反向对照证明：往某个 blob 末尾改一个字节，`verify -Deep` 必须报 `CORRUPT` 并**退出 2**
（`smoke_test.ps1` 的 S15 就是干这个的）。

---

## 5. 六个命令与退出码

| `-Cmd` | 它实际做什么 | 常见附加开关 |
|---|---|---|
| `-Cmd watch` | 常驻进程，按 `IntervalSec` 反复跑同一轮 pass（与 `once` 共用同一份代码，杜绝两边漂移）。一轮 = 全量重扫 + 判定 + 提交。 | `-Seconds` `-IntervalSec` `-MaxRounds` `-Quiet` `-DryRun` |
| `-Cmd once` | 只跑一轮，然后退出。适合挂在你已有的任何调度器上。 | `-DryRun` `-Store` `-WatchDir` |
| `-Cmd verify` | 复核库的完整性：默认查存在性，`-Deep` 逐 blob 重算 SHA-256；随后跑 `fsck`（heads / 孤儿 tx / 孤儿 blob）。 | `-Deep` `-Limit` `-Json` |
| `-Cmd restore` | 不带选择器时**只列 heads，不写任何东西**；带 `-FileId`/`-Path`/`-Name` 打印恢复计划并（确认后）写文件；写之前留 `restore-undo\<UndoId>.jsonl`。 | `-IntoDir` `-Original` `-Version` `-Yes` `-DryRun` `-AllowUnverified` `-IAmSureTheSourceIsDead` |
| `-Cmd status` | 库/索引/观察状态/监视集合/skipped 统计的当前快照，含"看到 N 个文件、库里 0 个"的告警。 | `-Deep` `-Json` |
| `-Cmd doctor` | 能力报告：这台机器现在能做哪些判断、每个判断 backed by 哪个刚跑过的探针。 | `-SkipProbes` `-Json` |

**退出码的准确含义**（调度器可以据此判断，不需要读文字）：

- `0` —— 命令跑完了并**如实报告**。包括：档位是降级的；`scanned=0`；`committed=0`；`restore` 只是列了 heads；
  你在确认提示里输了非 `YES` 而取消。"什么都没备份"绝不等于失败，但它一定会在输出里被说出来。
- `1` —— **工具拒绝运行**（输出里有 `REFUSED:` 与出错位置）。触发条件：配置找不到或 `-Config` 指向空、`StoreRoot` 没设、
  库的位置落在被监视树里（placement 拒绝）、所有被监视目录都不存在（"没事可做，而且这就是错误"）、
  `restore` 选择器有歧义或目标在库内、判据以外的参数错误。
- `2` —— **仪表矛盾**：仪器自己打自己的脸，这是包里的 bug 或库的完整性问题，**永远不会被报成一次成功的备份**。
  具体两类：`doctor` 打印 `INSTRUMENT CONTRADICTION: …`（例如 `Add-Type` 给判据层编出了类型但存储层没有、
  `Get-FileHole` 返回 null 或抛错、守卫字面量码点不符、凭据排除没把 5 条夹具全挡住、库位置被拒）；
  `verify` 查到 `corrupt>0` 或 `missing>0`（索引说的和字节对不上）。另外包加载失败也是 `2`。
- **精确原因走 `-Json`**：人类可读的行是给人看的，机器可读的那份（`once`/`watch`/`status`/`verify`/`restore` 的结果对象、
  `doctor` 的 `AsJson`）才是给脚本用的。

---

## 6. 完成判据：什么才算"备份了并且证明写完了"

```
G4  绝对空洞符号（单向）   hole = EndOfFile - AllocationSize
                           hole > 0  ⇒ 一定未完成
                           hole <= 0 ⇒ 只说明"分配是满的"，对内容不作任何断言
                           四条前置豁免（缺一即"判据不适用"，不是"判完成"）：
                             压缩/加密/offline/reparse 属性、卷不是 NTFS、eof < 64 KiB、容器/镜像扩展名只触发复核
G5  迅雷自己的声明（TaskDb：eof == ResourceSize == ValidSize ∧ CompletionTime > 0）
G7  改名见证：同一个文件身份 (VolumeSerial, FileId128) 经历了一次改名，本工具亲眼看到

verified = G4 ∧ ( G5 ∨ G7 )      其余一律 BACKUP_UNVERIFIED（照样备份，但标记出来给人看）
G6 静止窗口只能用于"暂缓"，永远不能用于"放行"
```

**这个包里 G5 是故意没有接进来的。** 判"完成"最直接的输入是迅雷自己的任务库 `TaskDb.dat`，但读它必须先把这个文件
复制出来——而它里面有**明文的第三方会话 cookie 和明文密码**。本包拒绝这笔交易，代价写清楚：

> **（本节原来那句"本机正常下载是以最终名落地的"是错的，已按 C 卷 USN 实测更正：普通下载走临时名，
> 完成时改名，见 L-35。）** 真实序列是 `create <最终名>.xltd` + `.xltd.cfg` → `Data truncation` → `Close`
> → `Rename: old` → `Rename: new` → 边车 `File delete`，窗口 37 s。所以唯一还能给出完成动作的来源——
> "本工具亲眼见证的改名"——**事件是存在的，问题在我们看不见它**：1 s 轮询实测漏掉改名 ⇒ 必须
> **<0.5 s 轮询或以 USN 为主**。在采样改成那样之前，正常下载这一类文件的 **`verified` 计数仍会接近 0**：
> 你会看到 `READY_with_completion_act=0 READY_UNVERIFIED=1`，`status` 里 `BACKUP_UNVERIFIED: N`。
> 这是**采样能力的上限**，不是 bug，也不是"备份失败了"。文件在库里，可以 `restore`，
> 只是本工具不替它担保"已经下完"。

于是这个工具的诚实形态是两条轴分开报：**"备份了吗"**（备了）与**"我能不能证明它写完了"**（多数不能，标 `BACKUP_UNVERIFIED`，
进 `status` 的可见列表）。它既不因为不能证明就不备份，也不因为备份了就谎报完成。把 `UnverifiedPolicy='skip'`
设成"不备份未验证件"在这个包里几乎等于不备份任何东西——请保持默认 `'backup'`（`L-02`）。

---

## 7. 已知局限（`L-01` … `L-41`，逐条都是实测或已裁定的事实）

**L-01 · 暂停与完成在文件系统层面全等**：一个"暂停 + 已是最终名 + 无持有者 + 长度恒定"的文件，与一个完成件在只读外部观测能拿到的每一个信号上完全相同；本工具不承诺能区分它们，只能给 `BACKUP_UNVERIFIED`。

**L-02 · G5（迅雷声明）故意没接**：读 `TaskDb.dat` 需要先复制一个含明文第三方 cookie 与明文密码的文件，本包拒绝这个交换；因此完成动作只剩"本进程见证的改名"一条来源，本机正常下载以最终名落地 ⇒ `verified` 计数接近 0（`doctor` 第 [2] 节自己会打印这句话）。

**L-03 · 非稀疏预分配对本地仪器整类免疫**：`hole<=0`、属性位、时间戳、`fsutil file queryallocranges` 输出串、字节统计、无写者探针、改名见证、增长见证，八类读数与真完整文件逐字相同；所以 `hole<=0` 永不授予 `verified`，只能靠外部期望尺寸或本工具见证的写完动作。

**L-04 · 截断再长回的尾缺永久隐形**：`SetLength` 缩短后再长回去时 NTFS 归还簇、重预分配时不写任何东西，尾缺在簇记账上与写满同形（`hole=0`）；分辨率下限是一簇 = 4096 B，迅雷是否会做这种形态仍是【待验】。

**L-05 · 小文件不吃空洞判据**：`eof < 65536` 走 `G4_NA_TINY`，因为 MFT 内记录的文件按字节粒度分配（实测 1 B → `alloc=8`、512 B → 512），1 簇下限不成立；迅雷自己的 `.cfg` 边车 59 个里有 57 个落在这条豁免里，与成品不可区分。

**L-06 · 稀疏文件是支持的，且必须按正确控制码理解**：`FSCTL_SET_SPARSE = 0x000900C4`（function 49）；把它写成 `0x000900A4` 调到的是 `FSCTL_SET_REPARSE_POINT`，NULL 缓冲区返回 `err=1784`，那条错误曾被本项目的早期结论误读成环境不给稀疏能力——那次误读已整体作废并撤回（`build-check.ps1` 现在有门禁盯着这两个常量）。

**L-07 · 判据只用空洞的符号**：`hole = EndOfFile - AllocationSize` 是绝对量，`hole > 0` 一定未完成；`hole <= 0` 只表示分配是满的，**不说明内容**。已完成文件的 `hole` 天然为负（簇向上取整，实测 `-3496..0`），所以 `-1` 不能当"未知"哨兵。

**L-08 · `doctor` 的稀疏夹具探针在当前构建里是坏的**：第 `[11]` 节会打印 `probe threw: … [TbsM] does not contain a method named 'MakePreallocated2'`（存储层暴露的是 `MakePreallocated`）。这一行不构成任何能力证据——稀疏这件事的依据是 `L-06`/`L-07` 与门禁，不是一个报错行；备份与恢复路径不受影响。

**L-09 · 读预算必须按 `EndOfFile` 计，绝不能按 `AllocationSize`**：实测 `eof=512MB / alloc=40MB` 的稀疏文件哈希吞吐 135.7 MB/s，与稠密文件的 136.3 MB/s 几乎相同——空洞不免费；按分配大小估算会把一个未完成 50 GB 任务的校验成本低估 25 倍。

**L-10 · 全量哈希的成本天花板已实测并接受**：10 万文件 / 200 GB ≈ 26 分钟（字节项 200 GB ÷ 139 MB/s ≈ 24.5 分 + 文件项 100k × 1.1 ms ≈ 1.9 分，串行，不含复制）；改成"大小 + 首尾块"这种近似键曾经**真的撞过**（三件同尺寸同键、全量 SHA-256 互异，含只翻 1 字节的形态），后果是静默不落盘 = 静默数据丢失，所以逐文件全量哈希是硬要求。

**L-11 · `SHA256Cng` 在这台机器上是更慢的实现**：256 MB 实测 `SHA256.Create()` 136.4 / `SHA256Managed` 118.8 / `SHA256Cng` 116.7 / `Get-FileHash` 83–89 MB/s；`doctor` 每轮自己再测一遍（同一台机器两轮：embedded 134 与 110.2、cmdlet 77.3 与 70.1、certutil 92.7 与 98.8）。缓冲区 1/4/16 MB 差异 <3%，不是性能旋钮。

**L-12 · 主键已是 `(VolumeSerial, FileId128)`，改名跟随 NTFS 文件身份**；`relpath` 降级为人读标签。三条诚实代价：① 跨卷 move/copy 会产生**新条目**（保守，可接受）；② 卷格式化 / 快照回滚之后 FileId 可能被**复用**，所以身份命中必须重新全量哈希复核；③ FileId 只在**单卷内**唯一，卷序列号不是装饰而是必需的隔离维度。

**L-13 · 非 NTFS 卷（exFAT/FAT：U 盘、SD 卡、移动硬盘）上的产物永远不可能 verified，但仍然会被备份**：那里 `FileIdInfo(18)` 返回 `err=87`，`Get-FileHole` 不可测，判据层输出 `G4_NA_VOLUME_<fs>`，而改名见证的身份维度同时失效——三件事一起消失，状态是 `BACKUP_UNVERIFIED + CAPABILITY_VOLUME_FAT`（`VERIFIED_CAPPED_BY_VOLUME` / `RENAME_NO_IDENTITY_ON_VOL_<fs>` 同一来源）。

**L-14 · 失效方向会反过来**：exFAT 上没有稀疏 run，`alloc >= eof` 恒成立 ⇒ "hole>0"这条测试永远打不响；实测 8 MB 一字未写的文件报 `hole=0`，看起来"完成"。所以判据在该卷上被**整体关掉**（由卷能力决定，与配置、版本、权限无关），而不是"放宽阈值继续用"。

**L-15 · 逆向得到的临时名规律对普通下载覆盖为 0**：本机 `.xltd` 只出现在云盘缓存目录（59 个，来源 `vodNNNN-*-vip-lixian`/`pk=xdrive`），迅雷安装目录零命中，普通下载的 6 个成品是最终名且无边车；所以判据地基不能是这套命名规律，只能是可以跨下载器成立的文件系统事实。

**L-16 · 迅雷状态词表只有一个样本**：`Status=8` 与完成相关是 6/6 的相关性，不是因果，词表未闭合，所以这个值绝不烧进代码；本包因此只依赖文件系统信号，代价就是第 6 节说的 `verified` 稀少。

**L-17 · 两架仪器的数值不可同表比较**：同一文件 `fsutil file queryallocranges` 报 hole=65,536、`FileStandardInfo` 报 45,056，**只有符号一致**；本包一律取 `FileStandardInfo`，`GetCompressedFileSizeW` 只在 `hole>0` 分支上懒查一次（0.108 ms）并仅作透明记录，因为它对非稀疏文件返回逻辑长度。

**L-18 · `RestartManager` 的归因是时点快照，不是文件属性**：任何"谁锁的"标签都必须带上采集时间，且不得写进永久结论；记录步长的真值是 **668**（早先记的 668 是错的，且必须由**多持有者**夹具才测得出来——单条记录时步长不可观测）。本 README 不承诺任何依赖该数值的能力；这条路径本身 47–240 ms/次，只在探针报锁之后按需一次，永不进热路径、永不当判据。

**L-19 · 句柄纪律与残留的小概率撞车**：观测与复制句柄必须带 `DELETE` 共享（`0x07`），否则实测会顶住迅雷的 `ReplaceFileW`（`err=32`）与 `MoveFileWithProgressW`（`err=5`）；文件级解了但**任务目录整体改名仍会失败**；"独占打开看看有没有人用"这种探针被禁用（share=0 就是那个 32 的成因，且它连读都分不出写者）。复制窗口与迅雷改名之间存在小概率撞车，本工具只承诺"短持有 + 分片 + 让路"，**不承诺零影响**。

**L-20 · 硬链接、reparse、压缩、加密、offline 件：备份会做，但独立性或完成度不保证**：`NumberOfLinks > 1` 直接 `E_HARDLINK_LINKS_<n>` 判 SKIP（因为写监视侧的名字会原样改到库里的 blob，"独立副本"承诺当场失效）；L0 档位下 `links` 是未知（`HARDLINK_STATE_UNKNOWN`），未知**不许当成 1**；带 reparse/压缩/加密/offline 属性的件走 `G4_NA_*` 豁免——复制它们，但不给完成结论。

**L-21 · 事件流必然丢失，正确性靠周期全量重扫**：事件通知会溢出（`ERROR_NOTIFY_ENUM_DIR`）且丢的那段不补发不报错；本机 USN 日志 `writeRangeTracking=Disabled`，一条记录能说出是哪个文件但永远说不出是哪个字节范围。所以重扫间隔内被删掉的文件可能来不及入库，`IntervalSec` 越小窗口越小、但每轮都是全量重扫。

**L-22 · 本项目在这台机器上留下的已知残留**：`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations` 里有 **2 条**指向 `work\04-tests\_mf_probe\*`（早期 `MoveFileEx` 标志位实验的产物，源文件已不存在，重启时是空操作）。该值整是 `REG_MULTI_SZ`，实测 **108 个元素 = 54 对 = 55 条非空路径**，其余 **53 对属于别的软件** ⇒ **不清**，原因很具体：撤销粒度不支持只删自己那一条。`doctor` 第 [9] 节只读地把这些数字打出来；本工具的代码不写这个键，存储源码里 `MoveFileExW` 的 `0x04/0x08/0x10/0x20` 是禁用的。

**L-23 · 防不住管理员**：`SeRestorePrivilege` 可以穿过 DACL 直接写（实测同一个被双层 deny 挡住的写：禁用特权 `err=5`，启用特权 `rc=0` 且**内容真的变了**），管理员一条 `icacls /remove:d` 或 `takeown` 就能解掉基于 ACL 的"只追加"（实测秒解）。所以库里那两层 deny **只防误操作和普通进程**；要防管理员请把备份集加密（EFS/BitLocker/自建加密卷），那超出本工具范围。

**L-24 · `-WithDb` 拷贝是用户的显式选择，不进发布物**：只有在 `work\live-verify\verify-download.ps1` 里显式加 `-WithDb` 才会把任务库副本取到会话目录；该脚本的 `-Mode scrub` 现在**默认是 dry-run**，必须再带 `-Apply` 才真删。**发布前必须跑一次 `verify-download.ps1 -Mode scrub -Apply`**；任何任务库副本永不打包、永不被提交、永不分享，`build-check.ps1` 的 hygiene 门禁会因为一个 `TaskDb.dat` 直接卡住发布。

**L-25 · "静默零备份"是这个工具类别最容易中的招**：迅雷的下载路径分散在最多 9 个配置键里，只解析出一个键时 `doctor` 会大声警告；`WatchDirsMode='manual'` 又填了不存在或空的目录 ⇒ 监视一个空目录、备份 0 个文件、全程无错误。防线是 `status` 那条 `*** ALARM: N file(s) visible in the watched tree, 0 in the library ***`，以及 `once` 的 `scanned=0` 说明行——请每天看一次，别只看退出码。

**L-26 · 观察状态有上限，裁掉就丢见证**：`StateMaxEntries=20000`，超出按最久未见的条目裁剪，被裁条目**失去它的改名见证**，于是原本 `verified` 的文件退回 `BACKUP_UNVERIFIED`；`once`/`status` 会把裁掉多少条大声打出来（`*** state pruned N entries … ***`），库里文件比这多就把它调大。

**L-27 · 编码是本包的一条硬约束，不是风格**：Windows PowerShell 5.1 把无 BOM 的 `.ps1` 按 ANSI 解码，纯 ASCII 文件没事，一旦有人加中文（注释、路径守卫）就变成乱码，而乱码恰好落在用来排除目录的中文字面量上——守卫照样跑、照样打印"已排除"、实际什么都没拦。所以所有 `.ps1` 必须是 UTF-8 带 BOM，`tools\add-bom.ps1`（`-Check` 只报告）与 `build-check.ps1` 的 encoding 门禁一起守这件事。

**L-28 · 集合一致性（清单/分片）没实装**：本工具按单文件判定，不保证备份集能播放——`.m3u8` 配一批残缺分片就是一套不可恢复的备份；判据层的 `GROUP_INCOMPLETE` 分支在这个包里不产生"整组就绪"的结论（`H1` 未实装）。另外迅雷被共享冲突顶回去之后自己会怎么做，本项目仍未观测到（【待验】），普通下载的中间态文件名也未观测到。

**L-29 · 两条豁免在本机无法构造夹具**：`G4_NA_OFFLINE`（需要分层/延迟移除驱动）与 `G4_NA_ENCRYPTED`（需要 EFS 会话）的**实现存在**已被断言、**行为**未被证明，自检报告里单列 `UNPROVEN` 且**不计入通过**；末行永远打印 `N rows, M unproven`——"全绿"这个词只有在这两个数字都摆在前面时才允许出现。
**L-30 · 库的位置由代码强制**：`StoreRoot` 落在任何被监视目录之内会被 `TEST-TBSM-PLACEMENT` 直接拒绝并退出 1（实测反例：把库装进监视树会开始备份自己的备份，内容寻址挡住了体积膨胀，但挡不住语义污染）；`restore` 的目标在库内同样拒绝；`-Original` 写回迅雷活跃目录会给出明确 NOTE，因为下一次任务改名就会把它盖掉。

**L-31 · "迅雷声明"这条腿只在**非预分配**的文件上有效，所以它不是第二重证据**：G5/C6 的等式是 `Status=8 ∧ eof == ResourceSize == ValidSize`，而 `eof` 正是"预分配"这一个动作就能决定的量。实测：4 MiB 一字未写、只做 `SetLength(4 MiB)` 的残件，配一条真的 `Status=8 / ResourceSize=4 MiB / ValidSize=4 MiB` ⇒ 等式成立 ⇒ 判据打出 `DB_STATUS8_SIZE_MATCH` 并给 `BACKUP`（`work\04-tests\verify\out-t9-midcopy-truncation.txt` 的 C 节）。同一形状下空洞判据也读不到证据（`hole=0`），因为两条腿读的是同一个量。人话：**声明尺寸和实际长度是同一个量的两次拼写，不是两次独立测量**；把 G5 接上之前必须先确认这个文件不是预分配出来的，否则接上去的是第三条会一起说谎的腿。本包里 G5 本来就没接（`L-02`），所以这条是"将来若接线"的前置条件，不是当前缺陷。

**L-32 · 属性位豁免是一个任何写者都能声称的前提，而它丢掉的是一条真实存在的读数**：`SetFileAttributesW(+0x1000)` 就能让文件报 `OFFLINE=True`，不需要分层驱动，也不需要 EFS——实测 `SetAttrs -> OK`、`HoleWhy=G4_NA_OFFLINE`。但要说准因果，两种形状分开看：① 压缩且尾部 768 KiB 未写的文件，压缩态下**确实读到** `alloc=262144 / hole=786432`，这条豁免把它宣布成 `NOT_APPLICABLE`，随后一个 act 换来 `BACKUP`——豁免在这里的作用是**丢弃已经存在的证据**；② 同一个 1 MiB 预分配残件，把那位清掉之后读到的是 `hole=0`，照样 `BACKUP`——所以**属性位不是这条误判的必要条件**，这条 FP 是过定的，真正必要的是"完成动作从不被内容佐证"。与 `L-13`/`L-14` 对照：exFAT 那条卷上限**拦得住**（已知非 NTFS ⇒ 最诚实状态就是 `BACKUP_UNVERIFIED`，连改名见证都不兑现承诺），属性位这条没有对应封顶，这是两种豁免机制之间目前唯一的不对称。按裁定把四条属性豁免像卷上限一样封顶（变体 V1，`work\04-tests\verify\variants\v1-attrcap`）在同一批夹具上的代价：误判 13→10（去掉的 3 条确实属于豁免），承诺 24→20（其中 1 条 `T3-exemption-works` 是本来承诺对了的），漏判 3→3、`SKIP` 62→62 **一条没变**——它是"少给承诺"不是"少备份"，不会制造静默零备份。剩下的 10 条误判属于预分配 + act 类，属性位机制碰不到，得靠 `L-03` 与 §7.2 禁止预分配。变体与数字：`out-compare-variants.txt`、`compare-variants.ps1`。


---

## 8. 干净卸载

```
powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -InstallDir E:\tb -KeepTask
powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -RemoveStore
```

- 只删 `install.ps1` 装的东西：工具目录里的文件（列清单 + 大小给你看，并要求你**输入 `YES` 再输一次目录名**两段确认），
  以及本工具注册的计划任务 `-TaskName ThunderBackup`（`-KeepTask` 保留它）。
- **保留备份库。** 卸载脚本删不掉、也不打算删你的数据；它把 `StoreRoot` 读出来打印在 `WILL NOT BE TOUCHED` 段里。
  要删库必须显式加 `-RemoveStore`，届时脚本会要求你**手输完整路径**，逐字符匹配才删（不匹配就报告"没有删除"）。
- 它明确列出不会碰的东西：迅雷安装目录与下载根目录（在本工具的删除白名单里是硬拒绝，包括卸载自己时）、
  注册表（本工具什么都没写过，所以没有可删的）、迅雷的配置文件（只读过）。
- 目录里没有 `thunderbackup.ps1` 时它拒绝执行（防止把别人的目录当成安装目录吃掉）。
- 残留自检：卸完之后 `%LOCALAPPDATA%\ThunderBackup` 不在、任务列表里没有 `ThunderBackup`、`StoreRoot` 仍在——
  这三件事就是"删干净"的定义；想连库一起清掉是你之后的独立决定，脚本会先告诉你文件数。

---

## 9. 遥测：这条承诺用测量证明，不用形容词

静态声明没有意义，"没有网络调用"必须被两件事同时撑住：

1. **静态门禁**：`build-check.ps1` 的 `static-telemetry` 门扫描包里每一个 `.ps1`，命中任何网络/动态代码 API
   （`Invoke-WebRequest`、`Net.WebClient`、`Sockets.*`、`WinHttp`、`Resolve-DnsName`、`curl.exe`、`Invoke-Expression`…）
   或注入/注册表写/服务安装原语就判 FAIL。这条门自己也要被证明是活的：`-SelfTest` 会往坏副本里塞一个 `Invoke-WebRequest`，
   看它是否真的 FAIL。
2. **动态实测**：包里的 `telemetry_audit.ps1` 用操作系统自带的手段去看**运行时真实发生了什么**——
   `Get-Process`（含模块列表）看这个进程加载了什么、`netstat -ano`（拿不到 `Get-NetTCPConnection` 时的退路）看它有没有打开过任何连接、
   `Test-NetConnection` 只做**正向对照**（先证明这套探针能看见一条真的回路，再宣布"没看见工具的"）。
   报告与它的方法学、它自己的自命中、它的判定阈值都写在 **`telemetry-audit.md`**（与本 README 同目录；
   **注意：`telemetry-audit.md` 不是脚本生成的。** 这句原先写成"跑一次 telemetry_audit.ps1 就自己生成一份"，
   是错的并已更正：脚本只输出 stdout 与一段 JSON；那份报告（551 行 / 43,531 B）是**人工从一次真实运行整理**
   出来的，所以它必须随包分发。要复核，请在你机器上跑脚本，再逐项比对它的输出与报告里声称的数字——
   别信任何没在你机器上跑过的结论。

---

## 10. 成本表（这台机器实测，`doctor` 会再测一遍哈希吞吐）

| 操作 | 实测成本 | 后果 |
|---|---|---|
| 原生单文件探针（FSI + FileId + 属性） | 0.285 ms/文件 | 全量重扫的底座，10 万文件 ≈ 28 秒 |
| PowerShell 包装后的同一探针 | 1.05–1.096 ms/文件 | 这是 PS 对象开销，不是 IO；能收进 C# 的都收进 C# |
| `fsutil file queryallocranges` | 31.7 ms/文件（10 万 ≈ 53 分钟） | 只做抽样/复核，绝不进每轮热路径 |
| 存储层 `Stat()` | 0.375–0.455 ms/文件 | vs `Get-Item` 1.05 ms：热路径禁用 cmdlet 对象 |
| `GetCompressedFileSizeW`（懒查，仅 hole>0） | 0.108 ms/文件 | 只为透明记录，不当豁免依据 |
| 卷类型查询（**按目录缓存**） | 0.022 ms/文件 | 按文件调 1.517 ms；按"卷根"缓存 1.81 ms/文件 = 等于没缓存 |
| `Add-Type` 冷编译 | 2.2–2.8 秒 | 所以 `watch` 是**常驻进程**：几分钟起一次的计划任务会把三分之一生命花在重编译 |
| 嵌入式 C# SHA-256 | 136.4 MB/s（256 MB 实测） | 1 MB 读+哈希 ≈ 8.5 ms，是 `PerFileDeadlineMs` 的量纲参考 |
| `Get-FileHash` cmdlet | 83–89 MB/s | 比嵌入式慢约 37%，这就是不用它的量化理由 |
| `certutil.exe` | CLM 机器的唯一退路 | 外部进程、更慢，`verify` 会打 `DEGRADED:` 并在 `THIRD_PARTY_NOTICES.md` 声明 |

---

## 11. 代码名对照表：包里打印的字面 ↔ 规范里的规范码

`once`/`watch` 在 `LogVerbose` 下打印的是判据层的原始 reason 码；汇总行把它们折算成计数。两边名字不同，这里给全对照。

| 包内打印的字面 | criteria-spec 的规范码 / 条目 | 怎么解读 |
|---|---|---|
| `G4_NA_VOLUME_exFAT` / `G4_NA_VOLUME_FAT32` | G4 豁免②（非 NTFS 卷） | 空洞判据在这块卷上**关掉**了，不是通过了；见 `L-13`/`L-14` |
| `G4-not-applicable=<n>`（汇总行） | 上表所有 `G4_NA_*` + `G4_REVIEW_*` 的计数 | 这个数不为 0 是好事：它意味着工具知道自己在哪些文件上看不见 |
| `READY_with_completion_act=<n>` / `BACKUP\|…` | `verified = G4 ∧ (G5 ∨ G7)` 成立 | 唯一会被叫作"完成"的类；本机主要由 `RENAME_WITNESSED` 提供 |
| `READY_UNVERIFIED=<n>` / `BACKUP_UNVERIFIED\|…` | 备份了但无完成动作 | 文件在库里、可恢复、不担保"下完了"；见第 6 节 |
| `CREDENTIAL-EXCLUDE …` / `CREDENTIAL-EXCLUDED=<n>` | 凭据硬排除（整个迅雷安装树） | `TaskDb.dat` 里的明文 cookie/密码永不进备份集；`doctor` 第 [6] 节要求 5/5 夹具被挡住 |
| `G4_NA_TINY` | G4 豁免③（`eof < 65536`） | 小文件不吃簇下限，见 `L-05` |
| `G4_NA_REPARSE` / `G4_NA_COMPRESSED` / `G4_NA_ENCRYPTED` / `G4_NA_OFFLINE` | G4 豁免①（属性驱动） | 后两条在本机没有正反夹具 ⇒ `UNPROVEN`，见 `L-29` |
| `G4_REVIEW_CONTAINER.vhd` 等 | G4 豁免④（容器/镜像扩展名：**只复核，不给结论**） | 只对显式列表生效：`.vhd .vhdx .vmdk .iso .img .raw .qcow2 .vdi .sparsebundle .sparseimage .wim .esd .ape` |
| `CAPABILITY_VOLUME_FAT` | 卷能力天花板：这块卷最高只能到 `BACKUP_UNVERIFIED` | 与配置/版本/权限无关，是卷的性质 |
| `VERIFIED_CAPPED_BY_VOLUME:exFAT` | 连"声明已完成"也被卷能力压低 | 即使有完成声明，在该卷上也不打印 `verified` |
| `IDENTITY_WEAK` | L0 档位没有强身份，退回路径键 | "同一路径"不等于"同一对象"，跨快照回滚不可当证据 |
| `RENAME_NO_IDENTITY_ON_VOL_exFAT` | 路径级改名 ≠ G7 改名见证 | 身份维度不存在，见证无法构造；不借用 `RENAME_WITNESSED` 这个标签 |
| `E_HARDLINK_LINKS_<n>` → `SKIP` | 判据 C14（`NumberOfLinks > 1`） | "独立副本"承诺对硬链接不成立；见 `L-20` |
| `HARDLINK_STATE_UNKNOWN` | 链数未知（L0） | 未知**不许**当"1"，因此不授予 `verified` |
| `NO_COMPLETION_ACT` / `EXPECT_UNKNOWN` / `NO_GROWTH_WITNESS` / `HOLE_UNKNOWN` | 完成动作的两条来源都没有 | 第 6 节那条 `{"Decision":"READY","Reason":"BACKUP_UNVERIFIED\|…"}` 就是这个组合 |
| `TMPNAME.xltd` / `TMPNAME_WEAK.xltd` | 判据 C1（后缀 + 一条佐证 / 只有后缀） | 只有后缀不算临时名，否则你的 `report.tmp` 会被永久跳过 |
| `SIDECAR_CFG_side_<m>` / `SIDECAR_STALE_<m>` | 判据 C2（迅雷自己的"任务未完成"边车） | 前者 WAIT；后者按年龄（默认 60 分钟）当崩溃遗留处理 |
| `HOLE_64K / HOLE_1M / HOLE_32M / HOLE_BIG`、`SPARSE_HOLE_PRESENT`、`HOLE_UNCONFIRMED`、`HOLE_STALL` | 判据 C4 的 hole>0 分支与二次确认 | 非稀疏文件第一次看到正洞不当证据（属性会滞后），下一轮确认才动 |
| `HOLDER_32 / HOLDER_33 / HOLDER_TIMEOUT`、`DELETE_PENDING`、`UNSETTLED_<s>`、`LEN_MOVING` | 判据 C3/C5/C8 | 全都是"本轮不动"的方向，没有一个能变成"完成" |
| `GROUP_INCOMPLETE` | 判据 C11（清单/分片） | 这条链在本包不完整，见 `L-28` |

**容器类扩展名只做 REVIEW，媒体容器不豁免。** 这一点是实测钉出来的：M2 那组 59/59 的稀疏 `.mkv`，
`hole > 0` 正是迅雷预分配留下的签名。把 `.mkv`、`.mp4` 之类当成"可能有洞的最终形态"，就等于把 59 个半成品全放过去。
所以豁免表里只有磁盘镜像/稀疏容器那一类显式列出的扩展名，媒体文件走正常判据链。

---

## 12. `smoke_test.ps1` 与 `build-check.ps1`：怎么跑、绿了意味着什么

```
powershell -NoProfile -ExecutionPolicy Bypass -File smoke_test.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File smoke_test.ps1 -Keep -ExFatDir E:\tb-smoke
powershell -NoProfile -ExecutionPolicy Bypass -File build-check.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File build-check.ps1 -SelfTest
```

- `build-check.ps1` 是**静态发布门禁**（不联网、不装东西、只读本包）：稀疏控制码、主键形态、豁免实现只有一份、
  每个 `.ps1` 的 BOM 与编码、解析 0 错误、新进程里 18 个必需函数 + 4 个探针类型真的存在、配置键都有书面含义、
  README 的门（六个 `-Cmd`、`L-nn` 无缺号、没有依赖安装的承诺、没有那句被撤回的稀疏错话）、
  以及 hygiene（>5 MB 的文件、`TaskDb.dat`/`user.core.db*` 副本、逆向中间产物、二进制、`.json/.jsonl/.csv` 快照）。
  通过 = `PACKAGE IS RELEASE-READY (static gates)`，退出 `0`；任何 FAIL 退出 `3`。
- `-SelfTest` 会往一份**故意做坏**的副本上跑同一批门（塞进 `0x000900A4`、剥掉 BOM、改名一个函数、把 `L-05..L-29` 删掉、
  丢一个 `TaskDb.dat` 和 8 MB 夹具进去、加一条 `Invoke-WebRequest`），要求每一类缺陷都有门真的 FAIL。
  打印 `SELF-TEST PASSED: every gate is alive.` 才有资格说"门禁在守着"。它只在 `build-check-work\` 里操作副本，跑完删掉。
- `smoke_test.ps1` 是**动态自证**：在 `%TEMP%` 造自己的夹具（`WatchDirsMode='manual'`，绝不把迅雷放进监视集合），
  跑 `doctor → once → once（改名发生在两轮之间）→ status → verify -Deep → 改坏一个 blob 再 verify → restore（含三次拒绝：写进库里、歧义、越界）→ watch 两轮 → install/uninstall 往返`。
  S01–S27 的 `SMOKE RESULT pass=… fail=… skip=…`；FAIL 退出 `7`。
  `-ExFatDir` 是给非 NTFS 那条门用的：不给这个参数且机器上没有可写的非 NTFS 卷时，S21 记 **SKIP 并写明"NOT TESTED"**——
  它不会默认算通过（这正是本项目对"绿"的标准）。
- **跑绿意味着**：这个包在这台机器上能被装、能跑六个命令、能正确挡住凭据/自己的产物/歧义恢复/越界写入，
  见证改名能产出 `BACKUP`，被改坏的字节能被 `verify -Deep` 抓到，`uninstall` 只删自己装的。
- **跑绿不意味着**：它没碰过真实迅雷会话（那次改名是本脚本在夹具目录里造的）；它没测真实机器上的 CLM 环境；
  G5 没接线所以测不到；**它完全不能说明你的真实文件已经被覆盖了**——真正的检验是你正常下载一天之后跑
  `-Cmd status -Deep`：`tracked files`、`BACKUP_UNVERIFIED`、`WAIT/SKIP` 三条都要有你能解释的数字。
- 建议顺序：装完先 `smoke_test.ps1`（证明包是好的），再 `doctor`（证明这台机器是好/降级到哪一档的），然后才让 `once`/`watch` 碰真实目录。

---

## 实测补充（2026-10-22/23：活体事实的两处更正、硬链接的实测行为、遥测盲区）

> 这一节里 **L-31 与"零新文件"两条原来是错的**，错因不是笔误，是仪器看不见东西。原样保留错误文字会
> 误导用户，所以先写清楚错在哪里，再给更正后的事实：
> ① 原来写"普通下载第二次也以最终名直接落地、没有可见改名"。C 卷 USN 实测推翻它：**普通下载用临时名**。
> ② 原来写"同一时刻迅雷 `ACCOUNT-REDACTED` 任务目录零新文件"。那是 **Hidden** 目录，
>    `Get-ChildItem` 不带 `-Force` 根本看不见 ⇒ 那个"0"是仪器漏看，不是事实。**所有列举目录的脚本一律加 `-Force`。**

- **L-35：普通下载确实走"临时名 → 改名"，改名窗口就是判定的关键素材期。** 同一 observation 只改 Path
  拼法，四条实测见 L-29/L-30；USN 侧的真实序列是：
  `create <最终名>.xltd` + 边车 `<最终名>.xltd.cfg` → `Data truncation` → `Close` →
  **`Rename: old name` → `Rename: new name`** → 边车 `File delete`（`.xltd.cfg` 在完成时被删除）。
  窗口 37 s，样本 n=1，2.5 GB HTTP。
  对本工具的后果，两条都是硬要求：
  **① 轮询必须 <0.5 s，或者以 USN 为主** —— 1 s 轮询实测**漏掉改名**，而改名见证（G7）只有看见改名才成立；
  **② 不能把"边车不见了"当成任务失败的信号** —— 完成时它本来就会被删。
  另：`FileIdInfo` 的 `FILE_ID_128` **低 64 位 == USN 的 FileReferenceNumber**（实测同一值），
  所以改名前后的两个名字可以按身份配对，不必靠文件名猜。

- **L-36：`TaskInfoEx` 不会被迅雷清理，因此可以作为长期凭据；但它是原地截断重写的。** 现场计数 8 个，
  最老的一个产生于 10-06，跨 16 天仍在场 ⇒ 任何"这类记录只在任务生命周期内短期有效，所以不能当证据"
  的假设都是错的，不许在文档或注释里写"仅短期有效"。
  同时，USN 侧实测 **39 个 `truncate → extend → Close` 循环、零 rename、约 1 次/秒** ⇒ 读它必须
  **容忍撕裂读并重试**（半条记录是正常状态，不是错误状态）。长期在场也意味着它可能被复用，所以真接 G5
  时仍要用（记录、期望大小、时间）对齐，不能只认文件名。

- **L-37：被监视目录里出现硬链接或重解析点时，跳过的是那一个文件，整轮照常提交。**
  现行输出形状（本轮改动）：
  `PER-FILE EXCLUSIONS (n): SKIP E_WATCH_HARDLINK <名字> -- ... has 2 hard links and no reparse point ...`，
  每一件同时写进 `logs/skipped.log`（`placement-per-file` 阶段），其余文件继续备份、退出码不再因它而 1。
  两种形状**分得开**：`mklink /H` ⇒ `E_WATCH_HARDLINK`（attrs=0x20、链数 >1、无重解析位）；
  `mklink /D` ⇒ `E_WATCH_REPARSE_POINT`（带 0x400 位）。链数读不出来时按 `HARDLINK_STATE_UNKNOWN`
  处理（未知 ≠ 1）。同族守卫 `STORE_INTEGRITY_AT_RISK`：内容哈希仍对但独立性没了 ⇒ verify 不许说 ok。
  **历史行为如实记账**：23:0x 之前的版本是"一个硬链接 ⇒ `STORE PLACEMENT REFUSED` 整轮拒绝、零提交、
  退出 1"，实测文本 `E_WATCH_HARDLINK ... has 2 hard links` 与符号链接同句、无法区分。改成逐文件跳过的
  理由是：39,999 个干净文件不该因为一个文件有两个名字而丢掉整轮备份；拒绝的理由（硬链接是同一对象的
  两个名字，不是副本）在单个文件上依旧成立，所以它仍然被拒绝——只是不再牵连全树。

- **L-38：`RestartManager` 的 stride 真值是 668，不是 656。** 656 之所以"看起来能用"，是因为
  本机每次真实查询只有一条记录——单条记录的测试永远证明不了步长这个参数真的生效；而且代码里
  一句 `if (recSize < 668) recSize = 668` 会静默钳回，把错误值掩盖成"通过"。⇒ 任何"谁锁了这个
  文件"的标签都必须带采集时间（它是时点快照，不是文件属性：同一文件一小时前有持有者、连查 5 次
  needed=0，普查命中率 2/59 → 1/59）；本 README 不承诺任何依赖 stride 数值的能力。

### 遥测与判定的能力上限（2026-10-23 审计实测，原样记录，不修饰）

- **L-39 · 本包现在不可宣称"零遥测"。** 审计脚本自己的结论是：
  `MAY PUBLISH A ZERO-TELEMETRY CLAIM : NO`（退出码 6）。三个原因写在这里，不是免责声明：
  ① **盲区窗口实测中位 2,018 ms / 最差 3,451 ms** —— 两次采样之间开合并关闭的连接，
     这套手段**测不出来**，所以"0 连接"是"窗口里没看见"，不是"从来没有"；
  ② **动态腿跑在 stub 树上**（`find-thunder-paths` 被故意 stub 掉，以免审计碰真实迅雷目录），
     所以它证明的是"工具自己不出网"，不是"工具与真实目录交互时不出网"；
  ③ **标准用户（非管理员）路径【待验】** —— 提权面只在管理员会话里测过。
  同一次审计里能立住的部分也照抄：静态出网 API 在 shipped 代码里 **0 命中**；动态 6 次负载
  归属审计树的连接 **TCP 0 / UDP 0**，而正向对照 `detector alive: saw 3 connection(s)` ⇒
  那个 0 是**活的 0**（探针能看见东西时确实什么都没看见）；静态反向对照 **5/5 CAUGHT**
  （含 rundll32/mshta/regsvr32 借宿主、`certutil -URLX`、纯 DNS、裸 socket）；
  UDP 腿 `Get-NetUDPEndpoint` + `netstat -ano` 兜底：145 端点、0 属审计 pid；
  DNS 腿 `Get-DnsClientCache`：649 → 718 条。
  持久化侧 **4 条 DECLARED**（`install.ps1:140/145`、`uninstall.ps1:143/147`）：计划任务的
  **名称、触发条件、卸载后残留什么**都在第 8/9 节写明，这不是出网，但它是对系统的写操作。
  `advapi32` 的 `OpenProcessToken / LookupPrivilegeValueW / AdjustTokenPrivileges` 三条是
  **提权面**，单列一类披露，不混进 48 条 DECLARED 里；`powershell.exe` 的豁免**仅限运行自身**
  （这个工具就是 PowerShell 脚本，解释器不是能力），任何 `powershell.exe -Command/-EncodedCommand`
  起新进程的形态**不得被这条豁免吞掉**。

- **L-40 · 误判率不是"猜错概率"。** 对抗夹具 **14/14 = 100%** 的含义只有一句：
  **只要上游肯给凭据，判据从不校验字节**。真实语料上 FP = 0 只说明**这次迅雷没说谎**，
  不说明本工具能识破说谎。由此一条已裁定：**属性位豁免（OFFLINE / COMPRESSED / ENCRYPTED /
  REPARSE）+ 一个 act 只能换到 `BACKUP_UNVERIFIED`，不能换到 `BACKUP`** —— 因为那四位是
  **外部任何写者都能单独拨动的开关**（实测 `T3C`：只打一位就产生假阳性），而 exFAT 那种
  **卷上限**是真的拦得住（`FileCtl=0x0` 的机器上 `FSCTL_SET_SPARSE` 返回 50）。这个不对称
  必须补平，补平之前 `BACKUP` 的含义只覆盖"本工具自己测出来的那几条腿"。

- **L-41 · 两条静默形状，密度门拦不住，复验也不会发生。**
  ① `prealloc` 一个动作**同时废掉 G4 与 C6**：两条腿都读"长度"，而长度正是预分配决定的量。
     实测 `T9C`：真 4 MiB 行 + 一个 `SetLength` 出来的残件 ⇒ `DB_STATUS8_SIZE_MATCH` ⇒ `BACKUP`。
     ⇒ 规格 §7.2 禁止预分配**不是风格问题**；README 与配置注释必须写成人话：
     **"G5/G8 的声明腿只在非预分配文件上有效"**。
  ② **跳过重读的键里没有内容哈希**（`tbsm-store.ps1:1706–1717`）：六项全同的文件在中间被改写
     **永不复验**；验证层实测 `hollow.bin density=1`、`still-growing.dat density=1`
     ⇒ **密度门（`-Gate`）对这两种误判形状不响**。这条是能力上限，不是待修 bug；
     要闭合只能在重读键里加入内容哈希，代价是每轮多读一遍。

- **已知问题节（本轮实测状态，如实记，不删条目）**
  - **F-03（未修，发布阻塞）**：`status` 打印 `last run : scanned= committed= deduped= wait=
    skipped= unchanged= bytesCopied=` —— **全空**，而同一个库里 `once` 明确给出 `6/5`、`runs=1
    state entries=6` ⇒ 计数**存下来了但没被读出来**。用户看到的是"好像从没跑过"。这属于本项目
    定义过的 **"未知塌成空"**，与规则 11 直接冲突；修复要求是读不到就打 `NOT-MEASURED`，
    **不许打空串、也不许打 `False`**。
  - **F-04（未修，发布阻塞）**：`doctor [1]` 的 `Get-FileHole live reading: returned but
    NOT-USABLE:` —— **冒号后为空**，状态有、原因缺，正是规则 3"降级必须带错误码"的反例。
  - **F-01 / F-02：本轮实测不复现**（`committed=5`、`verify` 退出 0、`6 heads 0 corrupt`）。
    按规矩记作"不复现"，**不删条目**——删掉就等于下一轮没有东西可以对照。

- **随包分发的取舍（审计后的裁定，写在这里以免文档与包内容漂移）**
  - `smoke_test.ps1` 判为 **test-only，不随包分发**：它需要 `fsutil hardlink create`
    （夹具必须造硬链接），而审计的允许动词集合是"实测到的那三个"，**为测试放宽门槛就再没有门了**。
    装了包之后想验证包是好的，请跑 `build-check.ps1` 与 `doctor`；`smoke_test.ps1` 随源码仓库走。
  - `tools\add-bom.ps1` 是 **tool-only**：它**只在文件头部前插 3 字节（EF BB BF）**，
    内容逐字节不变；**禁止**用它或任何工具做"编码规范化"（改行尾、改引号、重排 Unicode）——
    同一份内容实测：`42,711 B / bom=False ⇒ parse=12`，`42,714 B / bom=True ⇒ parse=0`，
    差的就是那 3 字节。**BOM 在本项目里是承重的**。
- **L-42 · `-Config` 指向的文件会被当作代码执行（config-as-code，这是能力面，不是漏洞）。**
  `lib\tb-core.ps1` 读取该文件字节，用 `[ScriptBlock]::Create($txt + "`r`n`$TBConfig")` 编译后 `& $sb` 执行。
  输入源是**操作者自己选的本地文件**，所以任何能写这份配置的人就等于能在你的账户里执行代码。
  与 `SeRestorePrivilege` 那条并列：**本工具防不了能写你配置的人**。要防请加密备份集并锁好配置目录。

- **L-43 · 累加型夹具至少跑 2 个元素（项目规矩）。**
  `$null += obj` 在 PowerShell 5.1 里返回**对象本身而不是数组**，所以第二条才炸
  （实测：一个硬链接的树正常，文件+别名=两个就整轮 `REFUSED: … PSObject … op_Addition`）。
  同一形状的失明还有 RestartManager 的 `stride=656`（单条记录测不到步长）。
  **结论：任何"只放一个样本"的测试，测不到累加器与步长这两类缺陷。**

- **L-44 · 枚举返回 0 必须区分"确实没有"与"枚举失败"。**
  实测（同一棵树，两种方法）：`[IO.Directory]::EnumerateFiles(...,AllDirectories)` 在 **1,155** 个文件处
  **抛了** `The name of the file cannot be resolved by the system.`，而 `cmd dir /b /s /a-d` 给出 **12,477** 行。
  若当时 `$ErrorActionPreference='SilentlyContinue'`，这份普查就会报"1,155 个文件、0 个 `.xltd`"——
  **一个看起来像事实的假结论**。⇒ 本项目要求：任何基于枚举/搜索的"不存在"，必须同时给出
  **该次搜索没有抛异常**的证明，或用第二种独立方法交叉确认。

- **L-45 · 链记录里 `criteria.decision` 是**规则桶**（实测值 `READY`），真正的裁决在
  `criteria.reason` 的**前缀**（`BACKUP|…` / `BACKUP_UNVERIFIED|…`）。**
  按 `decision` 筛"承诺过的文件"会数出 **0 条**，于是可以被误报成"CLI 从未承诺"——这是
  **"空结果与未执行同形"** 发生在读别人数据上的形状，与本仓库自己的 `logs\status.json` 路径错配（F-03）同型。

- **L-46 · 已修复的假阳性（原发布阻塞第一位）：改名见证只比了 `(目录, 长度)`。**
  注释承诺三条（临时名消失 / 终稿名**本轮新出现** / 大小相等），代码只做了第一条和第三条，
  **从头没比过名字**。实测（修复前）：一次真改名 + 同目录 4 个同尺寸老文件 ⇒ **5 条见证、4 条假**
  （FP=4/5=80%），且 4 条 collateral head 与真那条在持久层不可区分（都 `verified=True`）；
  **FN 贡献 = 0**，所以在"有没有备份到"的口径里完全隐形。
  修复后的授予条件：`(目录相同) ∧ (终稿名本轮新出现) ∧ (终稿 leaf == 临时 leaf 去掉 .xltd/.td) ∧ 长度相等`。
  门 `tests\t-rename-witness.ps1`（开发用，不随包分发）四条夹具 + 反向对照实测：
  `FIXTURE 1 witnesses=1`、`REVERSE CONTROL witnesses=5`、`FIXTURE 2（尺寸不同）witnesses=0 near-miss=1`、
  `FIXTURE 3（终稿上轮就在）witnesses=0`、`FIXTURE 4（两次独立改名）witnesses=2` ⇒ `WITNESS PASS fail=0`。
  **只读普查（2026-10-23，未写入任何文件）**：`C:\<download-root>` 扫到 125 个文件、`threw=False`、其中 **59 个 `.xltd/.td`**；
  合并工作树后按长度分组 **numerator=59 组 / denominator=1,280 个文件**，最大组 **192 个文件同为 262,144 B**，
  **937 个文件落在某个同长度组里**；按"名字派生 + 同长度"匹配的候选 **0 条（分母 59）**。
  ⇒ 结论：**"目录里有同长度文件"在真实树上不是边角情况而是常态**，旧规则的放大倍数因此很大；
  派生名这条新规则在现网样本上不产生误判（0/59），也不放过真改名（夹具 4 全中）。

- **L-47 · 项目级禁令：不得用 `[bool]` 强转归一外部传入的真假值。**
  本机实测 `[bool]'False'` = **True**、`[bool]'0'` = **True**——非空字符串一律为真。
  需要布尔语义的外部输入必须显式解析（`'True'/'False'/'1'/'0'`），解析不出来就 **throw**，
  不许"塌成真"也不许"塌成假"。本文件所在包的 `[bool]` 强转点已在审计中列出并逐条处置。

- **另：`smoke_test.ps1` 不随包分发**（它需要 `fsutil hardlink create` 造夹具，而审计的允许动词是
  实测到的三个）。安装后请跑 `build-check.ps1` + `-Cmd doctor`；冒烟测试从源码树运行
  `03-src\cli\smoke_test.ps1`。`win32io.ps1` 里"文件名进 `Invoke-Expression`"那条**不是现存缺陷**——
  `:387`/`:394` 是记录修复过程的**注释**，活代码走调用算符传参；相应的 payload 夹具从"必修"
  **降级为防回归**。
- **L-48 · `AutoDiscover` / `-NoAutoDiscovery` 是出货能力，不是测试旗标。** Thunder 的自动发现会把**它自己声明的下载根**纳入*拷贝集*——这是设计行为，也正是它的危险面：一次带自动发现的 `once` 在实测中把 6 个真实用户安装包（约 1.77 GB，来自 `C:\<download-root>`）复制进了临时库并写下 `heads`（用户数据只读，未回写）。三条披露并列：`SeRestorePrivilege` 穿 DAC、`-Config` 文件按代码执行、自动发现扩大拷贝集。设了 `AutoDiscover = $false` 或加了 `-NoAutoDiscovery` 之后，发现仍会**只读地跑一次**，用来回答 `doctor`/`status` 新增的那行告警 `LIVE-Thunder-ROOT-IN-WATCHSET`（告警，不阻断）：它点名 watch 集里与 Thunder 下载根重合的目录。测试后忘记改回配置的人，第一次会在报告里看见它，而不是在磁盘上。
- **L-49 · 跳过目录的比较只剩一个原语：`Test-TbSkipHit`。** 规则：键永远以分隔符结尾（所以 `...\云盘缓存\` 吞不掉 `...\云盘缓存2\`）；比较用 `OrdinalIgnoreCase`（文件系统本身大小写不敏感，ordinal 比较会让"排除某目录"看起来配好了其实没生效）；`\\?\` 与 `\\.\` 装饰两侧都剥掉；**空输入 throw，而不是返回看着安全的 `$false`**。大小写解析不出来时不再假装归一化过，而是显式打 `CASING-UNKNOWN …`（`Get-TbSkipKeys` 的 `Casing` 三态：`resolved` / `identical` / `CASING-UNKNOWN`）并降级为大小写不敏感。**仍未闭合**：大小写欠匹配的门（`tests\t-skipdir-semantics.ps1`）本轮仍有 FAIL，见 L-50；过匹配已闭合，由该门的 PASS 钉住。
- **L-50 · 同一个目录有两种拼写，而 `DirectoryInfo.FullName` 不是磁盘拼写的证据。** `%TEMP%` 交出来的是 `C:\Users\EXAMPL-1\...`，枚举交出来的是 `C:\Users\example\...`；即便大小写不敏感，这两种前缀之间也**不互相前缀匹配**。所以负分支（"这个文件不该被跳过"）会把两侧再解析成文件系统报告的长名重试一次（`Get-TbLongForm`，带缓存；正分支不付任何代价）。本条同时记录一次**误证**：`New-Object IO.DirectoryInfo('C:\Users\EXAMPL-1').FullName` 打印出长名，看上去像"读盘拿到了长名"，实际它只做路径规范化、**不要求路径存在**——拿它当证据，就是又把自己的仪器输出当成了被测物的事实。
- **L-51 · `tools\add-bom.ps1` 进包，但把自己限制成只会前插 3 字节。** 两条自证内建在工具里，而不是写在人心里：① 每次写入前先算"字节差恰为 3"与"剥掉前 3 字节的哈希 == 写入前的哈希"，任一不成立就 `REFUSED` 且**不落盘**，成立才打印 `before=… after=… strip==before=True`；② **拒绝处理 `.md`**——BOM 会让 README、审计报告、许可声明的全长哈希不再等于被引用的值，而那些哈希就是证据本身（今晚两份 `.md` 加了 BOM 又撤掉，代价就记在这里）。它进包的理由很直白：整晚 BOM 被剥了至少 5 次，而它是唯一的修复工具。
- **L-52 · "已就绪"是断言，不是状态。** 任何门只要没在本机真正跑过一次，报告里一律写 `NOT-MEASURED`，不写"已就绪"；开发门的退出码同样受 0/1/2 契约约束（本条起因：一个"已就绪"的跳过目录门第一次执行就 4 条 FAIL，其中 2 条是门自己的反向对照把 `\\?\` 形和 `C:\` 形放在一起比，测的是装饰而不是规则）。
- **L-53 · 会写盘的命令必须自己先报警（`RISK(before any copy)`）。** 1.77 GB 事故发生在 `once`，而 `LIVE-Thunder-ROOT-IN-WATCHSET` 过去只有 `status`/`doctor` 会打——设计恰好在真正动手的那条命令上失明。现在 `once`/`watch` 在任何拷贝之前先打这批行，`-DryRun` 也打（彩排正是"我先看看会碰到什么"的正确用法），末尾附一行 `RISK-SUMMARY: live-root=yes|no|NOT-MEASURED casing-unknown=N auto-discovery=ON|OFF`。通则：**任何"这次会碰到真实用户目录"的信号，必须出现在会写盘的命令上，不能只出现在只读诊断命令上。**
- **L-54 · 跳过判断比较的是"身份"而不是"文本"，而且两个方向都要试。** 今晚同一个缺陷以两个方向各出现一次：C9 早期把前缀当相等（过匹配），这轮又发现只用长名去比短名（欠匹配）。原语 `Test-TbSkipRelations` 因此按**路径段**比较（`OrdinalIgnoreCase`），8.3 短名（`ADMINI~1`）与长名（`Administrator`）用"词干 + `~N`"规则跨过去，任一侧是另一侧的完整段前缀即算命中——**方向不再假定**，因为键是人写的、观察值是系统给的。判不出来的段返回 `Undecided + 原因`（记成 `SKIP-RELATION-UNDECIDED`），**绝不返回看着安全的 `$false`**；`Get-TbSkipKeys` 的 `Casing` 也保持三态 `resolved|identical|CASING-UNKNOWN`。
- **L-55 · 夹具自己也会犯错，而且它的错会被读成产品缺陷。** 本门的第三版把"大小写不同"的夹具写成 `MiXdCase` 对比盘上的 `MiXeDcAsE`——这两个不是同一个词（少了一个 `e`），产品回答 `CASING-UNKNOWN` 是**正确**的，是夹具在测一个拼写错误。反向对照同样踩过一次：观察值走 `%TEMP%` 得到 `C:\Users\EXAMPL-1\…`，键是 `C:\Users\example\…`，两者直接 `StartsWith` 测的是装饰差异而不是规则差异，于是对照"永不开火"。**夹具必须与键同源同形**，否则绿色的门与红色的门同样没有意义。
- **L-56 · 生长键必须跨改名迁移：判据要的两把钥匙过去落在两个路径上，工具自己的观察永远凑不齐。** T16 实测：`movie.dat.xltd` 在 pass2 记着 `everGrew=True`，改名成 `movie.dat` 之后新路径的状态是 `everGrew=False`，理由串里同时出现 `NO_GROWTH_WITNESS` 与 `RENAME_WITNESSED`，而 `G4_NA_PREALLOC` 需要**同一条路径**上"见证过增长 ∧ 看见改名"⇒ 永远缺一条 ⇒ 连字节完整、sha 与终稿相符的诚实文件也只能 `BACKUP_UNVERIFIED`。剩下唯一能承诺的腿是外部声明，那正是本项目要避免的东西。`Update-TbRenameWitness` 命中一个见证时，把临时名状态条目里的 `EverGrew / 上一次长度 / Hole 与 Holder 连击 / 首观测时刻` 搬到终稿名，并把搬了哪些键记进 `MigratedKeys`，`-Json` 与状态行同时打 `witnessMigrated`。
  **搬的是观察到的东西，不是许可**：没长过的文件搬过去的是 `EverGrew=false`（夹具 6 反向对照），所以这条迁移不会变成万能许可证。夹具 7 把项目禁令钉在授予路径上：state.json 是**外部提供的文本**，字符串 `"False"` 按字面判为 `False`；同一行若用 `[bool]` 读就是 `True`，一个被手改过或写坏一半的状态文件就能凭空造出一个生长见证。
  顺带抓到同一族的第二个形状缺陷：见证表的键原本用 `Join-Path` 原文小写，而查找键走 `Get-TbNorm`——两者在任何会差别名的路径（本机 `%TEMP%` 给的 8.3 前缀、或 `\\?\` 前缀）上**不同形**，于是见证可以生成却永远查不到。现在两侧同一形状构造。
- **L-57 · "非出货"不等于"免检"：`tests\` 树改成允许清单制，未登记 ⇒ 报红并点名。** 今晚我在 `tests\` 与 `tests\out\` 里造了 12 个一次性探针（`_bom-census/_census/_cli-map/_drift/_gate-triage/_json-probe/_move-in/_recheck-claims/_resync` + `out\_ctl1.txt/_ctl2.txt/_inner-loadgate.ps1`，共 43,030 B）。第一次暴露它们的不是任何门，而是 `add-bom -Check` 顺带打印的 `_drift.ps1 nonAscii=6 BOM=NO`——也就是说**没有任何门会因为往 `tests\` 里丢文件而变红**。删除顺序按证据走：(1) 编码可感知的引用扫描（语料 164 个文件，实测含 3 个 UTF-16LE，搜索能力先用一个已知存在的名字做对照开火）证明逐名 0 引用，三个例外只被同批待删文件互相引用；(2) 删完**重跑门禁**证明没有退化（`SKIPDIR PASS fail=0`、`WITNESS PASS fail=0`、`tests\build-controls.ps1` 30 controls / 0 failed）——**0 命中与"搜索能力坏了"同形，所以结论只能由重跑给出**；(3) 新增 `tools\audit-tests-tree.ps1` + `tests.manifest.txt`：默认拒绝，允许条目分"具体文件"与"以 `\` 结尾的生成目录前缀"两类，且**生成目录里仍检查垃圾形状**（`^_`、`-probe`、`-census`、`-triage`、`\.bak$`、`instrumented`…），因为 21 KB 的 `build.ps1.instrumented.bak` 正是躺在"合法输出目录"里的。反向对照开火：植入一个未登记的 `tests\_auditor-control.ps1` ⇒ `exit=1 RED=1`；删掉 ⇒ `exit=0`。登记条目若盘上没有 ⇒ WARNING（"声明存在而不存在"与"声明不存在而存在"是同一类谎的两个方向）。
  为什么不用名字黑名单：`build.ps1` 的排除表列了 14 条前缀，实测漏掉 `_cli-map.ps1`——它没进包只是因为打包走白名单，不是因为排除表完整。
- **L-58 · `add-bom` 的退出码回到 0/1/2，并且每个分支都被执行过。** 原来是 `-Check` 漂移 ⇒ `exit 4`、解析失败 ⇒ `exit 5`：调用方只知道"非零 = 不好"，无法区分"有事要人决定"和"工具根本没跑起来"，这与把空结果当成健康是同一种失明。现在 `0` = 跑完且无需决定；`1` = 跑完但有需要决定的问题（漂移、或某个 `.ps1` 不再能解析）；`2` = 跑不起来（根目录不是目录，**或一个候选都没扫到**——空扫描与健康树同形，所以拒绝打印绿色）。六个状态全部实测开火：两种 `2`、`1`(漂移)、`0`(写入后)、`0`(再 `-Check` 复核)、`1`(解析失败)。
  过程里抓到一条更普遍的：**守卫放在被守卫事物的下游，就只是装饰。** 第一版把"根目录不存在 ⇒ `exit 2`"写在扫描之后，实测 `-Root` 不存在时 `Get-ChildItem` 先抛，工具带着 PowerShell 自己的 `exit 1` 死掉、什么都没打印——**分支在源码里存在，在行为里不存在**。检查因此上移到扫描之前。
  还有第四条：我曾为"让拒绝分支可达"加一个 `-Files` 显式候选口，连续四次修复不收敛（管线把元素交成没有 `.Name`/`.Extension` 的裸字符串，连 `.ps1` 都进了拒绝分支；`New-Object IO.FileInfo(...)` 与 `New-Object …List[object]` 各抛 `Argument types do not match`），于是整条撤掉，改用"扫描同时收集 `.ps1` 与 `.md`，`.md` 只用于被点名拒绝"这一更小的形状。**`-Files` 的状态记 `ABANDONED-NOT-MEASURED`**：既不是"已实现"，也不是"没做"。四个失败的尝试原样留着，因为"试过四种都不收敛所以选更小的形状"是设计文档里最有用的信息。
- **L-59 · 改名见证的载体必须是六字段结构，布尔载体在判据层会被拒绝——这条是被实测撞出来的，不是读出来的。** 生长键迁移上线后跑同一夹具，`gate-errors=1`：判据层 `Resolve-XldRenameWitness` 对 `RenamedFromTemp=$true` 直接 `throw WITNESS_SHAPE_REJECTED_BOOL`（布尔正是让六个字段无声消失的那个载体）。CLI 因此改为：见证值本身就是 `New-XldRenameWitness` 的有序六字段（`TempName/FinalName/DerivedFinal/LengthMatch/AppearedThisRound/GapMs`），`RenamedFromTemp` 只以 falsey 形式发送，`GapMs` 由决策循环用临时名条目的 `LastSeenMs` 与本轮 `NowMs` 算出（ witness 构造处没有时钟，诚实值是先写 `-1`，等真时刻到了再填）。同一条夹具的两侧状态文件给出绝对数：旧构建 `NO_GROWTH_WITNESS=1 / GROWTH_WITNESSED=0 / G4_NA_PREALLOC=1`，新构建 `NO_GROWTH_WITNESS=0 / GROWTH_WITNESSED=1 / WITNESS-MIGRATED=1 / WitnessMigrated=true=1` ⇒ 钥匙真的搬过去了；新构建剩下的拒绝码是 `TEMP_NAME_NOT_A_TEMP=1`，即**判据层接受的后缀清单 `\.(tmp|part|crdownload|downloading|td|tdp)$` 不含引擎实际使用的 `.xltd`**（本仓库 CLI 的 `TempSuffixes` 是 `.xltd, .td`）。这一条由 `tests\t-rename-witness.ps1` 夹具 9 现场测量并记录为**跨层未闭合阻塞**，不在我这层改：把 `.xltd` 塞进我的清单容易，把它塞进判据的接受表是判据层的决定。
- **L-60 · 两条轴，三个字段，缺字段 = 未测 ≠ 假：`verified` 这个词今晚正式退休。** 存储层的 writer 已不再落 `verified`（不留旧键），库里的版本现在带 `contentVerified`（内容轴：发布后重哈希是否仍等于自己的名字）、`completionClaimed`（完成轴：gate 是否真的裁决过一个完成动作）、`promisedVersion`（承诺轴：restore 被承诺回到哪一版，**没有承诺时这个键根本不存在**，而不是 null/false/0）。CLI 这一侧原先 8 处读的是那一个混称词，其中 `verify` 循环里的 `[bool]$h.verified` 在镜像失效下会把**每一个** head 读成"未经证明"——和今晚早些时候 `5/5 verified=True` 的假通过是同一枚硬币的两面：以前全绿是假的，现在全红也是假的。现在统一走一个读者 `Get-TbAxis`：键不存在 ⇒ `NOT-MEASURED(key-absent)`，值不是可判真值 ⇒ `NOT-MEASURED(undecidable:…)`，布尔照原样读出，**绝不把缺席折叠成 `$false`/0**（这正是 `Get-TbShown` 早就定下的形状，只是没应用到 head 上）。
  **禁止词汇映射**：这一层不许把 `READY`/`BACKUP`/`SKIP`/`WAIT` 这些词翻译成"完成 = 真"。现场 gate 用 `READY/SKIP/WAIT`，判据层用 `BACKUP/BACKUP_UNVERIFIED`，在任何一侧做映射本身就是伪造完成声明的源头；完成轴只认 gate 对象上真实存在的 `CompletionClaimed` 字段。
  改名见证的载体同批换掉：`RenamedFromTemp` 这个布尔键在送给判据的上下文里被**删除**（不是补一个 `$false`——留一个别人会信的键，就是给第二个读者造假），改名事实只以六字段 `RenameWitness` 有序表通过。判据层对布尔键直接 `throw WITNESS_SHAPE_REJECTED_BOOL`，所以"只升级判据、不动 runner"会让每一个被见证过改名的文件在 `Classify-File` 抛——而 Thunder 每次下载都要改名，爆炸半径是整个 scan。
  配置模板同步：`VerifyAfterCommit` / `SkipUnchanged` / `StateMaxEntries` 三条注释里的"verified/已校验"按轴拆开写，并新增披露：**`-AllowUnverified` 放行的是内容轴未经证明，不构成任何完成声明；用它恢复出来的文件仍可能是下载中断的半成品**（这是判据层把徽章 `Verified → CompletionClaimed` 改名的文档面）。
- **L-61 · 完成轴必须作为字段穿过 gate，否则库里全是 NOT-MEASURED；而"缺字段"这条腿是被一次失控的对照逼出来的。** 存储层现在只在 gate 对象**真的带着 `CompletionClaimed` 字段**时才落这个键。而 CLI 的 gate 只回 `{Decision, Reason}`——于是实测出现最荒诞的组合：判据已经答 `BACKUP`、blob 已 `contentVerified=true`、`heads.json` 里 `completionClaimed` 出现 **0 次**。库不知道任何承诺存在过，restore 也无从拒绝一个不存在的承诺。修法只有一个方向是对的：把判据自己的字段透传下去（`Get-TbBoolean` 读，读不出就不写这个键），**绝不由 `Decision` 的字面量倒推**——本 runner 说 `READY/SKIP/WAIT`，判据层说 `BACKUP/BACKUP_UNVERIFIED`，任何在两套词汇之间架桥的代码都是伪造完成声明的产地。同理，`status` 里那句 `completion acts (rename this process witnessed)` 原本就是数字节的标签 `Decision -eq 'BACKUP'` 得出来的：那正是被禁止的词汇映射，现在打成两个数——`completion acts by FIELD …`（字段）与 `BACKUP decision LABEL count …`（标签），并排给出，谁也不替谁说话。
  **反向对照（真的开火了）**：把状态文件里那条真 `true` 改成字符串 `"False"`（`"CompletionClaimed": "False"`，也就是 `[bool]` 会读成 `True` 的那一个形状），实测 `completion acts by FIELD` 从 **1 → 0**，`claims adjudicated FALSE` 从 **1 → 2**，而 `BACKUP decision LABEL count` 保持 **1** 不变——字段与标签确实是两条独立的读数。
  **但第一次"通过"的对照是假的**：我先用长路径 `C:\Users\example\…` 去替换配置里的路径，而配置里写的是 `$env:TEMP` 给出来的 8.3 短形 `C:\Users\EXAMPL-1\…`；`.Replace()` 命中 0 次，两次 `status` 读的其实是同一个没被动过的原始库，数字一模一样，看起来像"防护有效"。修法是替换前后各数一次：源路径出现次数必须从 2 → 0、克隆路径必须 > 0，否则**拒绝报告一个不可能开火的对照**。这与今晚另一条同类事故只隔一层纸：不同源、不同形的对照，永远不会红。
- **L-62 · `edit` 类工具会把非 ASCII `.ps1` 的 BOM 抹掉，而只有 build 门发现了它。** 我给配置模板改了三段中文注释（拆两轴、加 `-AllowUnverified` 的披露），回来 `build.ps1` 直接拒绝：`sources with non-ASCII and NO BOM … n=1`，`problem count = 1`，一个字节都没写进产物树。文件头从 `239,187,191` 变成 `35,32,61`——**BOM 在编辑中被丢了**，而 Windows PowerShell 5.1 读无 BOM 文件走 ANSI 代码页，2,955 个非 ASCII 字符的解码从此不可证明。补回来用的是本工具自己那套算术自证：字节数 +3、剥掉 3 字节后的哈希与改前**完全相等**，然后 `build exit=0 / files written=21 / problem count=0`。**教训是流程性的**：以后每次用编辑工具碰含非 ASCII 的 `.ps1`，都要立刻重测 `first3 / bytes / parse / 全长哈希`，不能把"我改的是注释"当成免检理由；而这一条能被抓到，纯粹因为 build 门在写字节之前先问解码，非出货与出货在这件事上没有区别。
  同批还消掉两处"一端改了另一端没改"：`thunderbackup.config.ps1` 的注释与 `tb-core` 帮助文本里残留的 `verified` 措辞，以及 `tb-commands` 里对旧 `verified` 键的 8 处读取（现在 0 处，全走 `Get-TbAxis`：键不存在 ⇒ `NOT-MEASURED(key-absent)`，值不可判 ⇒ `NOT-MEASURED(undecidable:…)`，绝不塌成 `$false` 或 0）。夹具 9 也改了写法：原来它把判据层一条硬编码后缀正则**抄进测试**，判据层随后改成查 `TempSuffixes`，我的夹具就停在"仍然报 `.xltd` 被拒"的旧世界上——**抄来的常数不是契约**；现在它只断言三件可证的事（硬编码字面量已不在判据源里、判据引用调用方提供的后缀表、本包确实递交 `.xltd`），真正的接受与否由构建产物上的 film.dat 端到端测量给出（`GROWTH_WITNESSED=1`、`TEMP_NAME_NOT_A_TEMP=0`、决策 `BACKUP`）。
