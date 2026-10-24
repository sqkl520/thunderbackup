<div align="center">

# ThunderBackup

> *「它不猜下载有没有完成——它只承认自己亲眼看见的那一次改名」*

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE)](https://learn.microsoft.com/powershell/)
[![Runtime network calls](https://img.shields.io/badge/runtime%20network%20calls-0-lightgrey)](#安全与数据流)
[![Lines](https://img.shields.io/badge/script%20length-12%2C060%20lines-c2410c)](#仓库结构)

<br>

**一个只读的外部备份工具：给迅雷的下载目录做版本化备份，并且拒绝把「看起来满了」当成「下载完了」。**

<br>

你有没有过这种经历——一个 4 GiB 的视频，进度条停在最后，文件在资源管理器里显示的**大小是完整的**，双击打开只有前 200 MiB 能播。大小到了不等于字节到了，这是 NTFS 预分配（preallocation）的常态：迅雷先把 `EndOfFile` 撑到目标大小，再往里写。你照着「大小对上了」去备份，备份下来的就是一个四分之三空壳。
这个工具存在的全部理由：**在它自己能证明完成之前，一个字节的完成声明都不发。**

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\thunderbackup.ps1 -Cmd doctor -Config .\thunderbackup.config.ps1
```

Windows PowerShell 5.1（19041 实测）· 无需管理员 · 不注入、不挂钩子、不装驱动 · 对迅雷目录**只读**

[先看输出](#先看输出一个文件敢不敢备份三个数字说了算) · [装上就能用](#装上就能用) · [判据机制](#它凭什么判断判据机制) · [边界](#边界它不做的事)

<br>

</div>

---

## 先看输出：一个文件敢不敢备份，三个数字说了算

`doctor` 是唯一一个"先证明仪器可信，再谈结论"的命令。它跑在一台真实机器上的原样输出（截前三段）：

```
[1] LANGUAGE  ps=5.1.19041.7725 edition=Desktop lang=FullLanguage pid=12984
native probe types: XldbProbe=True TbsM=True Win32Io=True | Get-FileHole live reading: ok eof=125049 alloc=126976 hole=-1927 vol=NTFS
capability level (criteria.ps1 ladder: 0=cmdlets only, 1=+native probes, 2=+Thunder declaration): 1
degraded criteria: C6.expect
claim: preallocation detected via ABSOLUTE hole bytes (sign only, 1 cluster = 4096 B resolution);
       paused-with-final-name NOT decidable without TaskDb -> BACKUP_UNVERIFIED.
```

第二段是它自己承认做不到什么：

```
[2] WHAT THAT COSTS US  (this tool's own judgement set)
hole sign (G4) available: True   deletePending (C5): True   FileId identity (C13): True   writer probe (C3): True
Thunder declaration (G5 / level 2): NOT WIRED IN THIS PACKAGE, by choice. Reading TaskDb.dat requires
  staging a copy of a file that holds plaintext third-party cookies and plaintext passwords; the package
  refuses that trade. Consequence: 'verified' can only come from a rename this process personally witnessed
  -> verified count is LOW by design, and needs-attention is where most files sit.
```

第三段是它发现**你的配置可能让备份静默失效**时的样子（这条真的会自己喊出来）：

```
[3] WATCH SET  (union of every candidate, never one 'authoritative' key)
  WARNING: watch set collapsed to ONE directory from 1 config key(s). Thunder keeps up to 9 download-path
  keys; if this is not where your files actually land, the tool will silently back up nothing.
  *** If that is not where your files land, the tool watches an empty directory and backs up NOTHING,
      with no error. Put the real path in WatchDirs. ***
```

**三个数字**：`EndOfFile`、`AllocationSize`、以及两者的差 `hole`。`hole > 0` 就一个字节都不会被承诺完成；`hole ≤ 0` 也**不**等于完成（最后那个不对称是整个设计的地基）。复算这一条不需要装任何东西——NTFS 上任意一个预分配文件都能验：

```powershell
# 读者可复算：对一个正在下载的文件看这两个数
fsutil file queryfileid "$env:USERPROFILE\Downloads\<某个正在下载的文件>"
fsutil file queryallocranges offset=0 length=1 "\\?\$env:USERPROFILE\Downloads\<同名文件>"
```

---

## 装上就能用

**方式一：直接用（不安装）**

```
git clone --depth 1 <this-repo>
cd thunderbackup
copy thunderbackup.config.ps1 thunderbackup.config.local.ps1
notepad thunderbackup.config.local.ps1     # 只改一行：$TBConfig['StoreRoot'] = 'D:\ThunderBackup'
powershell -NoProfile -ExecutionPolicy Bypass -File .\thunderbackup.ps1 -Cmd doctor -Config .\thunderbackup.config.local.ps1
```

**方式二：装到固定目录并挂计划任务**

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -InstallDir "$env:LOCALAPPDATA\ThunderBackup"
# 注册开机自启（可选，默认不注册）：
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -InstallDir "$env:LOCALAPPDATA\ThunderBackup" -Schedule
```

`-Schedule` 是**唯一**会碰计划任务操作的位置（`install.ps1` 里 `Register-ScheduledTask` 出现 3 处：`:5` 注释、`:147` 注册、`:152` 失败分支）。不带这个开关就只复制文件、不注册任何自启。

**方式三：只读源码，不要运行**

`lib\criteria.ps1` 是判据层（1,582 行），可以独立阅读——它不依赖包里其他文件就能告诉你"什么条件下这个工具会拒绝发完成声明"。

装完自检：目录里应当有 18 个 `.ps1` 和 3 个 `.md`（共 21 个文件）。少任何一个说明复制不全，`-Cmd doctor` 会在 `PACKAGE LOAD FAILED` 处停下而不是带着半个包继续跑。

然后在 PowerShell 里直接说话：

```
-Cmd once       跑一轮：扫描 → 判据 → 备份
-Cmd watch      常驻，按 -IntervalSec 轮询
-Cmd status     看上一轮做了什么，以及哪些文件在 needs-attention
-Cmd verify     复核库：blob 还在不在、哈希对不对
-Cmd restore    从库里还原，默认还原最新版本
-Cmd doctor     仪器自检：这台机器上哪些判据真的可用
```

---

## 它凭什么判断：判据机制

这个工具的核心不是"备份"，是**拒绝**。四道判据每条都只是必要条件，没有任何一条是充分的。

| 判据 | 它看什么 | 它挡什么 | 它挡不住的 |
|---|---|---|---|
| **G4 洞** | `hole = EndOfFile − AllocationSize`，只看符号不看阈值 | 预分配空壳（`hole > 0`） | `hole ≤ 0` 但尾部是零填充 |
| **G5 声明** | 迅雷自己的任务库说"完成了" | 状态没到就下结论 | 本包**故意不接线**（见上），所以大多数文件只能拿到 `BACKUP_UNVERIFIED` |
| **C3 写者** | 还有别人开着写句柄 | 边写边拷 | 读者/写者共享掩码双向，分不开 |
| **C13 身份** | NTFS FileId 跨改名守恒 | 把"换了个文件"当"同一个文件改名" | 非 NTFS 卷没有 FileId |

判据之后还有一道**三级降级阶梯**：L2（有迅雷声明）→ L1（有原生探针：洞、删除挂起、FileId、写者探测）→ L0（只有 cmdlet，洞和写者全失明）。掉到哪一级不是启动时定死的，而是**每一轮重新测**，因为 WDAC / AppLocker / 组策略可以在运行中生效。降级只会让承诺变少，不会变多——这是设计上的单向阀。

一个文件要拿到最强的那个词（`BACKUP` + 完成声明），必须同时满足：所有判据通过 **且** 提交协议三段全等 **且** 有一个正向完成证据（迅雷声明、字节级生长、或本进程亲眼看见的 `temp → final` 改名）。缺一样就退到 `BACKUP_UNVERIFIED`——**照样备份，照样能用，只是不承诺完成**。

---

## 安全与数据流

这些不是承诺，是可以当场跑的 grep。作用域说明：**运行时面** = `thunderbackup.ps1` + `thunderbackup.config.ps1` + `lib\*.ps1`；`build-check.ps1` 和 `telemetry_audit.ps1` 是开发/审计工具，不在运行时面里，它们自己会发起网络探测来测量，别把两者的命中数混在一起。

```powershell
# 运行时面：网络与注入原语，全部应为 0
Select-String -Path .\thunderbackup.ps1,.\thunderbackup.config.ps1,.\lib\*.ps1 `
  -Pattern 'Invoke-WebRequest','Invoke-RestMethod','Start-BitsTransfer','New-Object System.Net',`
           'VirtualAlloc','WriteProcessMemory','SetWindowsHookEx','CreateRemoteThread' -SimpleMatch |
  Measure-Object        # => Count : 0

# 运行时面：注册表写，全部应为 0（发现有 GetValue 只读）
Select-String -Path .\lib\*.ps1 -Pattern 'SetValue','Set-ItemProperty','New-ItemProperty' -SimpleMatch |
  Measure-Object        # => Count : 0

# 对迅雷目录只读：全包不应出现对它写文件的调用
Select-String -Path .\thunderbackup.ps1,.\lib\*.ps1 -Pattern 'Set-Content','Out-File','Add-Content' -SimpleMatch |
  Measure-Object        # 写操作只出现在 StoreRoot 下（restore 的落点由你指定）
```

数字（本仓库这一版实测）：运行时面 `Invoke-WebRequest` / `Invoke-RestMethod` / `Start-BitsTransfer` / `New-Object System.Net` / `VirtualAlloc` / `WriteProcessMemory` / `SetWindowsHookEx` / `CreateRemoteThread` 各 **0** 处；注册表 `SetValue` / `Set-ItemProperty` / `New-ItemProperty` 各 **0** 处；`OpenProcessToken` 只出现 2 处（`:689` 的声明 + `:711` 的调用），且是对**自己**的进程令牌（`GetCurrentProcess()`）取 `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY`，用于 DAC 遍历时的备份特权；`OpenProcess` 打开他人进程的原语出现 0 处。

**关于"零遥测"这句话，我不替它背书。** 包里带一个自审工具 `telemetry_audit.ps1`，它自己的结论就是不能宣称零遥测：

```
MAY PUBLISH A ZERO-TELEMETRY CLAIM : NO      (exit code 6)
```

三个原因写在 `telemetry-audit.md` 里，不是免责声明：轮询采样有盲窗（实测最差一轮 2,208 ms，一次开-关都发生在两次采样之间的连接看不见）；UDP 只列已绑定端点，一发即走的 `sendto()` 不留行；孙进程若在两次树走查之间起停则无法归属。所以准确的表述是：**运行时面没有主动发起网络的代码**（上面的 grep 可复算），而"零遥测"作为一个更强的主张，本仓库不宣称。

---

## 边界：它不做的事

- **不读迅雷任务库（`TaskDb.dat`）。** 那个文件里有明文的第三方 Cookie 和明文口令，本包拒绝为了一个判据去复制它。代价写在 `doctor` 第二段里：`verified` 的数量因此**偏低是设计如此**，大多数文件停在 `BACKUP_UNVERIFIED`。
- **不注入、不挂钩子、不装驱动、不碰注册表写、不改迅雷任何配置。** 关掉这个工具，被观察的软件不会知道它存在过。
- **拿不到 `hole ≤ 0` 就等于拿不到承诺。** 反过来不成立——这是它最大的判断盲区，本文将"实测误判率"直接列在下面而不是藏进附录。
- **对抗夹具上的误判率并不好看。** 在 46 个共有语料行上，本版 gen-2 的完成声明误判是 **8/12 = 66.7%**（12 次承诺里 8 次字节不是终稿），漏判 **6/194 = 3.1%**；上一代 gen-1 分别是 9/13 = 69.2% 与 6/141 = 4.3%。**两代数量级相同——这个版本没有把误判修好。** 这些夹具是专门造来攻击判据的（伪造任务库行、属性位欺骗、预分配残留），不是"平均下载场景"，但把它写在这里比藏起来有用：现阶段请把 `BACKUP` 当成"值得人工确认一次"，不要当成"文件完整"的证书。
- **不支持 exFAT / FAT32 上的完成判定。** 那些卷没有 FileId 也没有 `queryallocranges`，判据直接降级为"只复制、不承诺"。
- **普通用户可运行性未在本机验证。** 本仓库的审计跑在管理员令牌下；标准用户路径需要一台真正有标准账户的机器才能证伪或证实，标【待验】。
- **我自己踩过的坑，写在这里当警告**：一次在 `%TEMP%` 里试跑时忘了关自动发现，工具把真实的下载目录并进了监视集，拷走了大约 1.77 GB 用户数据。之后才加的 `-NoAutoDiscovery` / `AutoDiscover=$false` 和那条"监视集塌缩成一个目录"的告警。**默认值救不了错误配置，所以 `doctor` 会主动喊。**

这是一个 0 star 的原型工具，不是产品。它的价值在于判据本身可以被读懂和复算，而不在于能替你保管数据。

---

## 仓库结构

```
thunderbackup/
├── thunderbackup.ps1          # 唯一入口：六个动词的分发与参数
├── thunderbackup.config.ps1   # 配置模板（改 StoreRoot 这一行就能跑）
├── install.ps1 / uninstall.ps1# 安装与卸载（-Schedule 才碰计划任务）
├── lib/
│   ├── criteria.ps1           # 判据层：G4/G5/C3/C13 + 三级降级 + 拒绝理由码
│   ├── tb-core.ps1            # 扫描循环、判据装配、per-file 异常隔离
│   ├── tb-commands.ps1        # 六个动词的实现与输出格式
│   ├── tbsm-store.ps1         # 内容寻址存储：原子写、版本链、fsck
│   ├── tbsm-commit.ps1        # 提交协议：三段全等、版本链追加
│   ├── tbsm-restore.ps1       # 还原：按名/按 FileId/按版本
│   ├── win32io.ps1            # 原生探针：CreateFileW / FileIdInfo / 洞
│   └── find-thunder-paths.ps1 # 发现迅雷安装位置（只读注册表）
├── build-check.ps1            # 开发门：源码与产物逐文件比对（不发货时用不上）
├── telemetry_audit.ps1        # 自审工具：测量本包自己的网络面
├── telemetry-audit.md         # 那次审计的原始报告（含它自己的"不能宣称"结论）
└── THIRD_PARTY_NOTICES.md
```

`lib\criteria.ps1` 是这套东西里唯一值得单独读的文件：它把所有"什么时候拒绝"写成了显式的理由码（`G4_NA_PREALLOC`、`VERIFIED_CAPPED_BY_PREALLOC`、`NO_COMPLETION_ACT`、`TMPNAME_WEAK.*` 等），每个码都能在日志里被搜到。

---

## 起源：一个被推翻的方案

最初的判据是"分配密度"——已分配字节 / 文件大小，低于某个比例就认为没写完。它被推翻了，原因很实在：**密度是一个相对量，判据需要的是一个绝对量**。一个 4 GiB 文件写到 3.9 GiB（密度 97%）和一个 400 KiB 文件写到 390 KiB，密度一样但风险完全不同；更糟的是，任何阈值都能被"刚好写在你阈值之上"的残件绕过。

换成 `hole = EndOfFile − AllocationSize` 之后，判据变成了**符号**而不是阈值：`hole > 0` 是"文件系统自己承认还有簇没给"，不需要我猜比例。代价是它在另一侧彻底失明——`hole ≤ 0` 时它什么都不知道，因为 NTFS 会把零填充的尾部也真分配掉。这个不对称没有被"修好"，而是被**披露**：所有 `BACKUP_UNVERIFIED` 的存在都是这条不对称的直接后果。

第二个被推翻的是"可信的完成声明可以来自上游"。这一版仍然接迅雷的声明（G5），但把它当**必要而非充分**，并且因为口令明文的问题干脆没接线——所以这个版本里最强的证据只剩"本进程亲眼看见的那次 `temp → final` 改名"。这不是能力不足，是一个刻意选择的取舍：宁可承诺少，不可承诺假。

---

## 反馈与贡献

什么算 bug：判据给出了与 `lib\criteria.ps1` 注释不一致的结论；`doctor` 报告某项判据可用但实际没有生效；同一份存储在不同轮次给出不同判定。
什么算提案：新的判据（请附"它挡什么、它挡不住什么、在什么卷上不可用"三句话）；对降级阶梯的调整。

提之前请先跑这两条，把输出贴进 issue：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\thunderbackup.ps1 -Cmd doctor -Config .\thunderbackup.config.ps1
Select-String -Path .\lib\criteria.ps1 -Pattern 'BACKUP_UNVERIFIED' -SimpleMatch | Measure-Object
```

不要在 issue 里贴你的真实下载路径或迅雷账号——这个仓库的 README 和代码里的所有路径都已脱敏为示例值，你的不该例外。

## License

MIT —— 随便用、随便改、随便造，出事别找我。
