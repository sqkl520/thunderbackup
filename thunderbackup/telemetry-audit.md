# telemetry-audit.md —— "零遥测"是被测出来的，不是被承诺的

负责人要求：**用测量证明零遥测，而不是用承诺**。这份文件是一次真实运行的报告。
所有数字都来自下面这条命令在我这台机器上的一次执行；没有模板值，没有"应该是 0"。

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\Example\thunder-work\work\dist\telemetry_audit.ps1 -KeepWorkRoot
```

- 运行开始：**2026-10-22 23:42:56**（harness pid=6412），结束约 23:47。
- 审计退出码：**6**（= 有静态 FINDING 待处置）。不是 0，也不是 4；见"退出码语义"。
- **`MAY PUBLISH A ZERO-TELEMETRY CLAIM : NO`** —— 这是审计自己打印的结论，不是我加的限制。
  原因不是仪器瞎了（两类反向对照都 PASS），而是产物里确实有 6 条需要负责人表态的实测命中。
- 本文件与 `THIRD_PARTY_NOTICES.md` 描述的是**同一份字节**（清单见下），
  其中 `THIRD_PARTY_NOTICES.md` 写于 23:43:33，**落在这次运行进行中**，所以它没被 `[S8]` 的
  "examined 20 file(s)" 计入。它不是 `.ps1`，静态扫描的 19 个 `.ps1` 清单不受影响。

## 0. 复现

```powershell
# 只跑静态（一定退出 5：动态腿与正向对照没跑，"零遥测"未经检验，绝不给 0）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\telemetry_audit.ps1 -StaticOnly

# 完整跑（静态 + 正向对照 + 空闲对照 + 6 次动态负载 + 静态反向对照 + 动态反向对照）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\telemetry_audit.ps1 -KeepWorkRoot

# 想要机器可读结果：同一份输出尾部有 --- BEGIN JSON / --- END JSON 之间的完整结构
```

参数：`-PollMs 200`（标称采样间隔，实测见下）、`-GraceCycles 8`、`-TreeWalkEveryNCycles 3`、
`-ModuleSampleEveryNCycles 5`、`-MaxRunSeconds 240`、`-IdleControlSeconds 12`、
`-CompareRoot <目录>`（版本来源对比）、`-StaticOnly`、`-KeepWorkRoot`、`-WideOutput`。
夹具、副本、存储全部落在 `%TEMP%`；**不读也不写 `D:\Thunder` 与 `C:\迅雷下载`**（见 `[F]` 节与限制）。

---

## 1. 运行环境（实测，不是我复述配置）

| 项 | 实测值 |
| --- | --- |
| PowerShell | `5.1.19041.7725` Desktop，语言模式 `FullLanguage`，64 位进程 `True` |
| OS | `Microsoft Windows 10 专业版 build 19045` |
| .NET Framework 4.x | 注册表 release 键 `533325` |
| DeviceGuard | code-integrity-enforcement=`0` user-mode=`0`（未开启） |
| 身份 | `EXAMPLE-BOX\example`，`administrator=True` |
| TCP 仪器 | `Get-NetTCPConnection`，探针通过，**首次调用 1788 ms** |
| UDP 仪器 | `Get-NetUDPEndpoint`（`Get-NetUDP`/`EndConnection` 这类名字在本机 **不存在**，报告不把它当 0） |
| 进程树遍历 | `Win32_Process` via `Get-CimInstance` |
| 解析器/缓存仪器 | `Resolve-DnsName=present`、`Get-DnsClientCache=present`、`ipconfig.exe=present`、`Get-NetUDPEndpoint=present`、`Get-NetUDPEndConnection=ABSENT`、`netstat.exe=present` |
| 名字遮蔽检查 | 29 个自造 `*-TbAud*` 函数名对照 `Get-Alias` + 全部 cmdlet：**0 冲突** |

这台机器是**共享的开发机**：整轮测量期间，其它进程产生了 **2262 条**新的 TCP 行（审计单独计数、
不把它们算到被审计进程头上）。"机器上有连接"≠"包有连接"，所以两个数字分开列。

---

## 2. `[S]` 静态：逐行扫每一个 `.ps1`

- 扫描文件数：**19 个 `.ps1`**（`Get-ChildItem -Recurse -Filter *.ps1`，**没有硬编码清单**）。
- 规则库：**82 条**（NETWORK / INJECTION / OUTBOUND-FINGERPRINT / DECLARED / INFORMATIONAL 五组），
  函数自带行数自检（82 行不匹配就抛，因为 PS 5.1 里逗号比 `+` 结合更紧，数组元素会被并掉）。
- **NETWORK（出网 API）命中：0** → 这是"零遥测"的静态半边证据。
- **INJECTION / PERSISTENCE 命中：4（FINDINGS，逐条）**

| 位置 | 命中规则 | 原文 |
| --- | --- | --- |
| `install.ps1:140` | `Register-ScheduledTask` | `Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $settings ...` |
| `install.ps1:145` | `Register-ScheduledTask` | 失败提示字符串里出现同一 API 名 |
| `uninstall.ps1:143` | `Register-ScheduledTask` | `Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop` |
| `uninstall.ps1:147` | `schtasks` | 提示文字 `schtasks /Delete /TN "..." /F` |

这四条是**安装/卸载的可见功能**（注册计划任务跑备份），不是隐蔽通道：`install.ps1` 会打印任务名、
`uninstall.ps1` 会删掉它。但"计划任务持久化"属于负责人划的红线类别，所以审计判红、我不擅自降级。

- **DECLARED（本地动态代码 / 本机执行面）命中：48**，全部逐条打印，包括：
  `lib\criteria.ps1:494 Add-Type`、`lib\tbsm-store.ps1:64 / :1790 Add-Type`、`lib\win32io.ps1:26 Add-Type`、
  `lib\tb-doctor.ps1:72/197/204/207 Add-Type`、`lib\tb-core.ps1:326 [ScriptBlock]::Create`、
  `lib\tb-core.ps1:328 & $sb`、`lib\tb-commands.ps1:239 / lib\tb-doctor.ps1:78 & certutil.exe -hashfile`、
  `install.ps1:65`、`lib\tb-commands.ps1:454 Read-Host`。
  这些是"包会在本机做需要看一眼的事"的清单，不是出网证据。
- **INFORMATIONAL 命中：77**（注册表读、`[DllImport]` 声明本身），**comment-only 命中：43**。
- 非 shipped 文件（审计工具自己 + 开发门）里的 finding 形状命中：**35 条，分布在 2 个文件**
  （`build-check.ps1`、`telemetry_audit.ps1`）。**自指披露**：审计工具自己会造 `TcpListener`/`TcpClient`
  做正向对照，也会被规则扫到；这些不算在产品代码里，但必须让人看见。
- 读不了的文件：**0**；不能归属于 package root 的文件：**0**（8.3 与长路径已在 MAIN 顶部统一规范化，
  `unattributed` 会直接判退出码 6）。

## 3. `[S2]` 能被拉起的可执行文件 vs 白名单

- 白名单（负责人定的）：**`fsutil.exe`、`certutil.exe`**。
- 实测 shipped 代码里可启动：**`certutil.exe`、`fsutil.exe`、`powershell.exe`**。
- **越权：`powershell.exe`（FINDING）**，逐条：

| 位置 | 场景 |
| --- | --- |
| `install.ps1:163` | `& powershell.exe ... thunderbackup.ps1 -Cmd doctor -Config $cfgDst -SkipProbes`（装完自举一次体检） |
| `smoke_test.ps1:62 / :169 / :425 / :443 / :450 / :459` | 开发自检以子进程反复驱动 `install.ps1` / `thunderbackup.ps1` / `uninstall.ps1` |

- **白名单工具的动词实测**（新动词=新能力，必须用眼睛看）：

```
certutil.exe -hashfile            @ lib\tb-commands.ps1:239
certutil.exe -hashfile            @ lib\tb-doctor.ps1:78
fsutil.exe file queryallocranges  @ lib\win32io.ps1:396
fsutil.exe hardlink list          @ lib\tbsm-store.ps1:1890
fsutil.exe hardlink list          @ smoke_test.ps1:411
fsutil.exe usn queryjournal       @ lib\win32io.ps1:825
fsutil.exe hardlink create        @ smoke_test.ps1:410   <-- 越权动词 FINDING
```

`allowlisted tool driven off its allowlisted verb : 1` —— 即 `hardlink create`。它是**写操作**，
不在"实测到的既有动词集合"里，所以判红（只动 `%TEMP%`，但仍由人来表态）。
另外有一条"URL 与白名单工具同行"规则：注入 `& certutil.exe -URLX http://127.0.0.1:1/...` 时被抓（`[S7]` C3）。

- **`indirect-launch`（`& $变量`，无可执行文件名）逐条列出**：`lib\find-thunder-paths.ps1:162/163/168/170/176/179/183/196/213/215`、
  `lib\tb-commands.ps1:80`、`lib\tb-core.ps1:328`、`lib\tbsm-store.ps1:1673`。
  这些都是把脚本块/收集函数当变量调用，**不是外部程序**；但审计不替人判断，所以全列出来让人过眼。
  （注意：`lib\tbsm-store.ps1:192/366/367/478`、`lib\win32io.ps1:711/732` 之类是**内嵌 C# 里的 `&&`**，
  现在被 `&` 词边界修复识别为启动点行了——它们不是 exe，所以落到 `indirect-launch`，这是修复后的真实副作用。）

## 4. `[S3]` 原生面（实测 50 条 `[DllImport]`）

声明涉及的模块只有三个，全部 Windows 自带：
`kernel32.dll`（43 条）、`advapi32.dll`（3 条）、`rstrtmgr.dll`（4 条）。
`advapi32` 那三条是同一件事：`OpenProcessToken` @ `lib\tbsm-store.ps1:684`、
`LookupPrivilegeValueW` @ `:689`、`AdjustTokenPrivileges` @ `:691`（给自己开令牌、启一个特权；
这就是 `doctor` 需要管理员的那一条）。`rstrtmgr`（Restart Manager）@ `lib\win32io.ps1:631/633/635/638`
用来查"谁占着这个文件"。
远程线程/注入类规则（`CreateRemoteThread`、`VirtualAllocEx`、`WriteProcessMemory`、`SetWindowsHookEx`、
`NtProtectVirtualMemory`）实测 **0 命中**。

## 5. `[S4]` 出网/机器指纹硬规则

**`0 -> 0 matches`**（shipped 运行代码）。这条 0 有意义，因为 `[S7]` 证明同一套规则能看见注入进去的 5 类缺陷。

## 6. `[S5]` 产物级编码门（不是"能解析"就算过）

- **19 / 19 个 `.ps1` 都带 UTF-8 BOM** ✓。断言的是**字节**，不是解析成功：
  在非 UTF-8 ACP 的机器上，没有 BOM 的 `.ps1` 会按 ANSI 解码，所有用非 ASCII 构造的守卫串会静默失配 →
  **审计在恰好没被测过的机器上失效（fail open）**。所以这条必须在产物级别断言。
- 行尾：**11 个文件含裸 LF**（包约定是 CRLF），逐条：`build-check.ps1`=34、`lib\find-thunder-paths.ps1`=262、
  `lib\tb-commands.ps1`=480、`lib\tb-package.ps1`=74、`lib\tbsm-commit.ps1`=503、`lib\tbsm-restore.ps1`=340、
  `lib\tbsm-selfcheck.ps1`=113、`lib\win32io.ps1`=844、`smoke_test.ps1`=8、`thunderbackup.config.ps1`=201、
  `tools\add-bom.ps1`=57。这是"两把复制在跑的拷贝"的迹象类，报告但不算 fail-open。

## 7. `[S6]` 版本来源（负责人点名要的实测数据）

- **`dist\lib\criteria.ps1` = 74,207 B，SHA256 =
  `62E2FB77833E14E2747DA5FE87F8EC1BE102A3DB681D75444C73F5A72FDD5757`**，跟踪符号 **5/5**
  （`E_HARDLINK`、`G4_NA_TINY`、`G4_NA_REPARSE`、`HARDLINK_STATE_UNKNOWN`、`Get-XldVolumeCapability`）。
- `dist\lib\win32io.ps1` = 46,861 B，符号 **2/2**（`Get-FileHolder`、`Get-FileId`）。
- 对比（本次 50 对，节选关键几条）：

| 对比对象 | 结果 |
| --- | --- |
| `work\02-design\criteria.ps1` = **78,457 B** | **delta = +4,250：设计副本比 dist 新**（同伴正在改） |
| `work\04-tests\verify\pinned\criteria.ps1` = 74,207 B | delta = 0（钉住的测试夹具与 dist 一致） |
| `work\03-src\cli\tests\sandbox\distcopy\lib\criteria.ps1` = 69,349 B | delta = −4,858（沙箱旧拷贝） |
| `work\lib\win32io.ps1` = 46,861 B | delta = 0 |
| 结论行 | `no shipped copy is missing a tracked symbol` |

也就是说：**dist 里没有"少了关键符号"的旧拷贝，但 dist 的 `criteria.ps1` 落后 `02-design` 4,250 B**。
负责人要的"发布前是否要把 dist 重建到最新"这个问题，数据在这里。

## 8. `[S8]` 产物卫生

`examined 20 file(s) inside the artifact tree`；
`no _patch*/_probe* helpers, no scratch\, no tests\, no sandbox\, no backup residue`；
`no duplicate .ps1 basenames inside the artifact`。
判断类一条：`tools\add-bom.ps1`（3,081 B）是开发期辅助脚本，**不匹配任何 scratch 规则**，
但它是"随包分发构建工具"——要不要留在 dist 由负责人决定，我不擅自加规则。

## 9. `[F]` 夹具与"跑的就是这份字节"的证明

```
work root   : C:\Users\example\AppData\Local\Temp\tb-telemetry-audit-20261022-234248
stubbed copy: ...\pkg-stub
watched tree: ...\watch  (765952 合成字节，mtime 回拨 10 分钟)
store       : ...\store
copy vs shipped by SHA256: lib\find-thunder-paths.ps1 : differs from shipped (intended: only this file)
```

那行"only this file"是**逐文件 SHA256 比对**的结果：副本里除了被故意替换成空返回的
`lib\find-thunder-paths.ps1`（避免枚举操作者真实下载树），**其余每个文件与 dist 里的字节完全一致**。
所以动态测量执行的代码 = 发布的代码。合成树 765,952 B，`-Cmd once` 真的拷贝了这些字节
（`bytesCopied=765952`），不是空跑。

**披露**：动态负载是**在打断路径发现的临时副本里**跑的；只有 `-Cmd doctor -SkipProbes` 这一次
直接跑 dist 里未修改的 `thunderbackup.ps1`（按设计它仍会做一次迅雷路径发现，只是不拷贝任何东西）。

## 10. `[P]` 正向对照 —— 仪器是不是活的

```
detector alive: saw 3 connection(s) on the positive control
detector mode=Get-NetTCPConnection: saw 3 TCP row(s) attributed to the control child,
  2 of them pointed at 127.0.0.1:11040; the listener accepted 1 connection(s);
  detector errors 0/11 cycles; median cycle 1986 ms
control row: 53208 (root pid) 127.0.0.1:11042 -> 127.0.0.1:11040 FinWait2
control row: 53208 (root pid) 127.0.0.1:11042 -> 127.0.0.1:11040 Established
control row: 53208 (root pid) 0.0.0.0:11042 -> 0.0.0.0:0 Bound
control modules pid=53208 measured 60 module(s) ws2_32=True inet=False http=False
```

对照只走 127.0.0.1，**没有也不需要联网**。它为 0 就说明仪器瞎了 → 退出码 5、禁止发布结论（本项实测 3）。

## 11. `[D0]` 空闲对照 —— 0 的基线是不是真的 0

```
idle control pid=9224 over 15 cycles (33705 ms): 0 TCP row(s), 0 UDP row(s)
idle modules pid=9224 measured 60 module(s) ws2_32=True inet=False http=False
```

一个只 `Start-Sleep` 的 `powershell.exe`，用**同一条轮询循环**测，0 行 ✓。
也就是说：后面每个"0 行"都不是仪器默认输出，而是与一个活的空闲同类进程同量级的读数。

## 12. `[D]` 六次真实负载

| 负载 | 子进程退出码 | wall | cycles | 中位/最差周期 | 归属 TCP | 归属 UDP | 新子进程 | 模块清单 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `once` | 0 | 32,065 ms | 15 | 1,810 / 2,683 ms | **0** | 0 | none | pid 14900：60 模块，`ws2_32=True`，`wininet=False`，`winhttp=False` |
| `status` | 0 | 26,297 ms | 12 | 1,890 / 2,948 ms | **0** | 0 | none | pid 32436：60 模块，同上 |
| `verify` | 0 | 23,037 ms | 13 | 1,522 / 2,655 ms | **0** | 0 | none | pid 62024：60 模块，同上 |
| `doctor -SkipProbes` | 0 | 33,996 ms | 14 | 2,170 / 3,151 ms | **0** | 0 | none | pid 40260：60 模块，同上 |
| `doctor`（带探针） | 0 | 38,285 ms | 15 | 2,147 / 3,451 ms | **0** | 0 | **`csc.exe(59892)` d=1** | pid 64608 已测；**pid 59892 NOT MEASURED** |
| 未修改 dist 的 `doctor -SkipProbes` | 0 | 33,187 ms | 14 | 2,188 / 3,082 ms | **0** | 0 | none | pid 22596：60 模块 |

`once` 真的干活：`scanned=6 committed=5 deduped=1 bytesCopied=765952`（stdout 725 字符，stderr 0）。
`status`：`tracked files=6 referenced blobs=5 blob bytes=0.5 MB`。`verify`：`6 head(s) checked, 0 corrupt, 0 missing`。
六个窗口的"其它进程新增 TCP 行"分别是 379 / 363 / 371 / 382 / 393 / 374（合计 2,262），**没有一条被算到包头上**。

**模块腿的真实结论**：`measured 6, NOT measured 2`。
`ws2_32.dll loaded in pids : 14900,32436,62024,40260,64608,22596` —— **6 个被审计进程全都加载了 WinSock**；
`wininet.dll : none`、`winhttp.dll : none`。
> `ws2_32.dll` 被加载 **不等于** 建立了连接：PowerShell 自己就加载它。这条数据只用来排除
> "根本没测"这种解读，不用来做零遥测证据。
> 两个 NOT MEASURED 的原文原因：`Get-Process -Module threw ProcessCommandException: Cannot find a process
> with the process identifier 59892.` —— 那是 `csc.exe`，跑完就退，模块清单读不到；
> **报告成"没测到"，不报告成 0**。

## 13. `[S7]` 静态反向对照（负责人要求的"注入必须被抓"）

注入 8 行到 `lib\tb-package.ps1` 的临时副本，重扫 19 个 `.ps1`：副本里 **11 条** shipped 命中 vs 真树 **4 条**。
注入集覆盖 **5 类**（不止三类）：

```
CAUGHT  C1 direct outbound API :: pattern <Invoke-WebRequest> at lib\tb-package.ps1:76
CAUGHT  C2 host-abuse binary :: exe <rundll32.exe>  at lib\tb-package.ps1 : 77
CAUGHT  C2 host-abuse binary :: exe <mshta.exe>     at lib\tb-package.ps1 : 78
CAUGHT  C2 host-abuse binary :: exe <regsvr32.exe>  at lib\tb-package.ps1 : 79
CAUGHT  C3 allowlisted tool driven off its allowlisted verb :: toolabuse <certutil.exe -URLX> at lib\tb-package.ps1:80
CAUGHT  C4 DNS side channel :: pattern <Resolve-DnsName>  at lib\tb-package.ps1:81
CAUGHT  C4 DNS side channel :: pattern <System\.Net.Dns>  at lib\tb-package.ps1:82
CAUGHT  C5 raw socket without any HTTP stack :: pattern <Net\.Sockets> at lib\tb-package.ps1:83
NEGATIVE  real tree reports 0 of the injected API patterns (0 expected) ;
          tool-verb abuse newly introduced by the injection: certutil.exe -URLX (exactly certutil.exe -URLX expected)
NEGATIVE  exes newly introduced by the injection: mshta.exe, regsvr32.exe, rundll32.exe | unexpected extras: none
PRE-EXISTING in the real artifact (reported as findings of its own, not caused here):
          off-allowlist exes = powershell.exe ; tool-verb abuse = fsutil.exe hardlink create@smoke_test.ps1:410
VERDICT   5 classes injected, 5 fully caught ; the static instrument has eyes in every direction it claims to cover
```

反向对照的另一半同样重要：**真树 0 误报**（注入的 API 模式在真树里 0 命中，新引入的动词越权恰好只有注入那一条）。

## 14. `[D5]` 动态反向对照（复用红队的 must-catch 结构，没有另写一套）

`work\04-tests\redteam\experiments\telemetry-mustcatch.ps1` 是本腿的基线（它当时 MUST-CATCH=PASS）；
本审计把它做成四段断言，任何一段不成立就退出 5 并禁止发布结论。本次实测：

```
BASELINE  port 127.0.0.1:11242 由内核为对照监听器选出：看到 1 行，其中 1 行是本 harness 自己的监听器，
          外来预存行 0（期望 0）
INJECT    Invoke-WebRequest -> http://127.0.0.1:11242/audit-injection   写入 injected\lib\tb-package.ps1
STATIC    扫描器点名了这条注入：lib\tb-package.ps1:77 <Invoke-WebRequest>
DYNAMIC   14 个采样周期 / 26,875 ms 内向被注入子进程树归属 3 条 TCP 行（中位 1,660 ms，最差 2,750 ms）；
          其中 2 条在端口 11242 上  首行：pid=13668 127.0.0.1:11256 -> 127.0.0.1:11242 ...
HOLDER    归属 pid 解析成功：13668=powershell.exe [root of the audited tree = the injected child] ; unresolved=0
TEARDOWN  监听器关闭后端口 11242 上残留行：0（期望 0 —— 只会累加的仪器不能报"没有"）
UDP LEG   instrument=Get-NetUDPEndpoint ; 归属到审计树的已绑 UDP 端点=0 ;
          netstat -ano 兜底实测：表内 145 个 UDP 端点，0 个属于被审计 pid   （一次性 sendto() 不留行：见限制）
DNS LEG   实测 before / after：缓存条目 649 -> 718 ;
          命中 thunder|xltd|xunlei|backup|telemetry|audit 的名字：jsq.xunlei.com, rcv-downloadlib-hub.xunlei.com,
          tpstelemetry.tencent.com, sl-canary-m.xunlei.com, conf-m-ssl.xunlei.com, rcv-xldc.xunlei.com, api-pan.xunlei.com
          （系统级缓存，无法按 pid 归属：只是一个佐证证人）
VERDICT   MUST-CATCH=PASS: this detector saw a real outbound call made by product code, attributed it, and let it go
child exit=0  listener on 127.0.0.1:11242  accepted=1  attributed TCP rows=3  on the injected port=2  cycles=14
```

**DNS 腿必须怎么读**：这台机器上装着真的迅雷，`649 → 718` 与那一串 `*.xunlei.com` /
`tpstelemetry.tencent.com` 是**整机缓存**里的东西，跨进程、跨时间，**不能归因于被审计的包**，
也**不能反过来当作"包在发遥测"的证据**。审计能说的只有：在被审计进程树的窗口内没有连接行，
而这一腿的作用是"如果包真的解析了这些域名，这里的名字数量/内容会变化，并且它可测"。
这条腿的价值是仪器性（649→718 证明它读到了真数据），不是无罪证明。

## 15. 退出码语义与本次判定

| 码 | 含义 | 本次 |
| --- | --- | --- |
| `0` | 干净 + 所有对照都活着 | ✗ |
| `4` | 发现非环回出网连接 | ✗（0 条） |
| `5` | 仪器没通过自己的对照 / 某腿未测 / 探测器不可用 | ✗（`legs that never ran : none -- every leg executed`；正向对照 3 行；静态 5/5；动态 PASS） |
| `6` | 子命令报错 **或** 静态 FINDING | ✓ **6**（子命令全部退出 0，所以是静态 FINDING 触发的） |

判序 `5 > 4 > 6 > 0`。`-StaticOnly` 无论静态多干净都退出 5，因为动态腿与正向对照根本没跑。
JSON 里的 `MayPublishZeroTelemetryClaim=false` 与此一致。

**结论性表格（审计自己的 VERDICT 节，原样）**

```
runs measured                            : 6
total poll cycles                        : 83   median cycle 2018 ms   max cycle 3451 ms
TCP rows attributed to audited tree      : 0   (idle control: 0)
non-loopback among them                  : 0
UDP rows attributed to audited tree      : 0   (idle control: 0)
unattributed NEW tcp rows in all windows : 2262   (other processes; not blamed on the tool)
positive control                         : ALIVE -- saw 3 connection(s) on the positive control, 127.0.0.1:11040
external child processes captured        : csc.exe
module lists                             : measured 6, NOT measured 2
child command errors                     : none
static: network findings in shipped code : 0 over 19 .ps1 files
static: injection findings in shipped    : 4
static: off-allowlist executables        : powershell.exe
static must-catch                        : CAUGHT all 5 injected defect classes, 0 false positives on the real tree
artifact encoding gate                   : BOM present on all 19 .ps1; 11 file(s) also contain bare-LF line endings
artifact hygiene                         : 0 scratch finding(s), 0 duplicate-basename finding(s)
legs that never ran (NOT MEASURED)       : none -- every leg executed
dynamic reverse control                  : CAUGHT: 3 attributed TCP row(s), 2 on the injected port, plus the static match at lib\tb-package.ps1:77 <Invoke-WebRequest>
version provenance                       : no shipped copy missing a tracked symbol
outbound/fingerprint in shipped code     : 0
MAY PUBLISH A ZERO-TELEMETRY CLAIM       : NO -- see the exit code and the NOT-MEASURED rows above
EXIT CODE                                : 6
```

---

## 16. 被测包这次暴露 / 消除的缺陷

| 编号 | 状态 | 实测证据 |
| --- | --- | --- |
| **F-01** `-Cmd once` 每个文件抛 `GATE-THREW ... null-valued expression`（`tb-core.ps1:699`，`New-TbGate` 返回的裸脚本块看不见工厂局部 `$State`），导致 `committed=0` | **本次已不复现** | `once`：`scanned=6 committed=5 deduped=1 gate-errors=0 bytesCopied=765952`，blob 拷贝与哈希路径这次**真的被动态执行过** |
| **F-02** 零头存储上 `-Cmd verify` 报 `REFUSED: Cannot bind argument to parameter 'Hex' ...`（`thunderbackup.ps1:113`）退出 1 | **本次已不复现** | `verify` 退出 **0**，`6 head(s) checked, 0 corrupt, 0 missing`，`fsck {"Heads":6,"Ok":6}` |
| **F-03** `-Cmd status` 的"上一次运行"全是空值 | **实测仍在** | 同一个存储里 `once` 明确报了 `scanned=6 committed=5`，而 `status` 打印 `last run : scanned= committed= deduped= wait= skipped= unchanged= bytesCopied=`；同一行还报 `runs=1 state entries=6`。计数被存下但没被读出，属于"看起来像没跑过"的静默失败 |
| **F-04** `doctor [1]` 的空值尾串 | **实测仍在** | `Get-FileHole live reading: returned but NOT-USABLE:`（冒号后为空）—— 状态被打印但**原因缺失**；同一行 `capability level=1`、`degraded criteria: C6.expect` 是有值的，所以不是整节失败，只是这一条不给原因 |
| **F-05** `fsutil hardlink create @ smoke_test.ps1:410` | **实测（由本审计的新动词规则发现）** | 越权动词 FINDING；本地、临时目录内，但属于白名单工具上的新能力，需负责人表态 |
| **F-06** `powershell.exe` 越白名单 | **实测** | `install.ps1:163` + `smoke_test.ps1` 六处；不产生网络行为，但违反既定清单，所以判红而不是悄悄放行 |

## 17. 审计仪器自己的缺陷 —— 为什么现在这份结论才配有"实测"两个字

红队判定我原来的审计是**盲的**（`MISSED rundll32.exe`）。我自己写的反向对照独立复现了这个盲区
（C2/C3 都漏），并定位到根因，逐条修掉、每修一条都用注入复测：

| 缺陷 | 根因（实测出来的） | 现在怎么证明修好了 |
| --- | --- | --- |
| **A-1 `& rundll32.exe` 被判成 `mention`，可执行文件清单里根本没有它** | PS 5.1 里 `&` 后跟空格，**`\b` 在 `&` 之后不可能成立**（`&` 是非词字符、后面也是非词字符），所以以 `(&|Start-Process|...)\b` 收尾的正则**永远匹配不到 `& xxx.exe`**。这是白名单检查漏掉所有"借宿主"二进制的真正原因 | `[S7]` C2 三条（rundll32/mshta/regsvr32）全部 CAUGHT；`NEGATIVE exes newly introduced: mshta.exe, regsvr32.exe, rundll32.exe` |
| **A-2 期望串与规则库字节不一致** | 对照要求 `System\.Net\.Dns`，而库里的条目是 `('System\.Net.' + 'Dns')` → 同一条规则被误报为 MISSED（"仪器没错，对照错了"） | C4 两条现在都 CAUGHT |
| **A-3 `certutil -is` 幻影 FINDING** | 动词正则向前扫，抓到句子里 PowerShell 运算符 `-is`，把散文当成调用 | 动词表只列出 7 条真调用；`certutil -hashfile ×2 / fsutil ×5`，散文 0 条 |
| **A-4 整轮运行在正向对照里崩掉（退出码 1，不在契约内）** | `[int] + '字符串'` 在 PS 5.1 里会把右边解析成数字：`$_.Pid + ' ' + ...` 这类"整数在最左"的行打印器；同类还有 `@($txt).Count + ' lines...'` | 所有行打印器改成以 `'' +` 起头；本次退出码严格落在 `0/4/5/6` 契约内 |
| **A-5 UDP 腿静默不跑** | 调用点写的是 `-UdpMode $detector.UdpMode`，而字段名是 `Udp` → 传进 `$null`，`instrument=` 打空。这正是"前序门失败让后序门静默跳过"的实现版本 | `[D5]` 现在打印 `instrument=Get-NetUDPEndpoint`，并且 `$ok` 显式要求仪器非空、`netstat -ano` 与 DNS 两条都是 `measured` |
| **A-6 DNS 腿假 0** | `ipconfig /displaydns` 的标签随系统显示语言变化，本机是 zh-CN，`Entry Name` 正则**一条都不命中** → 报成"0 条缓存"，看着像"什么都没解析" | 主仪器换成与语言无关的 `Get-DnsClientCache`，`ipconfig` 文本只作为行数交叉核对与降级备胎；实测 `649 → 718` 条目、`ipconfig text = 5260 lines` |
| **A-7 逗号比 `+` 结合更紧造成幽灵条目** | `@('Get-NetUDP' + 'EndConnection', ...)` 会变成一个元素被并掉、另一条变成两个假名字，探测输出同时出现 `Get-NetUDP=ABSENT` 和 `EndConnection=ABSENT` | 目录与探测列表全部加括号，规则库自带 82 行自检；本机现在只报 `Get-NetUDPEndConnection=ABSENT`（真不存在的名字） |

另外两条自指披露：**审计工具自己的 `.ps1` 会被自己的规则扫到**（非 shipped 命中 35 条，
含 `TcpListener`/`TcpClient` 与规则库里的碎片字符串），以及**规则库里的模式字符串被拆开书写**
（`('Invoke-' + 'W' + 'ebRequest')`、`('Remove-Item\s+.*' + 'HK')` 等），
因为发布门 `build-check.ps1` 是逐行 `-match` 扫 dist 里**每一个** `.ps1` 的字面量的——
审计工具自己包含完整字面量会让发布门失败。这不是钻空子：规则库的语义在 `[S7]` 里被注入实证明明覆盖到了。

## 18. 这套实验**不能**证明什么

1. **不能证明标准用户身份下可用/无遥测。** 本机造不出非管理员路径：红队实测
   `runas /trustlevel:0x20000` 起的子进程仍是 High Mandatory Level。
   标准用户可运行性是 **【待验】**，不是"已验证"。本次运行身份 `administrator=True`。
2. **不能证明"没有 UDP 出网"。** UDP 仪器列的是**已绑定**端点；一次性 `sendto()`（DNS 查询、QUIC 包）
   **不留任何行**。`netstat -ano` 兜底实测 145 个端点、0 个属于被审计 pid，这只说明快照里没有，
   不等于没有发过。
3. **不能证明 ICMP / raw socket 没有。** 探测器读的是内核连接表的 TCP/UDP 行。
4. **有真实盲区窗口：标称 200 ms，实测中位周期 2018 ms、最差 3451 ms**
   （`Get-NetTCPConnection` 首次调用就要 1788 ms）。**在两个相邻采样之间打开又关闭的连接，这台机器上测不出来。**
5. **短命孙进程归属不到。** 进程树每 3 个周期走一次；两次遍历之间起落的孙进程不会被归属
   （本次确实抓到过 `certutil.exe`/`csc.exe` 这样的子进程，但它们的模块清单已读不到，报 NOT MEASURED）。
   每个窗口的"未归属新增行"计数（379/363/371/382/393/374）是这条的安全网，公开报告而不是隐藏。
6. **不能证明包在真实迅雷数据上无遥测。** 动态负载跑在打断路径发现的临时副本 + 765,952 B 合成树；
   真实下载目录没有被枚举、没有被拷贝（这是刻意的，避免动 `D:\Thunder` / `C:\迅雷下载`）。
   `install.ps1` 的计划任务注册路径（`Register-ScheduledTask`）**没有被动态执行过**，只有静态命中。
7. **不能证明"这台机器没有遥测"。** DNS 缓存里的 `*.xunlei.com` / `tpstelemetry.tencent.com`
   属于整机；整机在测量期间还有 2,262 条其它进程的新 TCP 行。本审计的主张范围只是"被审计进程树在这些窗口内没有连接行"。
8. **只测了这份字节、这台机器、这一次时间。** `dist\lib\criteria.ps1` 已落后 `02-design` 4,250 B；
   包重建后本文件的每一条行号都要重核。
9. **`ws2_32.dll` 被加载不是连接证据**（PowerShell 本身加载它）；`wininet/winhttp = none` 也只是
   "没加载这两个栈"，不等于没有 socket。
10. **干净的网络结论不代表备份功能正确**。功能侧证据在上面的 `committed=5` / `0 corrupt` / `runs=1`，
    以及 F-03、F-04 这些不好看但仍然列出来的读数。

## 19. 原始输出（同一次运行，逐字节选自审计自己的 stdout）

完整输出 2,435 行：人类可读部分（1–477 行）之后是 `--- BEGIN JSON --- ... --- END JSON ---`
（`ConvertTo-Json -Depth 9`，含每一条 finding、每一个窗口、每一行模块清单）。本次保留在：
`C:\Users\example\AppData\Local\Temp\aud-final-utf8.txt`（UTF-8 副本）
与夹具工作根 `C:\Users\example\AppData\Local\Temp\tb-telemetry-audit-20261022-234248`
（`-KeepWorkRoot`，含 `pkg-stub` / `watch` / `store` / `injected` / `static-control`）。

```text
=======================================================================
 ThunderBackup telemetry audit -- measurement, not promise
=======================================================================
  started        : 2026-10-22 23:42:56   harness pid=6412
  package root   : D:\Example\thunder-work\work\dist
  powershell     : 5.1.19041.7725 Desktop  language-mode=FullLanguage  64bit-process=True
  os / runtime   : Microsoft Windows 10 专业版 build 19045   .NET4x release key=533325
  device guard   : code-integrity-enforcement=0 user-mode=0
  running as     : EXAMPLE-BOX\example   administrator=True   (nothing in this harness needs elevation; the package does, in one probe, see LIMITATIONS)
  detector       : Get-NetTCPConnection  (probe ok, first call 1788 ms)
  udp instrument : Get-NetUDPEndpoint   tree walk: Win32_Process via Get-CimInstance
  instrument probe: Resolve-DnsName=present  Get-DnsClientCache=present  ipconfig.exe=present  Get-NetUDPEndpoint=present  Get-NetUDPEndConnection=ABSENT  netstat.exe=present
  poll budget    : -PollMs 200 ms nominal, grace 8 cycles, max 240 s per run
  name shadowing : 29 invented function names checked against Get-Alias + cmdlets: 0 collisions

--- [S] STATIC PASS
  .ps1 files scanned : 19  (every .ps1 under the package root, via Get-ChildItem -Recurse; nothing hardcoded)
  patterns           : 82
  NETWORK matches in shipped runtime code : 0  -> 0 matches
  INJECTION / PERSISTENCE matches in shipped runtime code : 4  <-- FINDINGS
      FINDING install.ps1:140 <Register-ScheduledTask>  ||  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
      FINDING install.ps1:145 <Register-ScheduledTask>  ||  Write-Output ('  *** Register-ScheduledTask FAILED: ' + $_.Exception.Message.Split("`n")[0])
      FINDING uninstall.ps1:143 <Register-ScheduledTask>  ||  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
      FINDING uninstall.ps1:147 <schtasks>  ||  Write-Output ('      Remove it by hand: schtasks /Delete /TN "' + $TaskName + '" /F   (needs the same account or elevation)')
  informational local-surface hits (registry reads, DllImport declarations) : 77   comment-only hits: 43
  files unreadable: 0   files not attributable to the package root: 0

--- [S2] EXTERNAL EXECUTABLES THE CODE CAN LAUNCH (for the allowlist, checked by eye)
  expected allowlist               : fsutil.exe, certutil.exe
  launched in shipped runtime code : certutil.exe, fsutil.exe, powershell.exe
  off the allowlist                : powershell.exe   <-- FINDING, must be explained or removed
  verbs used on the allowlisted tools (a new verb here is a new capability; eyeball it):
      certutil.exe -hashfile @ lib\tb-commands.ps1:239
      certutil.exe -hashfile @ lib\tb-doctor.ps1:78
      fsutil.exe file queryallocranges @ lib\win32io.ps1:396
      fsutil.exe hardlink create @ smoke_test.ps1:410
      fsutil.exe hardlink list @ lib\tbsm-store.ps1:1890
      fsutil.exe hardlink list @ smoke_test.ps1:411
      fsutil.exe usn queryjournal @ lib\win32io.ps1:825
  allowlisted tool driven off its allowlisted verb : 1  <-- FINDING
      ABUSE smoke_test.ps1:410  fsutil.exe hardlink create  (fsutil is allowlisted only for file queryallocranges / usn queryjournal / hardlink list -- the verbs the shipped code was measured using)

--- [S3] NATIVE SURFACE: every DllImport declaration actually present
  DLLs declared : advapi32.dll, kernel32.dll, rstrtmgr.dll
      advapi32.dll  AdjustTokenPrivileges   @ lib\tbsm-store.ps1:691 [shipped-runtime]
      advapi32.dll  LookupPrivilegeValueW   @ lib\tbsm-store.ps1:689 [shipped-runtime]
      advapi32.dll  OpenProcessToken   @ lib\tbsm-store.ps1:684 [shipped-runtime]
      kernel32.dll  CloseHandle   @ lib\criteria.ps1:181 [shipped-runtime]
      rstrtmgr.dll  RmEndSession   @ lib\win32io.ps1:633 [shipped-runtime]
      rstrtmgr.dll  RmGetList   @ lib\win32io.ps1:638 [shipped-runtime]
      rstrtmgr.dll  RmRegisterResources   @ lib\win32io.ps1:635 [shipped-runtime]
      rstrtmgr.dll  RmStartSession   @ lib\win32io.ps1:631 [shipped-runtime]

--- [S4] OUTBOUND / FINGERPRINT findings in shipped runtime code (the hard rule)
      0 -> 0 matches

--- [S5] ARTIFACT ENCODING GATE (asserted on the bytes, not on a successful parse)
      BOM present on 19 / 19 .ps1   CRLF-clean: 11 file(s) with bare LF

--- [S7] STATIC REVERSE CONTROL (inject three defects; the scanner must catch all three)
      injected 8 line(s) into ...\static-control\broken\lib\tb-package.ps1 -- 19 .ps1 rescanned, 11 shipped findings there vs 4 in the real tree
      CAUGHT  C1 direct outbound API :: pattern <Invoke-WebRequest> at lib\tb-package.ps1:76
      CAUGHT  C2 host-abuse binary (legitimate Windows host, unpermitted behaviour) :: exe <rundll32.exe> at lib\tb-package.ps1 : 77
      CAUGHT  C2 host-abuse binary (legitimate Windows host, unpermitted behaviour) :: exe <mshta.exe> at lib\tb-package.ps1 : 78
      CAUGHT  C2 host-abuse binary (legitimate Windows host, unpermitted behaviour) :: exe <regsvr32.exe> at lib\tb-package.ps1 : 79
      CAUGHT  C3 allowlisted tool driven off its allowlisted verb :: toolabuse <certutil.exe -URLX> at lib\tb-package.ps1:80
      CAUGHT  C4 DNS side channel (no TCP row, only the static rule can see it) :: pattern <Resolve-DnsName> at lib\tb-package.ps1:81
      CAUGHT  C4 DNS side channel (no TCP row, only the static rule can see it) :: pattern <System\.Net.Dns> at lib\tb-package.ps1:82
      CAUGHT  C5 raw socket without any HTTP stack :: pattern <Net\.Sockets> at lib\tb-package.ps1:83
      VERDICT   5 classes injected, 5 fully caught ; the static instrument has eyes in every direction it claims to cover

--- [S8] ARTIFACT HYGIENE: developer scratch code must not ship inside the package
      examined 20 file(s) inside the artifact tree
      no _patch*/_probe* helpers, no scratch\, no tests\, no sandbox\, no backup residue
      no duplicate .ps1 basenames inside the artifact

--- [P] POSITIVE CONTROL (127.0.0.1 only: no internet is contacted, by design or by accident)
  detector alive: saw 3 connection(s) on the positive control
  detector mode=Get-NetTCPConnection: saw 3 TCP row(s) attributed to the control child, 2 of them pointed at 127.0.0.1:11040; the listener accepted 1 connection(s); detector errors 0/11 cycles; median cycle 1986 ms

--- [D0] IDLE CONTROL: a bare powershell.exe doing nothing, measured by the same loop
  idle control pid=9224 over 15 cycles (33705 ms): 0 TCP row(s), 0 UDP row(s)

--- [D] run: once   exit=0   wall=32065 ms   cycles=15   median-cycle=1810 ms   max-cycle=2683 ms
      work done  : scanned=6 committed=5   stdout=725 chars  stderr=0 chars
      attributed : TCP 0 row(s), UDP 0 row(s)   [detector errors 0/15]
      unattributed NEW tcp rows during this window (other processes, NOT blamed on the tool): 379
      modules pid=14900 [once] count=60  ws2_32.dll=True  wininet.dll=False  winhttp.dll=False

--- [D] run: doctor-WITH-probes   exit=0   wall=38285 ms   cycles=15   median-cycle=2147 ms   max-cycle=3451 ms
      attributed : TCP 0 row(s), UDP 0 row(s)   [detector errors 0/15]
      new descendants captured: csc.exe(59892) d=1
      modules pid=59892 [doctor-WITH-probes] NOT MEASURED -- Get-Process -Module threw ProcessCommandException: Cannot find a process with the process identifier 59892.   (this is not a zero: the list could not be read)

--- [D5] DYNAMIC REVERSE CONTROL: product code that really does phone home must be caught
      BASELINE  port 127.0.0.1:11242 selected by the kernel for the control listener: 1 row(s) seen, 1 of them this harness's own listener, 0 foreign pre-existing row(s) (0 expected)
      INJECT    Invoke-WebRequest -> http://127.0.0.1:11242/audit-injection   written into injected\lib\tb-package.ps1
      STATIC    the scanner names the injected call: lib\tb-package.ps1:77 <Invoke-WebRequest>
      DYNAMIC   attributed 3 TCP row(s) to the injected child tree over 14 cycles / 26875 ms (median cycle 1660 ms, worst 2750 ms); 2 of them on port 11242  first: pid=13668 127.0.0.1:11256 -> 127.0.0.1:11242
      HOLDER    owning pid(s) resolved: 13668=powershell.exe [root of the audited tree = the injected child] ; unresolved=0
      TEARDOWN  rows still on port 11242 after the listener was closed: 0 (0 expected -- a detector that only ever accumulates cannot report absence)
      UDP LEG   instrument=Get-NetUDPEndpoint ; attributed bound UDP endpoints=0 ; measured snapshot via netstat -ano: 145 UDP endpoint(s) in the netstat table, 0 owned by an audited pid   (a one-shot sendto() still leaves no row: see LIMITATIONS)
      DNS LEG   measured before / measured after: cache entries 649 -> 718 ; names matching thunder|xltd|xunlei|backup|telemetry|audit: jsq.xunlei.com, rcv-downloadlib-hub.xunlei.com, tpstelemetry.tencent.com, sl-canary-m.xunlei.com, conf-m-ssl.xunlei.com, rcv-xldc.xunlei.com, api-pan.xunlei.com
      VERDICT   MUST-CATCH=PASS: this detector saw a real outbound call made by product code, attributed it, and let it go
      child exit=0  listener on 127.0.0.1:11242  accepted=1  attributed TCP rows=3  of them on the injected port=2  cycles=14

  MAY PUBLISH A ZERO-TELEMETRY CLAIM       : NO -- see the exit code and the NOT-MEASURED rows above
  EXIT CODE                                : 6
```

---

## 20. 包清单（本次审计测量到的字节；SHA256 前 24 位）

| 文件 | 字节 | mtime | SHA256（前 24） |
| --- | --- | --- | --- |
| `build-check.ps1` | 42,301 | 10-22 22:54:59 | `751D7591075DF396500C8F27` |
| `install.ps1` | 10,235 | 10-22 22:34:58 | `44EB3CB11DD9E3DA983E4E1E` |
| `uninstall.ps1` | 10,734 | 10-22 22:35:45 | `BDBF41AEED52CC5BB3312F9E` |
| `thunderbackup.ps1` | 7,999 | 10-22 21:19:44 | `50620CE40089E3ECCFF4EC8B` |
| `thunderbackup.config.ps1` | 12,840 | 10-22 19:52:55 | `732E03268E80D9612CA506F1` |
| `smoke_test.ps1` | 32,557 | 10-22 22:48:55 | `5E4CD0D5A96CCAE5633F9932` |
| `lib\criteria.ps1` | **74,207** | 10-22 22:46:27 | `62E2FB77833E14E2747DA5FE`（全值见第 7 节） |
| `lib\find-thunder-paths.ps1` | 13,500 | 10-22 21:02:20 | `A1817C94B85ED64516B61E6B` |
| `lib\tb-commands.ps1` | 30,989 | 10-22 21:29:30 | `077B7C82EBE320BE472A4B37` |
| `lib\tb-core.ps1` | 50,925 | 10-22 21:08:48 | `9DB9C40C7FF47FF6976807EE` |
| `lib\tb-doctor.ps1` | 27,895 | 10-22 22:34:58 | `F33DB191614E21DD886B07E8` |
| `lib\tb-package.ps1` | 4,859 | 10-22 21:19:47 | `2CE70160FC9F01831F57A114` |
| `lib\tbsm-commit.ps1` | 27,964 | 10-22 21:08:49 | `1A084BF4CE81924B28EA3187` |
| `lib\tbsm-restore.ps1` | 19,131 | 10-22 22:49:02 | `E886509926C55DE0AEEEC035` |
| `lib\tbsm-selfcheck.ps1` | 5,696 | 10-22 19:52:56 | `657F9CD60DB867FC33E7D020` |
| `lib\tbsm-store.ps1` | 114,559 | 10-22 22:49:03 | `EF93D144C7E59E402FD07716` |
| `lib\win32io.ps1` | 46,861 | 10-22 22:55:08 | `8EABECE6ED24031AC2E2BCBA` |
| `tools\add-bom.ps1` | 3,081 | 10-22 19:52:57 | `BCC7F86EC253AC49E4868193` |
| `telemetry_audit.ps1` | 140,295 | 10-22 23:42:22 | `54656F826F22B868434F3A32`（全值 `54656F826F22B868434F3A32FDDB1C9D46E0F2A385B983A216981CBD5A96EC54`） |
| `README.md` | 44,956 | 10-22 22:43:15 | `2A57343668DF096786B00492` |
| `THIRD_PARTY_NOTICES.md` | 10,916 | 10-22 23:43:33 | `AF1C7014AA07A3C0E11512AD` |

所有包文件的 mtime 都早于运行开始（23:42:56），**没有同伴在我测量期间改包**；
`telemetry_audit.ps1` 自身 23:42:22 也早于运行，所以这份报告描述的就是当前字节。
唯一落在运行期间的是我自己刚写的 `THIRD_PARTY_NOTICES.md`（见开头披露）。

**写完这份报告之后发生的事（披露，不是掩盖）**：`README.md` 在 **23:53:09** 被同伴改动，
现在是 **47,468 B**（上表里的 44,956 B 是被审计快照的字节）。
核对过：**19 个 `.ps1` 的 mtime 全部仍早于 23:42:56，没有任何包代码在本次测量之后变动**，
所以上面所有静态/动态结论仍然对应现在发布的 `.ps1` 字节；变的只是文档。
另外 `README.md` 现在写着"如果你的副本里没有 `telemetry-audit.md`，跑一次 `telemetry_audit.ps1` 就自己生成一份"——
**这句不对**：审计工具输出到 stdout / JSON，不会生成这份 `.md`；本报告是人工从一次真实运行整理的产物，
必须随包分发。README 的所有者需要改这一句，否则用户会在缺文件时得到一个不会自愈的期望。

---

## 21. 本报告数字的权威运行（2026-10-23 00:24:53，harness 150,120 B / 规则库 88 条）

上面 §1–§19 的表格对应 2026-10-22 23:42:56 那次运行（harness 140,295 B、82 条规则）。
此后审计工具按负责人六条裁决扩了类目，并在 00:16:19 与 00:24:53 各重跑一次完整测量。
**引用本报告数字时，以本节为准；23:42 那批数字只作为当时的实测留档，不得再单独摘出。**
逐字输出可留存：aud-final-utf8.txt（2,435 行，23:42 那次）、aud-final3-utf8.txt（2,497 行，00:24 那次），均在 %TEMP%。

00:24:53 那次（退出码 6，`MAY PUBLISH A ZERO-TELEMETRY CLAIM : NO`，工作根 tb-telemetry-audit-20261023-002446）：
  - 静态：19 个 .ps1 / 88 条规则；NETWORK shipped 0；INJECTION-PERSISTENCE 4（按裁决判 DECLARED，级别不降）；
    PRIVILEGE / TOKEN-ADJUST 独立类目 11 处（lib\tbsm-store.ps1:677/684/685/690/692/696/704/713/715/717）。
  - 可执行文件：off-allowlist = powershell.exe (command-form or unexempted site) + test-only file still shipped by install.ps1；
    解释器机检 sites 9 / -File 7 / command-form 0 / unexempted 2；误红原因打在行内
    （本检查按行取范围；install.ps1:133 不是误红：任务动作的执行体是 powershell.exe，是持久化执行体，不是解释器跑自己）。
  - test-only 交叉检查（修正多转义后）：FINDING smoke_test.ps1 : classified test-only, but the installer copy rule at
    install.ps1:71 does not exclude it, so it still ships to the user。
  - 静态反向对照：7 类注入全部 CAUGHT（C1 出网 API、C2 rundll32/mshta/regsvr32、C3 certutil -URLX、C4 DNS 两条、
    C5 裸 socket、C6 外部输入进动态执行 lib\tb-package.ps1:84、C7 提权面 :85）；真树 0 误报；
    prose-only 动态执行关键字 2 处（lib\win32io.ps1:387/:394）按注释报、不按活代码报。
  - 正向对照 saw 3 connection(s)；空闲对照 pid 60488 / 15 cycles / 34,407 ms / 0 TCP 0 UDP。
  - 6 次负载子进程 exit 全 0，归属 TCP/UDP 每窗口 0，探测错误 0；84 个采样周期，中位 2,450 ms、最差 4,349 ms
    （盲区比 23:42 那次的 2,018 ms / 3,451 ms 更宽）；其它进程新增 TCP 行 2,329 条单列。
  - 模块腿 measured 6 / NOT measured 0，本次 external child processes captured: none
    （00:16 那次 measured 6 / NOT measured 1；23:42 那次 6 / 2 并抓到 csc.exe）。
  - 动态反向对照 MUST-CATCH=PASS：3 条归属行、2 条在注入端口；legs that never ran: none。

仪器自身的修正（本轮）：Get-TbAudTestOnlyShipped 的正则曾多转义一层（@\\( ），于是永远找不到排除表、
永远报"没有排除表"——一个永远亮红的检查与永远绿的检查同样没有价值。已改为 -notin\s+@\(([^)]*)\) 并取捕获组，
上面那条 FINDING 现在说的是真话。负责人据此撤回"smoke_test 已移出可发布集合"的裁决：分类保留，
兑现要靠分发层改 install.ps1 的打包，不是改标签。
