# THIRD_PARTY_NOTICES —— 第三方组件声明（全部为实测结论）

本文件由 `telemetry_audit.ps1` 的测量结果反推写出，不是凭印象写的免责声明。
每一条都带 `文件:行号`，可以用编辑器逐条核对；核对不过就是这份声明错了。

- 生成本文件的审计运行：2026-10-22，`D:\Example\thunder-work\work\dist`，审计退出码见 `telemetry-audit.md`。
- 本文件描述的是**当前 dist 目录里的代码**（20 个文件：19 个 `.ps1` + 1 个 `README.md`）。
  审计的静态扫描按 `Get-ChildItem -Recurse -Filter *.ps1` 取文件，**没有硬编码文件清单**，
  所以新增文件会被自动扫到，删除文件不会留下幽灵结论。

---

## 1. 没有随包分发的第三方代码、库或二进制

实测：整个包目录里**没有任何二进制文件**（无 `.dll`、`.exe`、`.zip`、`.nupkg`、无 `vendor/`、无 `bin/`）。
文件清单（大小 / 修改时间 / SHA256 前 16 位）在 `telemetry-audit.md` 的"包清单"一节，共 20 个文件。

包内唯一的外部代码形式是 `Add-Type -TypeDefinition` 就地编译的 C#，源码就在 `.ps1` 里，
编译由 **Windows 自带的 .NET Framework 编译器** 完成。审计在以下位置实测到 `Add-Type`：

| 位置 | 内容 |
| --- | --- |
| `lib\win32io.ps1:26` | Win32 I/O 探针类型 |
| `lib\criteria.ps1:494` | 判定用的原生探针类型 |
| `lib\tbsm-store.ps1:64` | 存储层原生类型 |
| `lib\tbsm-store.ps1:1790` | 存储层第二段原生类型 |

这条路径在运行时确实会产生一个 OS 自带的子进程 `csc.exe`：审计在 `-Cmd doctor` 的进程树里
实测抓到了它（见 `telemetry-audit.md` 的 `[D]` 节 `new descendants captured`）。
`csc.exe` 只做本地编译，不联网，属于 Windows / .NET Framework 的一部分。

**没有 vendored 第三方库，所以没有需要转述的 MIT / BSD / Apache 版权段落。**
本包引用的外部组件全部是操作系统自带组件，其授权由你机器上那份 Windows 许可证覆盖，
ThunderBackup 不复制、不打包、不重新分发它们的任何一份副本。

---

## 2. 操作系统自带的外部可执行文件（唯一被允许的两个 + 实测到的其余）

审计对每条 `.ps1` 的每一行做启动点识别，把能被拉起的可执行文件列成清单，
与白名单 `fsutil.exe`、`certutil.exe` 对比。**下面每一个调用点都是实测出来的，行号可核对。**

### `certutil.exe`（Windows 自带的证书工具）

| 调用点 | 实际命令 | 用途 |
| --- | --- | --- |
| `lib\tb-commands.ps1:239` | `& certutil.exe -hashfile $Path SHA256` | `Add-Type` 被禁用时算 SHA256，是降级路径 |
| `lib\tb-doctor.ps1:78` | `& certutil.exe -hashfile $p SHA256` | `doctor` 用它对比原生哈希的耗时 |

其余出现 `certutil` 的行（`lib\tb-commands.ps1:190/241/244/286`、`lib\tb-doctor.ps1:55/80/81/82/209/310/330`）
是提示文字与降级说明，**不是启动点**；审计把它们和启动点分开列（`kind=mention`）。
`certutil` 只被允许使用 `-hashfile` 这一个动词：审计有一条"工具动词越权"规则，
实测到别的动词（例如 `-URLX`，它能下载）就会判红。注入这条越权动词作为反向对照时，
审计确实报了出来（见 `telemetry-audit.md` 的 `[S7]` C3）。

### `fsutil.exe`（Windows 自带的文件系统工具）

| 调用点 | 实际命令 | 用途 |
| --- | --- | --- |
| `lib\win32io.ps1:396` | `& fsutil file queryallocranges offset=0 length=$len $Path` | 读文件的簇分配区间，用来判断洞（稀疏） |
| `lib\win32io.ps1:825` | `& fsutil usn queryjournal $VolumeRoot` | 查卷的 USN 日志是否存在 |
| `lib\tbsm-store.ps1:1890` | `& fsutil hardlink list $probe` | 列出硬链接，判断文件是否被多处引用 |
| `smoke_test.ps1:410/411/412` | `& fsutil.exe hardlink create` / `hardlink list` | 开发期自检里造硬链接（**在临时目录**） |

允许的动词集合就是上表实测到的这三个（`file queryallocranges`、`usn queryjournal`、`hardlink list`）。
`smoke_test.ps1:410` 的 `hardlink create` 是**写操作**，不在允许集合里，审计把它判成越权动词并计一条 FINDING；
它只在开发自检中执行、只动 `%TEMP%` 下的文件，但"本地、临时、无害"这类判断不该由规则悄悄替人做完，
所以留红，由人来处置（要么把 `create` 显式加进允许集合并说明，要么把自检挪出发布目录）。

`fsutil` / `certutil` 的这五次调用**没有一次带 URL、没有一次触网**：审计有一条"URL 与白名单工具同行"规则，
注入 `& certutil.exe -URLX http://127.0.0.1:1/audit-control` 时确实被抓住。

### 实测到的白名单之外的可执行文件

`powershell.exe`：包代码会再启动一个 PowerShell 子进程。实测调用点：

| 调用点 | 场景 |
| --- | --- |
| `install.ps1:163` | 安装尾部用子进程跑一次 `-Cmd doctor -SkipProbes` |
| `smoke_test.ps1:62/169/425/443/450/459` | 开发自检里反复以子进程驱动 `install.ps1` / `thunderbackup.ps1` / `uninstall.ps1` |

这不产生网络行为（同一个解释器、同样的代码路径），但**它超出既定白名单**，
所以审计按规则判红（退出码 6），没有为了让结果好看而把它写进白名单。
处置权在负责人：要么承认"包会自举子进程"并把它列为已声明组件，要么改掉这两处调用。

`csc.exe`：由 `Add-Type` 间接触发（见第 1 节），不是包代码显式启动的，包代码里没有 `csc` 字面量。

---

## 3. 实测到的 P/Invoke 面（原生 API）

审计把每一条 `[DllImport]` 声明都列了出来（`[S3]` 节，共 **50 条声明**），涉及的模块只有三个，
**全部是 Windows 自带 DLL**，包内没有任何同名副本：

| 模块 | 条数 | 实测到的 API | 位置 |
| --- | --- | --- | --- |
| `kernel32.dll` | 43 | `CreateFileW`、`GetFileInformationByHandleEx`、`GetFileAttributesW`、`GetFileTime`、`GetCompressedFileSizeW`、`GetVolumePathNameW`、`GetVolumeInformationW`、`GetFinalPathNameByHandleW`、`DeviceIoControl`、`SetFilePointerEx`、`SetEndOfFile`、`WriteFile`、`FlushFileBuffers`、`MoveFileExW`、`DeleteFileW`、`CreateHardLinkW`、`CloseHandle`、`GetCurrentProcess`、`GetLastError` | `lib\criteria.ps1:156-181,344-354`；`lib\tbsm-store.ps1:129-150,220,471,693-694,1794-1796`；`lib\win32io.ps1:38-42,206-212,250-252,460-465` |
| `advapi32.dll` | 3 | `OpenProcessToken`、`LookupPrivilegeValueW`、`AdjustTokenPrivileges` | `lib\tbsm-store.ps1:684`、`689`、`691` |
| `rstrtmgr.dll` | 4 | `RmStartSession`、`RmRegisterResources`、`RmGetList`、`RmEndSession` | `lib\win32io.ps1:631`、`633`、`635`、`638` |

这三组 API 的作用范围，都在这张表里说完了：

- `kernel32` 那组是**文件与卷的元数据/读写**：开文件、查簇分配、查卷信息、写、移动、删、建硬链接。
- `advapi32` 那三个是一件事：**给当前进程开自己的令牌并启用一个特权**（`GetCurrentProcess` 也在同一类里）。
  这就是 `doctor` 需要管理员身份才能走通的那一条探针。它不开别人的进程、不注入、不写别的过程内存。
  审计的静态规则专门盯 `CreateRemoteThread` / `VirtualAllocEx` / `WriteProcessMemory` / `SetWindowsHookEx` /
  `NtProtectVirtualMemory` 这几类，实测结果：**0 命中**。
- `rstrtmgr.dll` 是 **Restart Manager**：查"哪个进程正占用这个文件"，用来解释为什么写入被拒。
  查询是本地的，返回的是同机进程的 PID 与名字。

注意：`ws2_32.dll`（WinSock）在被审计的子进程里**是已加载状态**——但这是 PowerShell 自身的加载行为，
不等于"建立了连接"。审计的实测结论是：在测得的时间窗内，被审计进程树**没有产生任何 TCP/UDP 行**
（同时空闲对照进程也是 0，正向对照 3 行，证明仪器不是瞎的）。模块加载情况与这个区分写在
`telemetry-audit.md` 的 `[D]` 节与"这套实验不能证明什么"一节。

---

## 4. Windows PowerShell 5.1 本身

包只在 Windows PowerShell 5.1（桌面版，操作系统组件）上运行与被测：
实测版本 `5.1.19041.7725`，`PSEdition=Desktop`，语言模式 `FullLanguage`，
宿主系统 `Microsoft Windows 10 专业版 build 19045`，`.NET Framework 4.x` 注册表 release 键 `533325`。
PowerShell 与 .NET Framework 由那份 Windows 许可证授权，本包不携带、不安装、不修改它们。
本包不依赖 `pwsh`（PowerShell 7+）；所有代码只用 5.1 存在的 cmdlet 与语法。

---

## 5. 没有使用的东西（明确写出来，免得被当成"藏在别处"）

- **SQLite / `winsqlite3.dll`：整个包里没有一处引用。** 在全部 20 个文件里做大小写不敏感的
  `sqlite` 检索，只命中一条文字说明：`lib\criteria.ps1:1197`
  `$r.taskdb = 'UNAVAILABLE(no sqlite reader wired in here)'`。
  也就是说：**迅雷的任务库当前读不了，代码明确把它标成 UNAVAILABLE，而不是"读到了但没说"**。
  任何"本包会读迅雷 SQLite 任务库"的说法，在当前这份代码上不成立。
- 没有任何 HTTP / 网络 API：`Invoke-WebRequest`、`Invoke-RestMethod`、`System.Net.WebClient`、
  `System.Net.Http.*`、`HttpWebRequest`、`Net.Sockets.*`、`WinHttp*`、`WinInet`、`curl.exe`、`wget`、
  `Start-BitsTransfer`、`Send-MailMessage` 在**包代码**（不含审计工具自身、不含注释）里 0 命中。
  这条结论有反向对照撑着：把这几种写法各注入一份，审计必须逐类报出来（`telemetry-audit.md` 的 `[S7]`）。
- 没有任何遥测用的持久化：`reg add`、`New-ItemProperty`/`Set-ItemProperty` 写 `HK*`、`sc.exe create`、
  `fltmc`、`devcon` 0 命中。**但计划任务有 4 条实测命中**，属于安装/卸载的可见功能，不是隐藏遥测：
  `install.ps1:140`、`install.ps1:145`（`Register-ScheduledTask`）、
  `uninstall.ps1:143`（`Unregister-ScheduledTask`）、`uninstall.ps1:147`（提示文字里的 `schtasks`）。
  这四条被审计判为 INJECTION/PERSISTENCE FINDINGS，是退出码 6 的一部分，需要负责人明确表态。

---

## 6. 这份声明的边界

- 本文件只声明**组件与调用面**，不是法律文本，不构成许可意见。
- 它描述的是被审计那一次运行时的 dist 内容。包内文件在开发过程中还在被同伴修改，
  每次改动后的清单（大小 / mtime / SHA256）以 `telemetry-audit.md` 里那一次实测运行为准；
  如果清单变了，本文件的行号需要重新核对。
- 声明"没有第三方代码"依赖的是可核对的证据（文件清单 + `[S3]` 的 50 条 `[DllImport]` + `[S2]` 的可执行文件清单），
  不是"我们不需要它"这种信念。

---

## 7. 更正记录（引用文本必须先判定它的地位）

`lib\win32io.ps1:387` 与 `:394` 曾被当作"文件名进动态执行"的现存缺陷登记。实测结论：**那两行是注释**，
内容恰恰是"这里以前把文件名拼进字符串交给解释器，现已改为用调用算符传一个参数"。
全包 20 个文件里含该关键字的行共 7 处，**活代码为 0 处**；唯一的活代码动态执行点是
`lib\tb-core.ps1:326` 的 `[ScriptBlock]::Create` + `:328` 的 `& $sb`，它执行的是**用户自己用 `-Config` 选的配置文件**
⇒ 判 **DECLARED（能力披露）**：配置文件是按你的选择被执行的代码，不是漏洞，但必须写在 README 里。
审计用第 6 类反向对照把这个区分钉在门上：注入活代码必须被抓（本次 CAUGHT @ `lib\tb-package.ps1:84`），
而真树里那两处散文必须**只按注释报**（本次 `prose-only hits: 2 at lib\win32io.ps1:387, :394`）。