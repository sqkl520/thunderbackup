# criteria.ps1 -- Classify-File reference implementation (Windows PowerShell 5.1, FullLanguage).
# ASCII-ONLY SOURCE on purpose: PS 5.1 decodes a BOM-less .ps1 as ANSI, which silently
# corrupts non-ASCII literals (global-miss class of failure).
#
# Spec, rationale, measured constants: D:\Example\thunder-work\work\02-design\criteria-spec.md
# Every native operation here is OPEN-EXISTING + QUERY + CLOSE. Nothing writes to a watched tree.
#
# ============================================================================
# HARD RULE 1 -- NO STRUCT/FIELD ACCESS IN POWERSHELL.
#   Observed trap (lead, 2026-10-22): reading a member of a Nullable<T> returned by a
#   static method -- `$f.Value.EndOfFile`, and even `$f.HasValue` -- comes back EMPTY with
#   no error. `eof - alloc` then becomes `0 - 0`, so EVERY file looks like a giant hole.
#   Direction: WAIT forever = silent global miss. Therefore every struct field is read
#   inside C# and handed over as (a) a plain public class instance field, and (b) a
#   pipe-delimited string via [XldbProbe]::Row(). PS never touches FSI/FID members.
#
# HARD RULE 2 -- NO >= 0x80000000 LITERALS IN POWERSHELL.
#   PS 5.1 parses 0x80000000 as Int32 (-2147483648) and [uint32]0x80000000 then throws
#   "Value was either too large or too small". GENERIC_READ/GENERIC_WRITE live in C# only.
#   (Escape hatch if ever needed in PS: ([uint32]1 -shl 31).)
#
# HARD RULE 3 -- TWO SHARE MASKS, TWO PURPOSES. DO NOT UNIFY.
#   0x05 READ|DELETE   -> the writer probe. It must NOT offer WRITE share, otherwise an
#                         existing writer's own share mask admits us and the probe stops
#                         meaning anything.
#   0x07 READ|WRITE|DELETE -> observation and the copy handle. FILE_SHARE_DELETE is 0x04
#                         (NOT 0x40); share=0x43 => CreateFileW err=87 INVALID_PARAMETER.
#                         Without 0x04 this tool blocks Thunder's ReplaceFileW (err=32)
#                         and MoveFileWithProgressW (err=5). Measured, exp11.
#
# HARD RULE 4 -- info class numbers are pinned: FileStandardInfo = 1 (0 = FileBasicInfo,
#   gives err 24 ERROR_BAD_FUNCTION_FUNCTION), FileIdInfo = 18 (needs its own 24-byte
#   struct: ulong VolumeSerial + byte[16]; reusing the FSI shape returns garbage).
#
# HARD RULE 5 -- EPOCHS ARE THREE, NOT TWO.
#   DateTime.Ticks -> 0001-01-01 ; FILETIME -> 1601-01-01 ; Unix -> 1970-01-01.
#   Feeding the FILETIME offset to Ticks puts "now" in year 3626; a mistyped 0001 offset
#   (I wrote 592652380800000000 instead of 621355968000000000) is 91 years off. Both fail
#   with NO error and shift every settle window and TTL. All conversions live in ONE place
#   (NowMs / NowFileTime / FtToMs / UnixMsToFileTime) and selftest A0-clock asserts
#   |C# - PowerShell| < 5 s plus "a fixture stamped 2 h ago reads back as 120 min".
#
# HARD RULE 6 -- A SENTINEL MAY NOT LIVE INSIDE THE RANGE THE QUANTITY CAN TAKE.
#   hole = EndOfFile - AllocationSize is NEGATIVE for every fully allocated file (alloc
#   rounds UP to a 4096-byte cluster: observed -3496 .. 0 on real completed files). Using
#   -1 as "unknown" made 5 of 6 completed files UNKNOWN. Validity is an explicit bool
#   (FsiOk); sentinels are only allowed in domains that cannot produce them (links, delPend).
#
# HARD RULE 7 -- DO NOT ACCUMULATE STATE THROUGH `& $scriptblock`.
#   `$R = @(); $add = { $R += $code }; & $add 'X'` leaves $R EMPTY: the assignment lands in
#   the scriptblock's own scope. (The earlier Generic.List version appeared to work only
#   because .Add() mutated a shared object -- and New-Object of a generic list is blocked
#   under ConstrainedLanguage anyway.) Reasons are appended directly in the function body.
#   Empty reason lists are a SILENT loss of diagnosis, so A23 asserts Count >= 3.
#
# HARD RULE 8 -- MEMBER NAMES ARE CONTRACTS; TYPO = $null, NOT AN ERROR.
#   doctor read `$o.DeletePending` while the surface exposes `DelPend`; `$null -ge 0` is
#   false, so the doctor line claimed a nonexistent instrument failure. selftest A26 pins
#   the field sets of all three observation surfaces (native / row / cmdlet) and requires
#   the L0 STRUCTURAL gap to be EXACTLY Alloc, CrtMs, NoWriterErr -- plus a separate
#   SEMANTIC gap assertion (fields present but information-free): HasFileId=false,
#   Links=-1, Hole=-1. A field that exists and is a sentinel is the most dangerous kind of
#   degradation, because "all fields present" reads as a pass. A26 pins both halves.
#
# HARD RULE 9 -- NEVER ASSUME THE HKCR: DRIVE.
#   On this box `Get-PSDrive -PSProvider Registry` yields only HKCU and HKLM, so
#   `Test-Path 'HKCR:\.xltd'` is FALSE and Thunder's temp-suffix discovery would return an
#   empty set -- looking exactly like "this machine has no Thunder", i.e. a silent global
#   miss of C1. Use `Registry::HKEY_CLASSES_ROOT\...`. A24 asserts .xltd/.td CONFIRMED and
#   .tmp NOT confirmed, which turns "empty" into a hard failure.
#
# HARD RULE 10 -- THE FILE MUST LOAD WHEN ADD-TYPE IS BLOCKED.
#   Add-Type is wrapped in try/catch and sets $script:XldNative; Get-FileObs falls back to
#   the cmdlet surface, New-ScanContext to Get-XldNowMs. An uncaught failure here kills the
#   whole dot-source and every judgement with it. No New-Object of .NET generics, no
#   [Math]::/[IO.File]::/[Convert]:: on the classify path -- those are CLM-blocked.
#   THE WARNING MUST BE LOUD: an Add-Type failure prints
#   "criteria.ps1 DEGRADED TO L0: native probes unavailable -- <message>", because L0's
#   answers are LEGAL, so a silent fallback is indistinguishable from a healthy run.
#   This warning caught two real compile errors this round (an undeclared SetEndOfFile
#   P/Invoke, and a wrong field name g.alloc) that would otherwise have masqueraded as
#   "graceful degradation".
#
# HARD RULE 11 -- EVERY REJECTING CHECK NEEDS A REVERSE CONTROL, OR IT DOES NOT EXIST.
#   "guard passed" and "guard never ran" are the SAME BYTES in a log. Four times this
#   project shipped the second one and read it as the first: a script whose 4 "guard
#   correctly rejects" rows were all fake because `-iequal` (not an operator) made the whole
#   file fail to parse; a missing `using System.Text;` meant a type never compiled and 9 rows
#   of "$null handled gracefully" were fiction; an invented property `.TotalAllocated` (real
#   name `.AllocatedBytes`) turned 59/59 nulls into "API unavailable"; `RealPath()` on a
#   DIRECTORY needs FILE_FLAG_BACKUP_SEMANTICS (0x02000000), and without it the resolver
#   returned ERROR_ACCESS_DENIED(5) plus an empty string, silently degrading a placement guard
#   to a string-prefix compare WHILE REPORTING PASS.
#   Machine-checkable form, all three implemented:
#     (i) load-time assertion: after Add-Type, assert the type exists, else throw -- never
#         catch-and-continue as if it were a policy;
#    (ii) parse gate: [Parser]::ParseFile and PRINT the error count; nonzero forbids any
#         conclusion. A45 feeds the gate a deliberately broken file and asserts it reports
#         errors, which proves the gate is watching this class of mistake;
#   (iii) every reject/degrade branch gets a fixture that ACTIVELY trips it, asserted as
#         expect=<reason code>, not expect=no error; plus a near-neighbour fixture asserting
#         NotReason=<same code> so the branch cannot be unconditional. A27..A53, and the
#         audit itself found 3 branches with no fixture (HOLE_STALL, HOLE_UNCONFIRMED,
#         GROWTH_WITNESSED) -- now A50..A53. Branches with no producible fixture
#         (G4_NA_OFFLINE) are reported as UNPROVEN and NOT counted as green.
#
# HARD RULE 12 -- DECODE THE CONTROL CODE BEFORE BLAMING THE ENVIRONMENT.
#   `FSCTL_SET_SPARSE err=1784` was reported twice -- once by us as a volume limit, once by
#   the lead as a buffer-marshalling problem. Both were wrong. 0x000900A4 decodes to function
#   41 = FSCTL_SET_REPARSE_POINT; FSCTL_SET_SPARSE is function 49 = 0x000900C4 (the codes
#   differ by 8<<2 = 0x20, i.e. "A4" vs "C4"). With the right code, sparse fixtures build
#   fine, so the observed "Thunder uses non-sparse preallocation" (RT-13) stands on its own
#   evidence again. Same class: FSCTL_SET_COMPRESSION returning ERROR_INVALID_PARAMETER(87)
#   was read as "no container support" when two things were wrong -- the format lives in the
#   LOW nibble (LZNT1=0x0001 works; XPRESS=0x0004 and LZX=0x0009 really do fail here) and the
#   handle must be GENERIC_READ|GENERIC_WRITE, not write-only. Also: FSCTL_GET_COMPRESSION
#   does not exist, and `fsutil file querycompressive` is not a verb.
#   doctor therefore capability-probes every ioctl it relies on and RECORDS the return value
#   and the resulting shape (IoctlLaw: control code, input byte count, OK/ERR+code,
#   sparseBit/eof/alloc/hole), printing NOT_PROBED when skipped. Never swallow a return.
#
# HARD RULE 13 -- READ ALLOCATION/Eof THROUGH A FRESH HANDLE.
#   FileStandardInfo queried on the handle that just modified the file can lag (measured:
#   alloc=3,080,192 in-handle vs 2,097,152 after reopen). Two agents disagreeing about a
#   number is usually one of them holding a stale handle (or using a different instrument --
#   see spec 10.2: fsutil queryallocranges and FileStandardInfo agree only on the SIGN).
#   Every post-modification shape read here reopens the file.
# ============================================================================

if (-not ('XldbProbe' -as [type])) {
$src = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class XldbProbe
{
    const uint GENERIC_READ  = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3;
    const uint SEQ_SCAN      = 0x08000000;
    const uint SH_ALL        = 0x00000007;   // READ|WRITE|DELETE : never block a rename
    const uint SH_RD_DEL     = 0x00000005;   // READ|DELETE       : writer probe only
    const uint FILE_SHARE_DELETE_ONLY = 0x00000004;
    static readonly IntPtr INVALID = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    public struct FSI { public long AllocationSize; public long EndOfFile; public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory; }

    [StructLayout(LayoutKind.Sequential)]
    public struct FID { public ulong VolumeSerial;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] FileId; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string p, uint acc, uint sh, IntPtr sa, uint disp, uint fl, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(IntPtr h, int cls, out FSI i, int sz);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(IntPtr h, int cls, out FID i, int sz);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileTime(IntPtr h, out long c, out long a, out long w);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFileAttributesW(string p);
    // G4's lazy third leg, queried ONLY on the hole>0 branch. Measured on this box: right
    // after `compact /c /exe:LZX` a byte-complete 128 KiB file reports eof=131072 alloc=4096
    // (hole=+126976) while FILE_ATTRIBUTE_COMPRESSED is still 0x20 -- the attribute lags,
    // sometimes for >1.5 s and in one trial forever. So "compressed" cannot be keyed on the
    // attribute bit alone. 0.108 ms/file. It is NOT proof of written bytes either.
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetCompressedFileSizeW(string p, out uint hi);
    // Volume type, for the non-NTFS exemption. MUST be called once per DIRECTORY (see
    // Get-XldFsType): per file it costs 1.517 ms/file = 152 s per 100k, i.e. 7.2x the whole
    // native observation budget (0.212 ms/file). Per directory it is 0.022 ms/file.
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool GetVolumePathNameW(string p, System.Text.StringBuilder vol, uint len);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool GetVolumeInformationW(string root, System.Text.StringBuilder name, int nameLen,
        out uint serial, out uint maxComp, out uint flags, System.Text.StringBuilder fs, int fsLen);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    // Sentinel discipline: -1 / false means UNKNOWN. UNKNOWN is never PASS.
    public class Obs
    {
        public string Path = "";
        public bool Opened;
        public int  Err;                 // open error, 0 = opened
        public long Eof   = -1;
        public long Alloc = -1;
        public long Hole  = -1;          // Eof - Alloc. Sign is the whole criterion (G4).
        public bool FsiOk;               // TRAP #7: hole is legitimately NEGATIVE for a
                                         // fully allocated file (alloc rounds UP to a
                                         // cluster), so -1 cannot double as "unknown".
                                         // Validity needs its own flag, not a sentinel
                                         // inside the value range.
        public int  HoleStateNum = 2;    // 0 PASS 1 FAIL 2 UNKNOWN 3 NOT_APPLICABLE
        public string HoleWhy = "";      // machine-readable NA reason, e.g. G4_NA_COMPRESSED
        public string HoleShape = "UNKNOWN"; // HOLLOW | DENSE | STORED_SMALL | UNKNOWN
        public long Gcs = -1;            // GetCompressedFileSizeW, only queried when Hole>0
        public bool GcsOk;
        public string Ext = "";          // lowercased extension, for the container/image class
        public int  Links = -1;
        public int  DeletePending = -1;
        public bool IsDir;
        public long LwtMs = -1;          // Unix ms, filesystem time, computed in C#
        public long CrtMs = -1;
        public uint Attr;
        public bool AttrSet;
        public bool Sparse; public bool Compressed; public bool Encrypted;
        public bool Offline;  public bool Reparse;   // G4 exemptions: 0x1000 / 0x400
        public ulong VolSerial;
        public string FileIdHex = "";
        public bool HasFileId;
        public int  NoWriterErr = -1;    // 0 => we obtained a write handle
        public int  HolderStateNum = 2;  // 0 PASS 1 FAIL 2 UNKNOWN
        public int  ExclusiveErr = -1;   // NOT used on the hot path (blocks renames)
        public string HoleState = "UNKNOWN";
        public string HolderState = "UNKNOWN";
    }

    // ---- EPOCH DISCIPLINE (trap #6, found by selftest A0-clock) --------------------
    //   DateTime.Ticks : 100ns ticks since 0001-01-01  (offset to 1970 = 621355968000000000)
    //   FILETIME       : 100ns ticks since 1601-01-01  (offset to 1970 = 116444736000000000)
    // Using the FILETIME offset against Ticks puts "now" 1600 years in the future; using
    // a wrong 0001 offset (I did, 91 years off) shifts every settle/TTL window. Both fail
    // SILENTLY -- so doctor/selftest asserts it: NowMs() must agree with PS to <5 s.
    const long TICKS_0001_TO_1970 = 621355968000000000L;   // 100ns ticks
    const long FT_1601_TO_1970    = 116444736000000000L;   // 100ns ticks

    public static long NowMs()       { return (DateTime.UtcNow.Ticks - TICKS_0001_TO_1970) / 10000L; }
    public static long NowFileTime() { return DateTime.UtcNow.ToFileTimeUtc(); }
    public static long FtToMs(long ft) { if (ft <= 0) { return -1; } return (ft - FT_1601_TO_1970) / 10000L; }
    public static long UnixMsToFileTime(long ms) { return ms * 10000L + FT_1601_TO_1970; }

    static IntPtr Open(string path, uint acc, uint sh)
    {
        return CreateFileW(path, acc, sh, IntPtr.Zero, OPEN_EXISTING, SEQ_SCAN, IntPtr.Zero);
    }

    // HOT PATH: exactly ONE handle for FSI + FileTime + FileId, plus one attribute query.
    // The writer probe is a second short open. Nothing here keeps a handle between calls,
    // and ProbeExclusive (share=0) is deliberately absent from this path: it would block
    // Thunder's ReplaceFileW (measured err=32, exp11 A2).
    public static Obs Read(string path)
    {
        Obs o = new Obs(); o.Path = path;
        IntPtr h = Open(path, GENERIC_READ, SH_ALL);
        if (h == INVALID) { o.Err = Marshal.GetLastWin32Error(); }
        else
        {
            o.Opened = true; o.Err = 0;
            FSI f;
            if (GetFileInformationByHandleEx(h, 1, out f, Marshal.SizeOf(typeof(FSI))))
            {
                o.FsiOk = true;
                o.Eof = f.EndOfFile; o.Alloc = f.AllocationSize; o.Hole = f.EndOfFile - f.AllocationSize;
                o.Links = (int)f.NumberOfLinks; o.DeletePending = f.DeletePending ? 1 : 0; o.IsDir = f.Directory;
            }
            else o.Err = Marshal.GetLastWin32Error();
            long c, a, w;
            if (GetFileTime(h, out c, out a, out w)) { o.CrtMs = FtToMs(c); o.LwtMs = FtToMs(w); }
            FID id;
            if (GetFileInformationByHandleEx(h, 18, out id, Marshal.SizeOf(typeof(FID))))
            {
                o.HasFileId = true; o.VolSerial = id.VolumeSerial;
                StringBuilder sb = new StringBuilder(32);
                for (int i = 0; i < id.FileId.Length; i++) sb.Append(id.FileId[i].ToString("x2"));
                o.FileIdHex = sb.ToString();
            }
            CloseHandle(h);
        }
        uint at = GetFileAttributesW(path);
        if (at != 0xFFFFFFFF)
        {
            o.AttrSet = true; o.Attr = at;
            o.Sparse = (at & 0x200u) != 0; o.Compressed = (at & 0x800u) != 0; o.Encrypted = (at & 0x4000u) != 0;
            o.Offline = (at & 0x1000u) != 0; o.Reparse = (at & 0x0400u) != 0;
        }
        string e = System.IO.Path.GetExtension(path);
        o.Ext = (e == null) ? "" : e.ToLowerInvariant();

        // ---- G4 physical validity, decided HERE so a policy layer cannot lose an exemption
        //      by a typo (HARD RULE 8). Three-valued + a machine-readable WHY.
        //      Compressed and non-NTFS push the criterion in OPPOSITE directions:
        //        compressed NTFS -> hole > 0 forever  -> "incomplete" forever  -> MISSED backup
        //        exFAT           -> hole <= 0 always  -> "complete"     forever -> BACKUP OF A PARTIAL FILE
        //      Both are "not measurable", never "passed".
        if (!o.FsiOk)                { o.HoleStateNum = 2; o.HoleWhy = "G4_NA_FSI_FAILED"; }
        else if (o.Compressed)       { o.HoleStateNum = 3; o.HoleWhy = "G4_NA_COMPRESSED"; }
        else if (o.Encrypted)        { o.HoleStateNum = 3; o.HoleWhy = "G4_NA_ENCRYPTED"; }
        else if (o.Offline)          { o.HoleStateNum = 3; o.HoleWhy = "G4_NA_OFFLINE"; }
        else if (o.Reparse)          { o.HoleStateNum = 3; o.HoleWhy = "G4_NA_REPARSE"; }
        else if (o.Hole > 0)
        {
            // Lazy third instrument, paid ONLY on the hole>0 branch (0.108 ms). Measured here,
            // GetCompressedFileSizeW tracks the UNCOMPRESSED size (compressed 128 KiB file:
            // eof=131072 alloc=4096 gcs=131072), so it CANNOT identify compression on this box.
            // It is recorded for transparency and deliberately NOT used as an exemption:
            // the compression signature we can rely on is FILE_ATTRIBUTE_COMPRESSED, and that
            // attribute LAGS (observed hole 131072 -> 4096 -> 131072 within 1.5 s with the bit
            // never set). Therefore a positive hole on a NON-sparse file is not acted on until a
            // second round confirms it -- see Classify-File's HOLE_UNCONFIRMED branch.
            uint chi; uint clo = GetCompressedFileSizeW(path, out chi);
            if (clo != 0xFFFFFFFF)
            {
                o.GcsOk = true; o.Gcs = (long)(((ulong)chi << 32) | (ulong)clo);
            }
            o.HoleStateNum = 1; o.HoleWhy = ""; o.HoleShape = "HOLLOW";
        }
        else { o.HoleStateNum = 0; o.HoleWhy = ""; o.HoleShape = "DENSE"; }
        o.HoleState = (o.HoleStateNum == 0) ? "PASS"
                      : (o.HoleStateNum == 1 ? "FAIL"
                      : (o.HoleStateNum == 3 ? "NOT_APPLICABLE" : "UNKNOWN"));
        return o;
    }

    // C3 writer probe: GENERIC_WRITE with share=READ|DELETE (0x05). Returns the Win32 error.
    // 0 = "I could open it for writing". 32/33 = "someone holds it" -- and because Win32
    // share checks are bidirectional this does NOT tell a writer from a reader.
    public static int ProbeHolder(string path)
    {
        IntPtr hw = Open(path, GENERIC_WRITE, SH_RD_DEL);
        if (hw == INVALID) return Marshal.GetLastWin32Error();
        CloseHandle(hw);
        return 0;
    }

    // ---- ioctl capability self-probe (DOCTOR ONLY; writes one throwaway file) --------
    // HARD RULE 12: when an ioctl fails, the FIRST hypothesis is that we used the wrong
    // control code, not that the machine lacks the capability. Measured on one box:
    //   0x000900C4 = CTL_CODE(9, 49, BUFFERED, ANY) = FSCTL_SET_SPARSE      -> OK, sparse bit set
    //   0x000900A4 = CTL_CODE(9, 41, BUFFERED, ANY) = FSCTL_SET_REPARSE_POINT
    //        -> err 1784 ERROR_INVALID_USER_BUFFER with no input buffer,
    //        -> err 4392 ERROR_INVALID_REPARSE_DATA with a 4-byte one.
    // 41 and 49 differ by 8<<2 = 0x20, i.e. "A4" vs "C4" -- and the failure text looks exactly
    // like "this volume does not do sparse files". That single typo cost three agents a wrong
    // environmental conclusion and a whole fixture family. So: never swallow the return value,
    // and never conclude "not supported" from an error that is really parameter validation.
    [StructLayout(LayoutKind.Sequential)]
    public struct ZERO_INFO { public long FileOffset; public long BeyondFinalSetByte; }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, uint inLen,
        IntPtr outBuf, uint outLen, out uint bytesRet, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, ref ZERO_INFO inBuf, uint inLen,
        IntPtr outBuf, uint outLen, out uint bytesRet, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(IntPtr h, long dist, out long newPtr, uint origin);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(IntPtr h, byte[] buf, uint len, out uint written, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetEndOfFile(IntPtr h);

    // which: 0 SET_SPARSE(in=0) 1 SET_SPARSE(in=4 ptr-to-value) 2 SET_REPARSE(in=4, the misuse)
    //        3 SET_REPARSE(in=0, the misuse) 4 SET_ZERO_DATA after 2 MiB written
    // Returns a self-describing line so the log shows the code AND the resulting shape: a
    // "success" that changed nothing is caught by the reverse control (rule 11).
    public static string IoctlLaw(string path, int which)
    {
        const uint FSCTL_SET_SPARSE   = 0x000900C4;  // function 49
        const uint FSCTL_SET_REPARSE  = 0x000900A4;  // function 41 -- NOT sparse
        const uint FSCTL_SET_ZERO     = 0x000980C8;  // function 50, METHOD_NEITHER
        uint code = FSCTL_SET_SPARSE;
        bool isReparse = (which == 2 || which == 3);
        if (isReparse) { code = FSCTL_SET_REPARSE; }
        bool isZero = (which == 4);
        if (isZero) { code = FSCTL_SET_ZERO; }

        IntPtr h = CreateFileW(path, 0xC0000000u, 0x07, IntPtr.Zero, 2 /*CREATE_ALWAYS*/, 0x80, IntPtr.Zero);
        if (h == INVALID) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
        try
        {
            uint ret; long p; uint w; bool ok = false; int err = 0;
            long allocBefore = -1, allocAfter = -1;
            byte[] blk = new byte[65536];
            if (isZero)
            {
                for (int i = 0; i < 32; i++) { WriteFile(h, blk, (uint)blk.Length, out w, IntPtr.Zero); }
                allocBefore = ShapeAllocFresh(path);          // fresh handle, never in-handle
                ZERO_INFO zi = new ZERO_INFO(); zi.FileOffset = 0; zi.BeyondFinalSetByte = 2097152;
                ok = DeviceIoControl(h, code, ref zi, (uint)Marshal.SizeOf(typeof(ZERO_INFO)),
                                     IntPtr.Zero, 0, out ret, IntPtr.Zero);
                err = ok ? 0 : Marshal.GetLastWin32Error();
                CloseHandle(h); h = INVALID;                   // so the after-read cannot see a stale handle
                allocAfter = ShapeAllocFresh(path);
            }
            else
            {
                IntPtr mem = IntPtr.Zero;
                if (which == 1 || which == 2) { mem = Marshal.AllocHGlobal(4); Marshal.WriteInt32(mem, 1); }
                ok = DeviceIoControl(h, code, mem, (mem == IntPtr.Zero) ? 0u : 4u,
                                     IntPtr.Zero, 0, out ret, IntPtr.Zero);
                err = ok ? 0 : Marshal.GetLastWin32Error();
                if (mem != IntPtr.Zero) { Marshal.FreeHGlobal(mem); }
                SetFilePointerEx(h, 4194304, out p, 0);
                if (!isReparse)
                {
                    // The extend has to be COMMITTED (SetEndOfFile) before the head write, or
                    // eof just lands on the 4 KiB we wrote and the shape proves nothing.
                    SetEndOfFile(h);
                    byte[] head = new byte[4096];
                    SetFilePointerEx(h, 0, out p, 0);
                    WriteFile(h, head, (uint)head.Length, out w, IntPtr.Zero);
                    SetFilePointerEx(h, 4194304, out p, 0);
                    SetEndOfFile(h);
                }
            }
            // Read the shape back on a FRESH handle: measured here, FileStandardInfo through the
            // handle that just modified the file can lag (alloc 3,080,192 in-handle vs 2,097,152
            // after a reopen). Same-file-number mismatches between tools usually mean one of the
            // two read through a stale handle, not that the volume lied.
            FSI f = new FSI();
            IntPtr h2 = CreateFileW(path, 0x80000000u, 0x07, IntPtr.Zero, 3 /*OPEN_EXISTING*/, 0x20, IntPtr.Zero);
            if (h2 != INVALID)
            {
                GetFileInformationByHandleEx(h2, 1, out f, Marshal.SizeOf(typeof(FSI)));
                CloseHandle(h2);
            }
            uint at = GetFileAttributesW(path);
            string rel = (allocBefore >= 0) ? (" release=" + (allocBefore - allocAfter)) : "";
            return string.Format("code=0x{0:x} in={1} ioctl={2} err={3} sparseBit={4} eof={5} alloc={6} hole={7}{8}",
                code, (which == 1 || which == 2) ? 4 : 0, (ok ? "OK" : "FAIL"), err,
                ((at & 0x200u) != 0), f.EndOfFile, f.AllocationSize, (f.EndOfFile - f.AllocationSize), rel);
        }
        finally { if (h != INVALID) { CloseHandle(h); } }
    }

    // Allocation read through a throwaway handle, so a modification's effect is measured on a
    // view that cannot be stale.
    static long ShapeAllocFresh(string path)
    {
        IntPtr hh = CreateFileW(path, 0x80000000u, 0x07, IntPtr.Zero, 3, 0x20, IntPtr.Zero);
        if (hh == INVALID) { return -1; }
        try
        {
            FSI g;
            if (!GetFileInformationByHandleEx(hh, 1, out g, Marshal.SizeOf(typeof(FSI)))) { return -2; }
            return g.AllocationSize;
        }
        finally { CloseHandle(hh); }
    }

    // Volume filesystem name for `path` ("NTFS", "exFAT", ...). Call it ONCE PER
    // DIRECTORY and cache; never per file. On failure it returns "ERR<n>" -- which Classify-File
    // treats as NOT-APPLICABLE (fail-closed), because "could not determine" must never become
    // "assumed NTFS" for a criterion whose failure direction is backing up a partial file.
    public static string VolumeFs(string path)
    {
        System.Text.StringBuilder vol = new System.Text.StringBuilder(261);
        if (!GetVolumePathNameW(path, vol, 261)) { return "ERR" + Marshal.GetLastWin32Error(); }
        string root = vol.ToString();
        System.Text.StringBuilder name = new System.Text.StringBuilder(64);
        System.Text.StringBuilder fs = new System.Text.StringBuilder(16);
        uint serial, maxComp, flags;
        if (!GetVolumeInformationW(root, name, 64, out serial, out maxComp, out flags, fs, 16))
        { return "ERR" + Marshal.GetLastWin32Error(); }
        return fs.ToString();
    }

    // doctor-only. NEVER on the hot path: share=0 blocks every rename/delete by others.
    public static int ProbeExclusive(string path)
    {
        IntPtr hx = Open(path, GENERIC_READ, 0u);
        if (hx == INVALID) return Marshal.GetLastWin32Error();
        CloseHandle(hx);
        return 0;
    }

    // The unambiguous surface: everything resolved in C#, PS just splits on '|'.
    // order: OK|err|eof|alloc|hole|holeState|links|delPend|sparse|compressed|encrypted|lwtMs|crtMs|vol|fileId|noWriterErr|holderState|attr
    //        |holeWhy|ext|gcs|holeShape|offline|reparse
    // Appending only: indices 0..17 are frozen because the verification layer scores on them.
    // Volume type is deliberately NOT here: it must be resolved per directory, not per file.
    public static string Row(string path)
    {
        Obs o = Read(path);
        int nw = o.Opened ? ProbeHolder(path) : -1;
        string hs = (!o.Opened) ? "UNKNOWN" : (nw == 0 ? "PASS" : (nw == 32 || nw == 33 ? "FAIL" : "UNKNOWN"));
        return string.Format("{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}|{12}|{13}|{14}|{15}|{16}|{17:x}|{18}|{19}|{20}|{21}|{22}|{23}",
            o.Opened ? "OK" : "NO", o.Err, o.Eof, o.Alloc, o.Hole, o.HoleState, o.Links, o.DeletePending,
            o.Sparse ? 1 : 0, o.Compressed ? 1 : 0, o.Encrypted ? 1 : 0, o.LwtMs, o.CrtMs,
            o.VolSerial, o.FileIdHex, nw, hs, o.Attr,
            o.HoleWhy, o.Ext, o.Gcs, o.HoleShape, (o.Offline ? 1 : 0), (o.Reparse ? 1 : 0));
    }
}
'@
# L0 discipline: if Add-Type is blocked (ConstrainedLanguage / WDAC / GPO), this file must
# still LOAD and still classify -- an uncaught Add-Type failure used to kill the whole
# dot-source, which is the same silent global miss the spec exists to prevent.
try {
    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop
    $script:XldNative = $true
} catch {
    $script:XldNative = $false
    # Loud, not debug-gated: a compile failure here drops the whole tool to L0 (no hole, no
    # FileId, no holder probe) and L0's answers are LEGITIMATE, so nothing else would ever
    # notice. Two real incidents in this project were exactly this shape (a missing
    # `using System.Text;` and an undeclared struct field name), both read as "graceful".
    Write-Warning ("criteria.ps1 DEGRADED TO L0: native probes unavailable -- " + $_.Exception.Message)
}
if (-not ('XldbProbe' -as [type])) {
    if ($script:XldNative) { Write-Warning 'criteria.ps1 DEGRADED TO L0: XldbProbe type absent after Add-Type' }
    $script:XldNative = $false
}
} else { $script:XldNative = [bool]('XldbProbe' -as [type]) }
# $script:XldSelf / $script:XldNative are set at load time so that functions never have to
# guess their own file (a default parameter expression evaluated in the CALLER's scope gave
# doctor 'level=0' on a machine where Add-Type had plainly succeeded -- i.e. a false alarm).
$script:XldSelf = if ($PSCommandPath) { $PSCommandPath } elseif ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { '' }

function Get-XldNowMs {
    # CLM-safe unix milliseconds: New-TimeSpan + Get-Date are cmdlets, [datetime] is an
    # allowed core type. Used whenever the native clock is unavailable.
    $ts = New-TimeSpan -Start ([datetime]'1970-01-01') -End (Get-Date).ToUniversalTime()
    return [long]$ts.TotalMilliseconds
}

function Get-XldAbs { param([long]$V) if ($V -lt 0) { return -$V } return $V }   # [Math]:: is blocked under CLM

function ConvertTo-ExtendedPath {
    param([string]$Path)
    if ($Path.StartsWith('\\?\') -or $Path.StartsWith('\\.')) { return $Path }
    if ($Path -match '^[A-Za-z]:\\' -or $Path.StartsWith('\\')) { return '\\?\' + $Path }
    return $Path
}

function Get-FileObs {
    <#  L1/L2 observation: 1 native handle + 1 attribute query (0.229 ms/file measured by
        the lead; the holder probe adds one more short open). The returned object carries
        ONLY plain instance fields (class, not struct, not Nullable<T>) plus the
        pre-computed three-valued states -- see HARD RULE 1.  #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    if (-not $script:XldNative) { return Get-FileObsCmdlet -Path $Path }   # L0: no native surface at all
    $ep  = ConvertTo-ExtendedPath $Path
    $raw = [XldbProbe]::Read($ep)
    $holder = 'UNKNOWN'; $nw = -1
    if ($raw.Opened) {                     # C3 costs one extra short open (~0.05 ms)
        $nw = [XldbProbe]::ProbeHolder($ep)
        $holder = if ($nw -eq 0) { 'PASS' } elseif ($nw -eq 32 -or $nw -eq 33) { 'FAIL' } else { 'UNKNOWN' }
    }
    [pscustomobject]@{
        Source='native'; Path=$Path; Opened=[bool]$raw.Opened; Err=[int]$raw.Err
        Eof=[long]$raw.Eof; Alloc=[long]$raw.Alloc; Hole=[long]$raw.Hole
        FsiOk=[bool]$raw.FsiOk
        HoleState=[string]$raw.HoleState; HolderState=$holder
        Links=[int]$raw.Links; DelPend=[int]$raw.DeletePending
        LwtMs=[long]$raw.LwtMs; CrtMs=[long]$raw.CrtMs
        Sparse=[bool]$raw.Sparse; Compressed=[bool]$raw.Compressed; Encrypted=[bool]$raw.Encrypted
        Offline=[bool]$raw.Offline; Reparse=[bool]$raw.Reparse
        Attr=[uint32]$raw.Attr; AttrSet=[bool]$raw.AttrSet; Ext=[string]$raw.Ext
        HoleWhy=[string]$raw.HoleWhy; HoleShape=[string]$raw.HoleShape; Gcs=[long]$raw.Gcs; GcsOk=[bool]$raw.GcsOk
        VolSerial=[string]$raw.VolSerial; FileIdHex=[string]$raw.FileIdHex; HasFileId=[bool]$raw.HasFileId
        NoWriterErr=$nw
    }
}

function Get-FileObsFromRow {
    <#  Zero-ambiguity alternative: parse the C#-rendered row. Use this whenever a
        teammate's instrument disagrees with this one -- mixing the two tools' NUMBERS
        in one table is forbidden by the spec (fsutil says hole=65536 where
        FileStandardInfo says hole=45056 for the same file; only the sign is portable). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $c = ([XldbProbe]::Row((ConvertTo-ExtendedPath $Path))) -split '\|'
    [pscustomobject]@{
        Source='row'; Path=$Path; Opened=($c[0] -eq 'OK'); Err=[int]$c[1]
        Eof=[long]$c[2]; Alloc=[long]$c[3]; Hole=[long]$c[4]
        FsiOk=([long]$c[2] -ge 0)          # a real file always has EndOfFile >= 0
        HoleState=$c[5]; Links=[int]$c[6]; DelPend=[int]$c[7]
        Sparse=($c[8] -eq '1'); Compressed=($c[9] -eq '1'); Encrypted=($c[10] -eq '1')
        LwtMs=[long]$c[11]; CrtMs=[long]$c[12]
        VolSerial=$c[13]; FileIdHex=$c[14]; HasFileId=($c[14].Length -eq 32)
        NoWriterErr=[int]$c[15]; HolderState=$c[16]
        Attr=[uint32]('0x' + $c[17]); AttrSet=($c[17] -ne '0')
        HoleWhy=$c[18]; Ext=$c[19]; Gcs=[long]$c[20]; HoleShape=$c[21]
        GcsOk=([long]$c[20] -ge 0)     # Row() renders -1 when the lazy probe never ran
        Offline=($c[22] -eq '1'); Reparse=($c[23] -eq '1')
    }
}

function Get-FileObsCmdlet {
    <#  L0 observation (ConstrainedLanguage / WDAC): cmdlets only, no type accelerators,
        no static .NET calls, no Add-Type. hole / deletePending / fileId / holder are
        UNKNOWN on purpose -- and UNKNOWN never upgrades to PASS.
        IMPORTANT: the G4 exemptions that do NOT need FileStandardInfo (compressed, encrypted,
        offline, reparse, tiny, container extension) are still enforceable at L0, because the
        attribute flags and the size come from Get-Item. Only the hole measurement is lost.  #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $i = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    $ext = ('' + [System.IO.Path]::GetExtension($Path)).ToLowerInvariant()
    if (-not $i -or $i.PSIsContainer) {
        return [pscustomobject]@{ Source='cmdlet'; Path=$Path; Opened=$false; Err=2
            Eof=-1; Hole=-1; FsiOk=$false; HoleState='UNKNOWN'; HolderState='UNKNOWN'; Links=-1; DelPend=-1
            LwtMs=-1; Sparse=$false; VolSerial=''; FileIdHex=''; HasFileId=$false
            Compressed=$false; Encrypted=$false; Offline=$false; Reparse=$false; AttrSet=$false; Attr=[uint32]0
            Ext=$ext; HoleWhy='G4_NA_FSI_FAILED'; HoleShape='UNKNOWN'; Gcs=[long](-1); GcsOk=$false }
    }
    $a   = '' + $i.Attributes
    $lwt = (New-TimeSpan -Start $i.LastWriteTimeUtc -End (Get-Date).ToUniversalTime())
    [pscustomobject]@{ Source='cmdlet'; Path=$Path; Opened=$true; Err=0
        Eof=[long]$i.Length; Hole=-1; FsiOk=$false; HoleState='UNKNOWN'; HolderState='UNKNOWN'; Links=-1; DelPend=-1
        LwtMs=[long]$lwt.TotalMilliseconds; Sparse=($a -match 'Sparse')
        VolSerial=''; FileIdHex=''; HasFileId=$false
        Compressed=($a -match 'Compressed'); Encrypted=($a -match 'Encrypted')
        Offline=($a -match 'Offline'); Reparse=($a -match 'ReparsePoint')
        AttrSet=$false; Attr=[uint32]0        # the numeric word is native-only; the named flags are not
        Ext=$ext; HoleWhy='G4_NA_FSI_FAILED'; HoleShape='UNKNOWN'; Gcs=[long](-1); GcsOk=$false }
}

# Rule 16 (gate attribution): "it was refused" does not prove WHICH gate refused it. With gates
# in a fixed order the earliest can fire first and the test still "passes" -- storage hit exactly
# this (integrity gate before placement gate). Every decision object therefore carries the gate
# that produced it, DERIVED from the reason codes instead of hand-maintained at 18 call sites:
# one table, longest matching prefix wins, and an unmapped code becomes UNKNOWN_GATE rather than
# a silently empty field (rule 16's own corollary: "no value" must not look like "a value").
$script:XldGateMap = @{
    'GONE_'                = 'C0.open'
    'ACL_DENIED'            = 'C0.open'
    'HOLDER_READ'           = 'C0.open'
    'LOCK'                  = 'C0.open'
    'OPEN_ERR'              = 'C0.open'
    'DELETE_PENDING'        = 'C5.delete-pending'
    'DIR_SKIP'              = 'C9.skip-dir'
    'TMPNAME_WEAK'          = 'C1.temp-name'
    'TMPNAME'               = 'C1.temp-name'
    'SIDECAR_STALE'         = 'C2.sidecar-stale'
    'SIDECAR_CFG'           = 'C2.sidecar'
            'SIDECAR_UNPAIRED_'    = 'C2.sidecar-unpaired'
    'E_HARDLINK'            = 'C14.hardlink'
    'HARDLINK_STATE_UNKNOWN' = 'C14.hardlink-l0-unknown'
    'HOLE_STALL'            = 'C4.hole-stall'
    'HOLE_CONFIRMED'        = 'C4.hole'
    'HOLE_UNCONFIRMED'      = 'C4.hole-first-sighting'
    'HOLE_'                 = 'C4.hole'
    'SPARSE_HOLE_PRESENT'   = 'C4.hole'
    'SPARSE_NO_HOLE'        = 'C4.hole'
            'G4_NA_PREALLOC'        = 'C4.exempt-prealloc'
    'G4_NA_VOLUME_'         = 'C4.exempt-volume'
    'G4_NA_'                = 'C4.exempt-attribute'
    'G4_REVIEW_CONTAINER'   = 'C4.review-container'
    'RENAME_NO_IDENTITY_ON_VOL_' = 'C7.rename-capped'
    'RENAME_WITNESSED'      = 'C7.rename'
    'RENAME_NOT_WITNESSED'  = 'C7.rename'
    'DB_STATUS'             = 'C6.db'
    'SIZE_MISMATCH'         = 'C6.db-size'
    'EXPECT_UNKNOWN'        = 'C6.expect-unresolved'
    'NO_COMPLETION_ACT'     = 'C6.no-act'
    'CAPABILITY_VOLUME_'    = 'CEILING.volume'
            'VERIFIED_CAPPED_BY_PREALLOC' = 'CEILING.prealloc'
    'VERIFIED_CAPPED_BY_VOLUME' = 'CEILING.volume'
    'LEN_MOVING'            = 'C10.unsettled-growth'
    'UNSETTLED_'            = 'C10.settle-window'
    'GROUP_INCOMPLETE'      = 'C11.group'
    'NO_GROWTH_WITNESS'     = 'C10.growth'
    'GROWTH_WITNESSED'      = 'C10.growth'
    'IDENTITY_WEAK'         = 'IDM.identity'
    'PAIRING_AMBIGUOUS'     = 'C6.pairing'
}
function Get-XldBlockedBy {
    # Decision-aware: for BACKUP / BACKUP_UNVERIFIED the attributing gate is the completion ACT
    # (or the ceiling that capped it); for WAIT / SKIP it is the last reason that maps to a gate,
    # which is the one that actually returned. Scanning backwards and breaking on the first hit
    # also keeps this cheap -- the naive forward scan over all 38 prefixes cost ~0.5 ms per file
    # and tripped the A21 cost assertion (measured, not guessed).
    param([string]$Decision, [string[]]$Reasons)
    $rs = @($Reasons)
    $wantGrant = ($Decision -eq 'BACKUP' -or $Decision -eq 'BACKUP_UNVERIFIED')
    for ($i = $rs.Count - 1; $i -ge 0; $i--) {
        $s = '' + $rs[$i]
        if (-not $s.Length) { continue }
        if ($wantGrant) {
            $isGrant = $false
            foreach ($g in @('DB_STATUS', 'RENAME_WITNESSED', 'ACT_', 'VERIFIED_CAPPED_BY_VOLUME', 'VERIFIED_CAPPED_BY_PREALLOC', 'CAPABILITY_VOLUME_', 'SIDECAR_STALE')) {
                if ($s.StartsWith($g)) { $isGrant = $true; break }
            }
            if (-not $isGrant) { continue }
        }
        $hit = ''
        foreach ($p in @($script:XldGateMap.Keys)) {
            if ($s.StartsWith($p) -and $p.Length -gt ('' + $hit).Length) { $hit = $p }
        }
        if ((('' + $hit).Length) -gt 0) { return ('' + $script:XldGateMap[$hit] + '=' + $s) }
    }
    if ($wantGrant) {
        # Nothing in the trace is a granting ACT -- which is exactly what BACKUP_UNVERIFIED means.
        # Attribute it to the last mapped reason (usually C6.no-act = NO_COMPLETION_ACT) so the row
        # states WHY the claim is not verified; UNKNOWN_GATE stays reserved for genuinely unmapped
        # codes, otherwise every unverified row screams UNKNOWN and the tripwire loses its value.
        for ($i2 = $rs.Count - 1; $i2 -ge 0; $i2--) {
            $s2 = '' + $rs[$i2]
            if (-not $s2.Length) { continue }
            $hit2 = ''
            foreach ($p2 in @($script:XldGateMap.Keys)) {
                if ($s2.StartsWith($p2) -and $p2.Length -gt ('' + $hit2).Length) { $hit2 = $p2 }
            }
            if ((('' + $hit2).Length) -gt 0) { return ('' + $script:XldGateMap[$hit2] + '=' + $s2) }
        }
    }
    return 'UNKNOWN_GATE'
}

function Test-XldPublishable {
    # Rule 18: "not executed" is its own state and it BLOCKS publication. A record may only be
    # published as evidence ("zero telemetry", "all guards passed", "clean") when every leg
    # carries non-empty execution evidence: null, empty, NOT-MEASURED, NOT_PROBED, NOT_RUN,
    # UNKNOWN and UNPROVEN are all blocking. This exists because an audit that ran 1615 lines and
    # exited 5 still LOOKS like it is working if you only ask "did it report any outbound call".
    param([hashtable]$Legs)
    $bad = @()
    foreach ($k in @($Legs.Keys)) {
        $v = $Legs[$k]
        if ($null -eq $v) { $bad += ($k + '=NULL'); continue }
        $s = '' + $v
        if (-not $s.Length) { $bad += ($k + '=EMPTY'); continue }
        if ($s -match 'NOT-MEASURED|NOT_MEASURED|NOT_PROBED|NOT_RUN|SKIPPED|UNKNOWN|UNPROVEN|FORBIDDEN') { $bad += ($k + '=' + $s) }
    }
    [pscustomobject]@{ Ok = (@($bad).Count -eq 0); Blocking = (@($bad) -join ',') }
}

function New-Decision {
    # [string[]], not Generic.List: New-Object of a generic list is blocked under CLM, and
    # @($list) throws "Argument types do not match" in PS 5.1 (trap #2). Plain arrays only.
    param([string]$Decision, [string[]]$Reasons, [pscustomobject]$Obs)
    [pscustomobject]@{
        Decision  = $Decision
        Reasons   = @($Reasons)
        BlockedBy = (Get-XldBlockedBy -Decision $Decision -Reasons $Reasons)
        CompletionClaimed = ($Decision -eq 'BACKUP')
        Identity  = $(if ([bool]$Obs.HasFileId) { 'fileid' } else { 'relpath-weak' })
        Eof       = $Obs.Eof
        Hole      = $Obs.Hole
        FileId    = $Obs.FileIdHex
    }
}

function Get-FileExtension {
    param([string]$Path)
    $n = Split-Path $Path -Leaf
    $k = $n.LastIndexOf('.')
    if ($k -lt 0 -or $k -eq ($n.Length - 1)) { return '' }
    return $n.Substring($k).ToLowerInvariant()
}

function New-XldRenameWitness {
    <# Builds the six-field rename witness. It performs NO validation on purpose: every assertion
        lives in Resolve-XldRenameWitness, which is called by Classify-File. A constructor that
        blesses its own input is the self-described-guarantee defect class (pit 33).
          TempName / FinalName : the two path leaves the runner saw
          DerivedFinal         : what TempName maps to once the engine temp suffix is stripped
          LengthMatch          : bytes at rename == bytes now (a rename that also grew is a
                                 different claim from "the file this witness covers is finished")
          AppearedThisRound    : final name absent last round, present now; without it a stale
                                 cached pair keeps licensing forever
          GapMs                : wall time between the two sightings; used only as a sanity bound
                                 (>= 0 and < 24 h), never as a completion claim                      #>
    param([string]$TempName, [string]$FinalName, [string]$DerivedFinal,
          [bool]$LengthMatch, [bool]$AppearedThisRound, [long]$GapMs)
    [ordered]@{
        TempName          = ('' + $TempName)
        FinalName         = ('' + $FinalName)
        DerivedFinal      = ('' + $DerivedFinal)
        LengthMatch       = [bool]$LengthMatch
        AppearedThisRound = [bool]$AppearedThisRound
        GapMs             = [long]$GapMs
    }
}

function Resolve-XldRenameWitness {
    <# RULING B enforced at the boundary. Three outcomes:
         $null                              no claim at all (the ordinary case)
         @{ Ok=$false; Code=<field code> }  a claim that fails one assertion: the rename leg keeps
                                            its FACT but loses its LICENSING power
         throw                              a claim that arrived collapsed (bool / scalar / unknown
                                            type) or with a field missing. Refusal is a throw
                                            because a collapsed claim cannot even be examined --
                                            there is nothing left to assert -- and quietly treating
                                            it as "no claim" would let a runner that lost its
                                            struct keep answering as if it still had one.
        Accepting only an IDictionary carrying all six keys is what makes the T14 class visible:
        the boolean form was the carrier that made six fields disappear without any error.      #>
    param([hashtable]$Ctx, [string]$FinalPath)
    if ($Ctx.Contains('RenamedFromTemp')) {
        $legacy = $Ctx['RenamedFromTemp']
        if ($null -ne $legacy) {
            $legacyType = '' + $legacy.GetType().Name
            $isFalsey = ($legacyType -eq 'Boolean' -and -not [bool]$legacy)
            if (-not $isFalsey) {
                throw ('WITNESS_SHAPE_REJECTED_BOOL: rename claim arrived as ' + $legacyType + ' [' + ('' + $legacy) +
                    '] on ' + $FinalPath + '; a claim must arrive as the six-field RenameWitness')
            }
        }
    }
    if (-not $Ctx.Contains('RenameWitness')) { return $null }
    $w = $Ctx['RenameWitness']
    if ($null -eq $w) { return $null }
    if ($w -is [bool] -or $w -is [string] -or $w -is [int] -or $w -is [long] -or $w -is [double]) {
        throw ('WITNESS_SHAPE_REJECTED_BOOL: RenameWitness is a scalar ' + ('' + $w.GetType().Name) + ' [' + ('' + $w) +
            '] on ' + $FinalPath + '; all six fields are required')
    }
    if (-not ($w -is [System.Collections.IDictionary])) {
        throw ('WITNESS_SHAPE_UNSUPPORTED_TYPE: RenameWitness is a ' + ('' + $w.GetType().Name) + ' on ' + $FinalPath)
    }
    foreach ($wf in @('TempName', 'FinalName', 'DerivedFinal', 'LengthMatch', 'AppearedThisRound', 'GapMs')) {
        if (-not $w.Contains($wf)) { throw ('WITNESS_SHAPE_MISSING_FIELD_' + $wf + ': on ' + $FinalPath) }
    }
    $finalLeaf = '' + (Split-Path -Path $FinalPath -Leaf)
    if ('' + $w['FinalName'] -ne $finalLeaf) { return [pscustomobject]@{ Ok = $false; Code = 'FINAL_NAME_NOT_OBSERVED' } }
    if ('' + $w['DerivedFinal'] -ne $finalLeaf) { return [pscustomobject]@{ Ok = $false; Code = 'DERIVED_FINAL_LIES' } }
    $tempLeaf = '' + $w['TempName']
    # TempName must be FinalName plus exactly one authorised temp suffix. "Ends with a temp-looking
    # suffix" was weaker than it looks: a rename from an unrelated file whose name happens to end in
    # a listed suffix would have passed, and it needed its own copy of the suffix list -- which is
    # how the drift above got in. The check now reads the single authority.
    if ($tempLeaf -eq $finalLeaf -or -not $tempLeaf.StartsWith($finalLeaf)) {
        return [pscustomobject]@{ Ok = $false; Code = 'TEMP_NAME_NOT_A_TEMP' }
    }
    $wSfx = '' + $tempLeaf.Substring($finalLeaf.Length)
    if ($script:XldTempSuffixAuthority -notcontains $wSfx) {
        return [pscustomobject]@{ Ok = $false; Code = ('TEMP_SUFFIX_UNLISTED_IN_CRITERION' + $wSfx) }
    }
    # The observing layer must ALSO treat that name as temporary. Refusing here rather than
    # licensing on the criterion's list alone is the safe direction: if the layer that saw the file
    # does not consider the source a temp file, the rename proves nothing about completion.
    # This is deliberately NOT "trust the caller's list": TempSuffixesExtra is user config, and a
    # user-added suffix would otherwise hand licensing power to a config line (README L-04 already
    # documents that table as a loaded lever).
    $wCtxTable = $null
    if ($Ctx.Contains('TempSuffixes')) { $wCtxTable = $Ctx['TempSuffixes'] }
    if ($null -ne $wCtxTable -and -not $wCtxTable.ContainsKey($wSfx)) {
        return [pscustomobject]@{ Ok = $false; Code = ('TEMP_SUFFIX_NOT_IN_CTX' + $wSfx) }
    }
    if (-not [bool]$w['LengthMatch']) { return [pscustomobject]@{ Ok = $false; Code = 'LENGTH_NOT_MATCHED' } }
    if (-not [bool]$w['AppearedThisRound']) { return [pscustomobject]@{ Ok = $false; Code = 'NOT_APPEARED_THIS_ROUND' } }
    $gap = [long]$w['GapMs']
    if ($gap -lt 0 -or $gap -ge 86400000) { return [pscustomobject]@{ Ok = $false; Code = 'GAP_IMPLAUSIBLE' } }
    [pscustomobject]@{ Ok = $true; Code = 'WITNESS_OK' }
}

function Classify-File {
    <#
      INPUT
        $obs : Get-FileObs | Get-FileObsFromRow | Get-FileObsCmdlet record for ONE file
        $ctx : hashtable from New-ScanContext (see defaults there):
               Level TempSuffixes SkipDirs Sidecar SidecarLwtMs NowMs SettleWindowMs
               SidecarTTLMin HolderFailRounds HolderMaxRounds HoleFailRounds HoleMaxRounds
               Prev Expect IsManifest GroupReady RenamedFromTemp RenameWitness
      OUTPUT @{ Decision; Reasons; CompletionClaimed; Eof; Hole; FileId }, Decision in
               BACKUP | BACKUP_UNVERIFIED | WAIT | SKIP

      LADDER RULE -- the single thing that keeps RT-02 out of the store:
        a VERIFIED backup requires an ACT of completion, not an absence of activity.
        Only two qualify:
          (a) Thunder's own declaration (level>=2: Status=8 AND eof==ResourceSize==ValidSize)
          (b) a temp->final rename THIS tool personally observed
        "We watched it grow and then it went quiet" does NOT qualify: a paused download
        produces exactly that trace forever (red team RT-02, deterministic, no race).
        Such files land in BACKUP_UNVERIFIED, which is visible by construction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$obs,
        [Parameter(Mandatory)][hashtable]$ctx
    )
    $R = @()

    # ---- C0 observation validity ----------------------------------------------------
    if (-not $obs.Opened) {
        switch ([int]$obs.Err) {
            2       { $R += 'GONE_OBS2' }
            3       { $R += 'GONE_PATH3' }
            5       { $R += 'ACL_DENIED5' }
            32      { $R += 'HOLDER_READ32' }
            33      { $R += 'LOCK33' }
            default { $R += ('OPEN_ERR' + [int]$obs.Err) }
        }
        return New-Decision 'WAIT' $R $obs
    }

    # ---- C5 delete-pending: veto this round (a pending-delete object cannot be renamed)
    if ([int]$obs.DelPend -eq 1) { $R += 'DELETE_PENDING'; return New-Decision 'SKIP' $R $obs }

    # ---- C9 directory skip ----------------------------------------------------------
    foreach ($sd in $ctx.SkipDirs) {
        if ([string]::IsNullOrWhiteSpace($sd)) { continue }
        if ($obs.Path.StartsWith($sd)) {
            $R += ('DIR_SKIP:' + (Split-Path $sd -Leaf)); return New-Decision 'SKIP' $R $obs
        }
    }

    # ---- C1 temp name: suffix AND one corroborating signal, else it is a trap (RT-10)
    $ext     = Get-FileExtension $obs.Path
    $isTmp   = [bool]$ctx.TempSuffixes.ContainsKey($ext)
    $hasSide = [bool]$ctx.Sidecar
    # ---- sidecar pairing bound (trap #28 + #34). Before this line the sidecar arrived as a bare
    #      boolean from the caller ($ctx.Sidecar / $ctx.SidecarLwtMs) and the criteria NEVER asked
    #      whether that .cfg could belong to THIS file's last write. One hole, two opposite leaks:
    #        - a stale-but-plausible pair still bought the "ignore the sidecar" grant (C1: 4 MiB of
    #          preallocation, nothing written, hole==0 invisible -> promised as final);
    #        - an IMPOSSIBLE pair vetoed a finished file forever (D: data frozen 4,912 min, sidecar
    #          5 min old, gap 294,419,549 ms -> WAIT with no exit).
    #      Now: a sidecar whose pairing is not 'ok' carries NO information at all -- it neither
    #      vetoes (no WAIT) nor grants (no stale bypass). It is treated as absent, everywhere.
    #      Get-XldPairing had definitions=1 / occurrences=1 (itself) until this line: this is its
    #      first real user, and A76 proves the call exists inside this function body from the AST.
    $sidePair = $null
    if ($hasSide) {
        $sideBound = 600000.0
        if ($ctx.ContainsKey('PairingBoundMs') -and ($null -ne $ctx['PairingBoundMs'])) { $sideBound = [double]$ctx['PairingBoundMs'] }
        $sideGapMs = [Math]::Abs([double]([long]$ctx.SidecarLwtMs) - [double]([long]$obs.LwtMs))
        $sidePair = Get-XldPairing -GapMs $sideGapMs -BoundMs $sideBound
        if (('' + $sidePair.Decision) -ne 'ok') {
            $R += ('SIDECAR_UNPAIRED_' + ('' + $sidePair.Code))
            $hasSide = $false
        }
    }
    $hollow  = ($obs.HoleState -eq 'FAIL')
    $held    = ($obs.HolderState -eq 'FAIL')
    if ($isTmp -and ($hasSide -or $hollow -or $held)) {
        $R += ('TMPNAME' + $ext); return New-Decision 'SKIP' $R $obs
    }
    if ($isTmp) { $R += ('TMPNAME_WEAK' + $ext) }

    # ---- C2 sidecar = Thunder's own "task not finished" predicate -------------------
    #      (DownloadSDK.dll exports XL_IsDownloadTaskCFGFileExit; completion removes it)
    $staleSidecar = $false
    if ($hasSide) {
        $sideAgeMin = Get-AgeMinutes -NowMs $ctx.NowMs -Ms ([long]$ctx.SidecarLwtMs)
        $fileAgeMin = Get-AgeMinutes -NowMs $ctx.NowMs -Ms ([long]$obs.LwtMs)
        if ($sideAgeMin -ge 0 -and $fileAgeMin -ge 0 -and
                $sideAgeMin -gt $ctx.SidecarTTLMin -and $fileAgeMin -gt $ctx.SidecarTTLMin -and
                -not $held -and $ctx.Level -ge 1) {
            $staleSidecar = $true; $R += ('SIDECAR_STALE_' + [int]$sideAgeMin + 'm')
        } else {
            $R += ('SIDECAR_CFG_side_' + [int]$sideAgeMin + 'm'); return New-Decision 'WAIT' $R $obs
        }
    }

    # ---- C14 hardlink: NumberOfLinks > 1 => refuse to back it up (E_HARDLINK) ---------
    #      Measured: mklink /H makes two names for ONE object; GetFinalPathNameByHandle returns
    #      whichever name was used to open, so BOTH placement guards report "inside my tree",
    #      the reparse bit is absent, and a write through the watched name lands in the store.
    #      "Backup = independent copy of the bytes" is false for a link, and the user's later
    #      cleanup of the watched name would silently alias into the library.
    #      links is already in FileStandardInfo, so this costs 0 -- it was simply unused.
    #      At L0 links is UNKNOWN (-1): never default it to 1. Fail closed by forbidding
    #      verified below, and say so with HARDLINK_STATE_UNKNOWN.
    $linksKnown = ([int]$obs.Links -ge 0)
    if ($linksKnown -and [int]$obs.Links -gt 1) {
        $R += ('E_HARDLINK_LINKS_' + [int]$obs.Links)
        return New-Decision 'SKIP' $R $obs
    }
    if (-not $linksKnown) { $R += 'HARDLINK_STATE_UNKNOWN' }

    # ---- C4 absolute hole. NO threshold, NO epsilon: the sign is the criterion. -----
    #      alloc is rounded UP to a cluster, so a fully allocated file has hole <= 0
    #      (measured -3496..0 on 6/6 completed files). Resolution floor = one cluster
    #      (4096 B on D:); files whose data lives in the MFT record (<= ~700 B measured)
    #      are byte-granular instead (1 B -> alloc 8), which is why tiny files are exempt.
    #      Four exemptions, each with its own code, and each direction-checked by selftest:
    #        G4_NA_COMPRESSED / G4_NA_ENCRYPTED / G4_NA_OFFLINE / G4_NA_REPARSE   (attr-driven,
    #            resolved in C# where the attribute word is read)
    #        G4_NA_VOLUME_<fs>       non-NTFS: exFAT has no sparse runs, alloc >= eof always,
    #            so hole can NEVER be > 0 -> an 8 MiB file with nothing written reads "complete".
    #            The criterion's failure direction REVERSES here: it backs up a partial file.
    #        G4_NA_TINY              eof < 65536: Thunder's own 16 KiB-aligned .cfg sidecars
    #            sit at hole == 0 exactly like a finished artifact -- indistinguishable (57/59
    #            sidecars on this box land in this exemption, 0 mislabels).
    #        G4_REVIEW_CONTAINER     container/image extensions: a hole may be the FINAL shape
    #            (sparse-format .vhd/.iso), so hole > 0 must not WAIT forever and hole <= 0
    #            must not imply complete. Review, not verdict.
    $g4na = @()
    if ($obs.HoleState -eq 'NOT_APPLICABLE') { $g4na += [string]$obs.HoleWhy }
    $fs = Get-XldFsType -Path $obs.Path -Ctx $ctx
    if ('' + $fs -notmatch '^NTFS$') { $g4na += ('G4_NA_VOLUME_' + $fs) }
    # Volume-capability ceiling, computed HERE (not only in the verdict) because it also decides
    # what a rename observation is WORTH. On a known non-NTFS volume, FileIdInfo(18) returns
    # ERROR_INVALID_PARAMETER before and after the rename alike (lead's independent repro), so
    # the identity that G7 is defined over does not exist: a "rename" seen there is a path-level
    # event, not a witness. UNRESOLVED / ERR<n> are NOT capped -- unknown is not known-bad.
    $volCap = ('' + $fs)
    $capVol = ($volCap -ne 'NTFS' -and $volCap -ne 'UNRESOLVED' -and $volCap -notmatch '^ERR')
    if ([long]$obs.Eof -lt 65536) { $g4na += 'G4_NA_TINY' }
    $isContainer = [bool]($ctx.ContainerExt.ContainsKey($ext))
    $g4noEvidence = (@($g4na).Count -gt 0) -or $isContainer
    foreach ($n in $g4na) { $R += $n }
    if ($isContainer) { $R += ('G4_REVIEW_CONTAINER' + $ext) }

    if ($hollow -and -not $g4noEvidence) {
        $R += ('HOLE_' + (Get-HoleBucket $obs.Hole))
        if ($obs.Sparse) { $R += 'SPARSE_HOLE_PRESENT' }
        if ($obs.Sparse -or [int]$ctx.HoleFailRounds -ge 1) {
            if (-not $obs.Sparse) { $R += 'HOLE_CONFIRMED' }
            if ($ctx.HoleFailRounds -lt $ctx.HoleMaxRounds) { return New-Decision 'WAIT' $R $obs }
            $R += 'HOLE_STALL'; return New-Decision 'SKIP' $R $obs
        }
        # First sighting of a hole on a NON-sparse file. On this box a byte-complete
        # compressed file shows exactly this for a while (hole 0 -> 126976 -> 0 while
        # FILE_ATTRIBUTE_COMPRESSED never appeared), so one sample is not evidence.
        # Abstain this round, re-check next round; it can never reach BACKUP here because
        # there is no completion ACT.
        $R += 'HOLE_UNCONFIRMED'
    }
    if ($hollow -and $isContainer -and -not (@($g4na).Count -gt 0)) {
        # a container with holes: not evidence of incompletion, but never a verified backup
        $R += ('HOLE_' + (Get-HoleBucket $obs.Hole)); $ctx['G4NoEvidence'] = $true
    }
    if ($obs.HoleState -eq 'UNKNOWN') { $R += 'HOLE_UNKNOWN' }
    if ($obs.Sparse -and $obs.HoleState -eq 'PASS') { $R += 'SPARSE_NO_HOLE' }
    if ($g4noEvidence) { $ctx['G4NoEvidence'] = $true }

    # ---- C3 holder: cannot distinguish reader from writer (bidirectional sharing) ---
    if ($held) {
        $R += ('HOLDER_' + [int]$obs.NoWriterErr)
        if ($ctx.HolderFailRounds -lt $ctx.HolderMaxRounds) { return New-Decision 'WAIT' $R $obs }
        $R += 'HOLDER_TIMEOUT'
    }

    # ---- C8 settledness, filesystem time as the base (never event-arrival time) -----
    $ageMs = Get-AgeMillis -NowMs $ctx.NowMs -Ms ([long]$obs.LwtMs)
    if (($null -ne $ctx.Prev) -and ([long]$ctx.Prev.Eof -ne [long]$obs.Eof)) {
        $R += 'LEN_MOVING'; return New-Decision 'WAIT' $R $obs
    }
    if ($ageMs -ge 0 -and $ageMs -lt $ctx.SettleWindowMs) {
        $R += ('UNSETTLED_' + [int]($ageMs / 1000)); return New-Decision 'WAIT' $R $obs
    }

    # ---- C6 external expectation (L2) ----------------------------------------------
    $declaredDone = $false
    if ($ctx.Level -ge 2 -and $ctx.Expect) {
        $st = [int]$ctx.Expect.Status
        if ($st -eq 8 -and [long]$obs.Eof -eq [long]$ctx.Expect.ResourceSize -and [long]$obs.Eof -eq [long]$ctx.Expect.ValidSize) {
            $declaredDone = $true; $R += 'DB_STATUS8_SIZE_MATCH'
        } elseif ([long]$obs.Eof -ne [long]$ctx.Expect.ResourceSize) {
            $R += ('SIZE_MISMATCH_' + [long]([long]$ctx.Expect.ResourceSize - [long]$obs.Eof))
            return New-Decision 'WAIT' $R $obs
        } else {
            $R += ('DB_STATUS' + $st); return New-Decision 'WAIT' $R $obs
        }
    } else { $R += 'EXPECT_UNKNOWN' }

    # ---- C7 provenance: context only, never a licence to upgrade --------------------
    #      EverGrew comes from state.json history for this (vol,fileId): the tool saw the
    #      length change at some point. Prev is only the immediately previous round, used
    #      above for LEN_MOVING. Neither of them is proof of completion.
    if ([bool]$ctx.EverGrew) { $R += 'GROWTH_WITNESSED' } else { $R += 'NO_GROWTH_WITNESS' }
    # RULING B (lead, gen-2 batch): a rename CLAIM must arrive as the six-field witness,
    # never as one bit. Measured by the verification layer on THIS function: hollow 4 MiB +
    # EverGrew=$true produced the SAME decision and the SAME reason codes for the bare bool,
    # for a struct lying about DerivedFinal / LengthMatch / AppearedThisRound, and for the
    # string yes. Six fields were never read, and "bool => refuse" did not throw either.
    # A claim collapsed into one bit has already thrown away everything that could have
    # contradicted it, so the shape is refused at the boundary, not reinterpreted here.
    $witness = Resolve-XldRenameWitness -Ctx $ctx -FinalPath ('' + $obs.Path)
    $witnessClaimed = ($null -ne $witness)
    if ($witnessClaimed -and -not [bool]$witness.Ok) { $R += ('RENAME_CLAIM_REJECTED:' + ('' + $witness.Code)) }
    if ($witnessClaimed -and [bool]$witness.Ok) {
        if ($capVol) {
            # The runner saw a path-level rename. On this volume no file identity exists to have
            # survived it, so this is NOT G7 and must not share G7's label.
            $R += ('RENAME_NO_IDENTITY_ON_VOL_' + $volCap)
        } else { $R += 'RENAME_WITNESSED' }
    }

    # ---- G4 fifth exemption: G4_NA_PREALLOC (lead (1), same lever as blocker 3) ------------------
    #      eof == alloc (hole <= 0) on a NON-sparse file this tool never saw grow is NOT evidence of
    #      completeness: it is exactly the reading a non-sparse preallocation gives before a single
    #      byte has been written (RT-13, measured on this box). There, hole=0 means "the instrument
    #      cannot see", not "there is nothing to see" -- that is rule 11, applied to a byte count.
    #      Structurally identical to the four exemptions we already accept (COMPRESSED / OFFLINE /
    #      ENCRYPTED / REPARSE); the fifth trigger is the file's SHAPE plus our own witness history,
    #      not a volume attribute, so it is computed here and not in the native probe.
    #      Effect: a witnessed rename alone no longer grants BACKUP; verified may only come from the
    #      declaration leg (G5 / G8). Cost booked honestly: a genuinely final file that the tool
    #      started watching after its last byte lands here too -- as BACKUP_UNVERIFIED, i.e. still
    #      copied, still usable, visibly unverified, NEVER "not backed up". Born-at-final-size files
    #      cannot be told apart from this by observation alone; sec13 item 17 measures that exposure.
    $preallocBlind = ($obs.HoleState -eq 'PASS' -and [long]$obs.Hole -le 0 -and [long]$obs.Eof -ge 65536 -and
        -not [bool]$obs.Sparse -and -not [bool]$ctx.EverGrew)
    if ($preallocBlind) { $R += 'G4_NA_PREALLOC' }

    # ---- C11 group / manifest ------------------------------------------------------
    if ([bool]$ctx.IsManifest -and -not [bool]$ctx.GroupReady) {
        $R += 'GROUP_INCOMPLETE'; return New-Decision 'WAIT' $R $obs
    }

    # ---- verdict -------------------------------------------------------------------
    # `verified` (== BACKUP) requires a completion ACT. G4's PASS branch can never supply it:
    # "no unallocated bytes" is equally true of an 8 MiB exFAT file with nothing written and of
    # a truncated-then-regrown tail.
    # Identity: the primary key is (VolumeSerial, FileId128). At L0 we have neither, so the
    # decision degrades to a path-keyed identity -- we still honour a witnessed rename, but we
    # label it IDENTITY_WEAK so nobody treats "same path" as "same object" across a snapshot
    # rollback, a rebuilt volume, or another machine (spec: identity hit => mandatory re-hash).
    $identityWeak = (-not [bool]$obs.HasFileId)
    if ($identityWeak) { $R += 'IDENTITY_WEAK' }

    # Volume-capability ceiling (lead's independent repro, 2026-10-22). On a KNOWN non-NTFS
    # volume three things vanish together, not one:
    #   1. the allocation sign -- exFAT has no sparse runs, alloc >= eof always, so "hole > 0"
    #      is unreachable and the criterion's failure direction INVERTS to "always complete";
    #   2. the strong identity key -- FileIdInfo(18) returns ERROR_INVALID_PARAMETER (87)
    #      there, and keeps returning it after a rename, so no key can be built;
    #   3. therefore G7 -- a rename witness is defined as "one file identity passing through a
    #      rename event", which needs (2), so the witness cannot be constructed either.
    # That is a property of the volume, not of configuration, version or privilege. So the
    # strongest honest state on such a volume is BACKUP_UNVERIFIED: we STILL copy it (a miss is
    # worse than a missing badge) but we never print a verified claim there.
    # UNRESOLVED / ERR<n> are NOT capped: unknown is not known-bad; those cases already carry
    # G4_NA_VOLUME_<x> and land in needs-attention.
    $volCap = ('' + $fs)
    $capVol = ($volCap -ne 'NTFS' -and $volCap -ne 'UNRESOLVED' -and $volCap -notmatch '^ERR')
    if ($capVol) { $R += ('CAPABILITY_VOLUME_' + $volCap) }

    if ($declaredDone) {
        if ($capVol) { $R += ('VERIFIED_CAPPED_BY_VOLUME:' + $volCap); return New-Decision 'BACKUP_UNVERIFIED' $R $obs }
        return New-Decision 'BACKUP' $R $obs
    }
    if ($witnessClaimed -and [bool]$witness.Ok) {
        if ($staleSidecar) { $R += 'RENAME_VS_STALE_SIDECAR' }
        if ($preallocBlind) {
            # The rename witness stays TRUE as a fact (we did see it) but it loses its licensing
            # power on this shape, so the reason list says both: what we saw, and why it is not enough.
            if ($capVol) { $R += ('VERIFIED_CAPPED_BY_VOLUME:' + $volCap); return New-Decision 'BACKUP_UNVERIFIED' $R $obs }
            $R += 'VERIFIED_CAPPED_BY_PREALLOC'
            return New-Decision 'BACKUP_UNVERIFIED' $R $obs
        }
        if ($capVol) {
            # C7 already replaced the label: on this volume a path-level rename is not G7.
            # Do not silently grant on it anyway.
            $R += ('VERIFIED_CAPPED_BY_VOLUME:' + $volCap)
            return New-Decision 'BACKUP_UNVERIFIED' $R $obs
        }
        return New-Decision 'BACKUP' $R $obs
    }
    $R += 'NO_COMPLETION_ACT'
    return New-Decision 'BACKUP_UNVERIFIED' $R $obs
}

function Get-XldFsType {
    <#  Volume filesystem name for a path, MEMOISED PER DIRECTORY -- this is a hard rule, not
        an optimisation. Measured on 118 files: resolving per FILE costs 1.517 ms/file
        (100k = 152 s, 7.2x the entire native observation path); resolving once per DIRECTORY
        costs 0.022 ms/file (100k = 2 s). A cache keyed by volume ROOT still calls
        GetVolumePathNameW per file, which is the mistake that makes the cache worth nothing.
        Key = the file's parent directory string, so interleaved volumes cannot contaminate
        each other (asserted by selftest). Unknown is 'UNRESOLVED' -> caller treats G4 as
        NOT APPLICABLE: fail closed, never "assumed NTFS".  #>
    param([string]$Path, [hashtable]$Ctx)
    if ($Ctx.ContainsKey('FsByDir')) {
        $dirKey = ('' + (Split-Path -Path $Path -Parent))
        if ($Ctx['FsByDir'].ContainsKey($dirKey)) { return $Ctx['FsByDir'][$dirKey] }
        $fs = 'UNRESOLVED'
        if ($script:XldNative) {
            $fs = '' + [XldbProbe]::VolumeFs((ConvertTo-ExtendedPath $Path))
        } else {
            $dl = '' + (Split-Path -Path $Path -Qualifier)
            if ($dl) {
                $v = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='" + $dl + "'") -ErrorAction SilentlyContinue)
                if (@($v).Count -ge 1 -and $v[0].FileSystem) { $fs = '' + $v[0].FileSystem }
            }
        }
        $Ctx['FsByDir'][$dirKey] = $fs
        $Ctx['FsLookups'] = [int]$Ctx['FsLookups'] + 1
        return $fs
    }
    return 'UNRESOLVED'
}

function Get-AgeMinutes {
    param([long]$NowMs, [long]$Ms)
    if ($Ms -le 0 -or $NowMs -le 0) { return -1 }
    return [long](($NowMs - $Ms) / 60000)
}

function Get-AgeMillis {
    param([long]$NowMs, [long]$Ms)
    if ($Ms -le 0 -or $NowMs -le 0) { return -1 }
    return [long]($NowMs - $Ms)
}

function Get-HoleBucket {
    param([long]$Hole)
    if ($Hole -le 65536)    { return '64K' }
    if ($Hole -le 1048576)  { return '1M' }
    if ($Hole -le 33554432) { return '32M' }
    return 'BIG'
}

# ---------------------------------------------------------------------------------------------
# Test-XldNotShrunk -- rule 18 applied to OUR OWN deliverables.
#   A destructive write does not look destructive: the file still exists, still has a BOM, still
#   "loads". This happened for real in this session: a loop variable named `$l` iterating a
#   collection named `$L` -- PowerShell names are case-INSENSITIVE, so the loop variable and the
#   collection were the SAME slot; after the loop `$L` held the last STRING, the rebuilt list got
#   one element, and the 163,299-byte spec was replaced by a 5-byte file (BOM + CRLF). Recovery
#   worked only because A77 keeps a pinned copy. Existence is not size, and a size check must be
#   able to tell "one side is missing" from "the file shrank" (rule 17: distinct codes).
#   The ratio here is a SAFETY FLOOR, not a cost claim; both absolute byte counts are always
#   returned so the caller prints them (calendar-vs-ratio law).
function Test-XldNotShrunk {
    param([string]$LivePath, [string]$PinPath, [double]$MinRatio = 0.9)
    if (-not (Test-Path -LiteralPath $LivePath)) {
        return [pscustomobject]@{ Ok = $false; Code = 'SIZE_LIVE_MISSING'; Live = -1; Pin = -1; Ratio = -1 }
    }
    if (-not (Test-Path -LiteralPath $PinPath)) {
        return [pscustomobject]@{ Ok = $false; Code = 'SIZE_PIN_MISSING'; Live = -1; Pin = -1; Ratio = -1 }
    }
    $liveLen = ([System.IO.File]::ReadAllBytes($LivePath)).LongLength
    $pinLen = ([System.IO.File]::ReadAllBytes($PinPath)).LongLength
    if ($pinLen -le 0) {
        return [pscustomobject]@{ Ok = $false; Code = 'SIZE_PIN_EMPTY'; Live = $liveLen; Pin = $pinLen; Ratio = -1 }
    }
    $ratio = [double]$liveLen / [double]$pinLen
    $isOk = ($ratio -ge $MinRatio)
    $code = 'SIZE_OK'
    if (-not $isOk) { $code = ('SIZE_SHRUNK_RATIO_' + ([math]::Round($ratio, 6))) }
    return [pscustomobject]@{ Ok = $isOk; Code = $code; Live = $liveLen; Pin = $pinLen; Ratio = $ratio }
}
# $XldTempSuffixAuthority is the criterion's own list of what a downloader temp name looks like.
# It existed twice before: New-ScanContext built the default table from one literal while
# Resolve-XldRenameWitness matched a SECOND, hand-typed regex that had already drifted (it lacked
# the engine's real .xltd and .tdtmp, and carried a .tdp nobody ever observed). Two lists for one
# fact is the display-predicate / counter-predicate defect inside a single file: the stricter copy
# silently made the rename leg unreachable for every real file -- measured by the distribution
# layer as TEMP_NAME_NOT_A_TEMP on a correct six-field witness for movie.dat.xltd -> movie.dat.
# Measured on this install: Thunder uses .xltd / .td (row A24 confirms via HKCR); .tdtmp / .!ut /
# .part / .crdownload / .tmp / .downloading are the wider observed downloader family.
$XldTempSuffixAuthority = @('.xltd', '.td', '.tdtmp', '.downloading', '.!ut', '.part', '.crdownload', '.tmp')

function New-ScanContext {
    param([int]$Level = 1, [string[]]$Skip = @(), [hashtable]$Temp = $null,
          [long]$SettleWindowMs = 20000, [long]$NowMs = 0, [hashtable]$ContainerExt = $null, [double]$PairingBoundMs = 600000)
    if (-not $Temp) {
        $Temp = @{}
        foreach ($e in $script:XldTempSuffixAuthority) { $Temp[$e] = 1 }
    }
    if (-not $ContainerExt) { $ContainerExt = Get-XldContainerExt }
        $now = $NowMs
    if ($now -le 0) { $now = Get-XldNowMs }
    @{
        Level = $Level; TempSuffixes = $Temp; SkipDirs = $Skip
        Sidecar = $false; SidecarLwtMs = [long]0; NowMs = [long]$now
        SettleWindowMs = $SettleWindowMs; SidecarTTLMin = 60; PairingBoundMs = $PairingBoundMs
        HolderFailRounds = 0; HolderMaxRounds = 3
        HoleFailRounds = 0;  HoleMaxRounds = 5
        Prev = $null; Expect = $null; EverGrew = $false
        IsManifest = $false; GroupReady = $false; RenamedFromTemp = $false; RenameWitness = $null
        # G4 policy inputs. FsByDir is keyed by the DIRECTORY, never by the volume root.
        FsByDir = @{}; FsLookups = 0; G4NoEvidence = $false
        ContainerExt = $ContainerExt
    }
}

function Get-XldContainerExt {
    <#  The "hole may be the final shape" class: sparse-format disk images and containers.
        For these, G4 gives no verdict in either direction -- only review (spec C4 exemption 4;
        镜像/容器类). Keep the list explicit and auditable rather than inferring from MIME.  #>
    param([string[]]$Extra = @())
    $h = @{}
    foreach ($e in @('.vhd', '.vhdx', '.vmdk', '.iso', '.img', '.raw', '.qcow2', '.vdi',
                     '.sparsebundle', '.sparseimage', '.wim', '.esd', '.ape') + $Extra) { $h[$e] = 1 }
    return $h
}

# ---------------------------------------------------------------------------
# Capability probe. The ladder must PROVE the tier it is on, every round:
# WDAC/AppLocker/GPO can engage mid-run, and a silently weakened judgement is
# exactly the failure this whole spec exists to prevent.
# $ProbePath defaults to this script itself: a file we own, read-only opened, plus
# one share-0x05 write-intent probe that performs no write.
# ---------------------------------------------------------------------------
function Get-XldTempSuffix {
    param([string[]]$Candidates = @('.xltd', '.td', '.tdtmp', '.downloading'))
    # (registry discovery probes a SUBSET of the authority; the gate asserts subset-of-authority)
    # Validate rather than guess. HKCR maps Thunder's temp extensions to a Xunlei ProgID
    # whose icon is XLTempFile.ico (observed: .xltd/.td -> Xunlei.TDFile.6). A user's own
    # .tmp never maps here, which is what stops C1 from becoming RT-10's blanket skip.
    $out = @{}
    foreach ($e in $Candidates) {
        $hit = $false; $progid = ''
        try {
            $k = "Registry::HKEY_CLASSES_ROOT\$e"   # the HKCR: PSDrive is NOT guaranteed to exist (observed absent here)
            if (Test-Path -LiteralPath $k) {
                $progid = '' + (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).'(default)'
                if ($progid -match '(?i)xunlei') {
                    $ik = "Registry::HKEY_CLASSES_ROOT\$progid\DefaultIcon"
                    if (Test-Path -LiteralPath $ik) {
                        $ico = '' + (Get-ItemProperty -LiteralPath $ik -ErrorAction SilentlyContinue).'(default)'
                        if ($ico -match '(?i)XLTempFile') { $hit = $true }
                    } else { $hit = $true }
                }
            }
        } catch { }
        $out[$e] = [pscustomobject]@{ Ext = $e; Confirmed = $hit; ProgId = $progid }
    }
    return $out
}

function Get-XldSkipDirs {
    param([string]$ConfigPath)
    # Thunder's own config.json declares the cache dir (key ThunderPanPlugin.VODCachePath).
    # Read-only. If the key moves this returns nothing and --skip-dir must be set by hand.
    if (-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath)) { return @() }
    try {
        # Get-Content, not [IO.File]:: static calls are blocked under CLM.
        $txt = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
        $j = $txt | ConvertFrom-Json
        $dirs = @()
        foreach ($p in @('ThunderPanPlugin.VODCachePath', 'ThunderPanPlugin.SavePath', 'Downloader.SavePath')) {
            $v = $j; $ok = $true
            foreach ($seg in $p.Split('.')) {
                if (@($v.PSObject.Properties.Name) -contains $seg) { $v = $v.$seg } else { $ok = $false; break }
            }
            if ($ok -and ($v -is [string]) -and $v) { $dirs += $v }
        }
        return @($dirs | Where-Object { $_ } | Select-Object -Unique)
    } catch { return @() }
}

function Get-XldVolumeCapability {
    <#  ONE call, reused by doctor / status / install-time warning. Never reimplement this in
        the runner: the rules below are measured, not assumed.
        Given any path (usually a watch root), report what that VOLUME is able to prove:
          Fs               NTFS | exFAT | FAT32 | ... | UNRESOLVED | ERR<n>
          HoleSign         reachable | UNREACHABLE     (non-NTFS: alloc >= eof always, so the
                          "hole > 0" test can never fire and its failure direction INVERTS)
          Identity         strong | weak(<why>) | no-file-to-probe
                                                   (FileIdInfo(18) -> err=87 on exFAT, before
                                                    AND after a rename, so no key can be built)
          VerifiedCeiling  BACKUP | BACKUP_UNVERIFIED (the strongest state a file on this volume
                          can ever reach; non-NTFS caps it because identity -- and therefore a
                          G7 rename witness -- is unobtainable there)
        Read-only by construction: it opens at most one existing file in the root, writes
        nothing, and never needs admin.                                                  #>
    param([string]$Path, [hashtable]$Ctx)
    $fs = '' + (Get-XldFsType -Path $Path -Ctx $Ctx)
    $hole = 'UNREACHABLE'
    if ($fs -eq 'NTFS') { $hole = 'reachable' }
    $id = 'no-file-to-probe'; $why = ''
    $target = ''
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item) {
        if ($item.PSIsContainer) {
            # -First 1 short-circuits the enumeration, so recursing past a root that holds only
            # directories is still one entry, not a walk. Without this, such a root would answer
            # "no-file-to-probe" and the runner would be tempted to treat unknown as capability.
            $fe = @(Get-ChildItem -LiteralPath $Path -File -Force -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1)
            if (@($fe).Count -ge 1) { $target = '' + $fe[0].FullName }
        } else { $target = '' + $Path }
    }
    if ($target) {
        $o = Get-FileObs -Path $target
        if ([bool]$o.HasFileId) { $id = 'strong' }
        else { $id = 'weak'; $why = ('' + $o.FileIdHex) }
    }
    $ceiling = 'BACKUP'
    # Known non-NTFS caps; UNRESOLVED / ERR<n> do not (unknown is not known-bad), matching
    # the classifier's $capVol rule. The two must never disagree -- selftest asserts shape.
    if ($fs -ne 'NTFS' -and $fs -ne 'UNRESOLVED' -and $fs -notmatch '^ERR') { $ceiling = 'BACKUP_UNVERIFIED' }
    [pscustomobject]@{ Path = $Path; Fs = $fs; HoleSign = $hole; Identity = $id;
        IdentityWhy = $why; VerifiedCeiling = $ceiling; ProbedFile = $target }
}


function Get-Capability {
    param([string]$ProbePath = $script:XldSelf, [long]$NowMs = 0, [string]$ProbeDir = '', [string[]]$WatchRoot = @())
    $r = [ordered]@{}
    $r.ps   = '' + $PSVersionTable.PSVersion
    $r.lang = '' + $ExecutionContext.SessionState.LanguageMode
    $t = 'XldbProbe' -as [type]
    $r.addType = [bool]($t -ne $null)
    $level = 0
    $probes = @{}
    $r.taskdb = 'n/a'; $r.cfg = 'n/a'; $r.clock_delta_ms = [long]0
    $r.ioctl = 'NOT_PROBED(pass -ProbeDir <dir>; a skipped guard must never look like a passed one)'
    if ($r.addType -and $ProbePath -and (Test-Path -LiteralPath $ProbePath)) {
        $level = 1
        $full = (Resolve-Path -LiteralPath $ProbePath).ProviderPath
        $o = Get-FileObs -Path $full
        $probes.fsi     = $(if ($o.Eof -ge 0 -and $o.HoleState -ne '') { 'OK' } else { 'BROKEN' })
        $probes.hole    = $(if ([bool]$o.FsiOk) { 'OK' } else { 'BROKEN(trap#7)' })
        $probes.delpend = $(if ([int]$o.DelPend -ge 0) { 'OK' } else { 'BROKEN' })   # DelPend, NOT DeletePending: the object surface renames it, and a misspelled member is silently $null (trap #9)
        $probes.fileid  = $(if ($o.HasFileId) { 'OK(cls18)' } else { 'BROKEN(cls18)' })
        $probes.holder  = $(if ($o.NoWriterErr -in @(0, 5, 32, 33)) { 'OK' } else { "BROKEN($($o.NoWriterErr))" })
        $probes.mask    = 'obs=0x07 probe=0x05 excl=FORBIDDEN'
        # G4 exemption census on the probe file itself, so "the exemptions are wired" is proven
        # on every run instead of asserted in a document.
        $fsc = New-ScanContext -Level 1
        $probes.fstype  = ('' + (Get-XldFsType -Path $full -Ctx $fsc))
        $na = @()
        if ($o.Compressed) { $na += 'COMPRESSED' }
        if ($o.Encrypted)  { $na += 'ENCRYPTED' }
        if ($o.Offline)    { $na += 'OFFLINE' }
        if ($o.Reparse)    { $na += 'REPARSE' }
        if ('' + $probes.fstype -ne 'NTFS') { $na += ('VOLUME:' + $probes.fstype) }
        if ([long]$o.Eof -lt 65536) { $na += 'TINY' }
        $probes.g4na = $(if (@($na).Count) { ($na -join '+') } else { 'none(applicable)' })
        $psNow = [long]((New-TimeSpan -Start ([datetime]'1970-01-01') -End (Get-Date).ToUniversalTime()).TotalMilliseconds)
        # Plain locals, explicit casts, and a PARENTHESISED call. The delta is printed inside the
        # status string: a self-proof line that says BROKEN without a number is un diagnosable.
        $deltaMs = [long](Get-XldNowMs) - [long]$psNow
        $r.clock_delta_ms = $deltaMs
        $absDelta = [long](Get-XldAbs -V $deltaMs)
        $probes.clock = $(if ($absDelta -lt 5000) { ('OK({0}ms)' -f $deltaMs) } else { ('BROKEN(trap#6 delta={0}ms)' -f $deltaMs) })
        $r.cfg = 'probe-with-Get-XldTempSuffix'
        $r.taskdb = 'UNAVAILABLE(no sqlite reader wired in here)'
        if ($ProbeDir -and (Test-Path -LiteralPath $ProbeDir)) {
            # HARD RULE 12: record every ioctl's real return value. An error here is a question
            # about our control code, not about the machine.
            $lines = @()
            foreach ($w in 0, 1, 2, 3, 4) {
                $fp = Join-Path $ProbeDir ("zz_doctor_ioctl_{0}.bin" -f $w)
                $lines += ('w{0}:{1}' -f $w, ([XldbProbe]::IoctlLaw($fp, $w)))
                Remove-Item -LiteralPath $fp -Force -ErrorAction SilentlyContinue
            }
            $r.ioctl = ($lines -join ' ')
        }
    }
    if (@($WatchRoot).Count -gt 0) {
        # Per-ROOT capability, never a single "this machine supports X" line: the answer is a
        # property of the volume the artifacts live on, and one user can have NTFS and exFAT
        # roots at the same time (USB sticks and SD cards are exFAT by default).
        $capCtx = New-ScanContext -Level 1
        $capLines = @()
        foreach ($wr in @($WatchRoot)) {
            $c = Get-XldVolumeCapability -Path $wr -Ctx $capCtx
            $capLines += ('{0} fs={1} hole-sign={2} strong-identity={3} verified-ceiling={4}' -f `
                $wr, $c.Fs, $c.HoleSign, $c.Identity, $c.VerifiedCeiling)
        }
        $r.volumes = $capLines
    }
    $r.level = $level
    $r.probes = $probes
    $deg = @()
    if ($level -lt 1) { $deg = @('C4.hole', 'C3.holder', 'C5.deletePending', 'C13.fileId') }
    if ($level -lt 2) { $deg += 'C6.expect' }
    $r.degraded = $deg
    $r.claim = $(if ($level -ge 2) {
        'BACKUP(verified) needs TaskDb Status=8 with eof==ResourceSize==ValidSize, or a witnessed temp->final rename.'
    } elseif ($level -eq 1) {
        'preallocation detected via ABSOLUTE hole bytes (sign only, 1 cluster = 4096 B resolution); paused-with-final-name NOT decidable without TaskDb -> BACKUP_UNVERIFIED.'
    } else {
        'L0: completion is UNDECIDABLE for paused-with-final-name files. BACKUP is claimed only for files whose temp->final rename this tool personally witnessed. Everything else is BACKUP_UNVERIFIED and listed.'
    })
    return [pscustomobject]$r
}

function Invoke-Doctor {
    param([string]$ProbePath = $script:XldSelf, [string]$ProbeDir = '', [string[]]$WatchRoot = @())
    $c = Get-Capability -ProbePath $ProbePath -ProbeDir $ProbeDir -WatchRoot $WatchRoot
    $degr = $(if (@($c.degraded).Count) { (@($c.degraded) -join ',') } else { 'none' })
    "doctor level=$($c.level) ps=$($c.ps) lang=$($c.lang)"
    if ($c.level -ge 1) {
        $p = $c.probes
        "       probes fsi=$($p.fsi) hole=$($p.hole) delpend=$($p.delpend) fileid=$($p.fileid) holder=$($p.holder) clock=$($p.clock) mask=$($p.mask)"
        "       g4      fstype=$($p.fstype) exemptions=$($p.g4na)   # G4 must be told it is blind, not told it passed"
        "       l2      taskdb=$($c.taskdb) cfg=$($c.cfg)"
    }
    "       ioctl   $($c.ioctl)"
    if (@($c.volumes).Count -gt 0) {
        # capability is per VOLUME, never "this machine supports": a user can hold an NTFS root
        # and an exFAT root in the same config, and the exFAT one can never be verified.
        foreach ($vl in @($c.volumes)) { "       volume  $vl" }
        "               # verified-ceiling=BACKUP_UNVERIFIED means every artifact on that root is capped, by the volume, not by config/version/privilege"
    }
    "       degraded [$degr]"
    "       claim: $($c.claim)"
    $c | ConvertTo-Json -Compress -Depth 4
    return $c
}

function Get-XldPipeWidth {
    # Structure-checker primitive: count real column separators in one markdown table row.
    # Escaped pipes (\|) are content, not separators. Written as a char loop on purpose:
    # @(... | Measure-Object).Count returns the Count of the MeasureInfo ARRAY (always 1),
    # which silently made every width equal 1 and every table "consistent" for five rounds.
    param([string]$Line)
    $s = ('' + $Line).Trim().Replace('\|', '~')
    $n = 0
    foreach ($ch in $s.ToCharArray()) { if ([int]$ch -eq 124) { $n = $n + 1 } }
    return $n
}

function Get-XldSpecAudit {
    # Audit a markdown file's tables. Rows may be separated by blank lines (this spec does that in
    # the pit table), so a group = consecutive table rows with only blank lines between them, ended
    # by the first non-blank non-table line. Returns real widths, mismatching groups, and the
    # encoding shape so a reader cannot mistake a UTF-16 file for a clean UTF-8 one.
    param([string]$Path, [string]$TrapHeaderPattern = '^\| # \| ', [string]$TrapStopPattern = '^元规则')
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $bom = ($bytes.Length -ge 3 -and [int]$bytes[0] -eq 239 -and [int]$bytes[1] -eq 187 -and [int]$bytes[2] -eq 191)
    $utf16 = ($bytes.Length -ge 2 -and (([int]$bytes[0] -eq 255 -and [int]$bytes[1] -eq 254) -or ([int]$bytes[0] -eq 254 -and [int]$bytes[1] -eq 253)))
    $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ($bom) { $txt = $txt.Substring(1) }
    $lines = @($txt -replace "`r`n", "`n") -split "`n"
    $groups = @(); $cur = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $t = ('' + $lines[$i]).Trim()
        if ($t.StartsWith('|')) { $cur += , @(((Get-XldPipeWidth $t)), $i); continue }
        if ($t -eq '') { continue }
        if (@($cur).Count -gt 0) { $groups += ,@($cur); $cur = @() }
    }
    if (@($cur).Count -gt 0) { $groups += ,@($cur) }
    $bad = @()
    foreach ($g in $groups) {
        $w = @($g | ForEach-Object { $_[0] } | Sort-Object -Unique)
        if (@($w).Count -gt 1 -and @($g).Count -gt 1) { $bad += ('L' + ($g[0][1] + 1) + ' widths=' + (@($g | ForEach-Object { '' + $_[0] }) -join ',')) }
    }
    $bare = @($lines | Where-Object { ('' + $_).Trim() -eq '?' }).Count
    $ti = -1; $tj = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($ti -lt 0 -and ('' + $lines[$i]) -match $TrapHeaderPattern) { $ti = $i } }
    for ($i = $ti + 1; $i -lt $lines.Count; $i++) { if (('' + $lines[$i]) -match $TrapStopPattern) { $tj = $i; break } }
    $tnum = @(); $tw = @()
    if ($ti -ge 0 -and $tj -gt $ti) {
        for ($i = $ti; $i -lt $tj; $i++) {
            $t = ('' + $lines[$i]).TrimStart()
            if (-not $t.StartsWith('|')) { continue }
            $p = @($t.Substring(1).Trim().Split('|'))
            $c = ('' + $p[0]).Trim()
            if ($c -match '^\d+$') { $tnum += [int]$c; $tw += (Get-XldPipeWidth $t) }
        }
    }
    $seqOk = ($tnum.Count -gt 0)
    for ($i = 0; $i -lt $tnum.Count; $i++) { if ($tnum[$i] -ne ($i + 1)) { $seqOk = $false } }
    [pscustomobject]@{
        Bytes = $bytes.Length; Bom = $bom; Utf16 = $utf16; Lines = $lines.Count
        Groups = @($groups).Count; Mismatching = @($bad); BareQuestionLines = $bare
        TrapRows = @($tnum).Count; TrapSeqOk = $seqOk; TrapLast = @($tnum | Select-Object -Last 1)
        TrapWidthsUnique = (@($tw | Sort-Object -Unique) -join '/')
    }
}

function Get-XldPairing {
    # Rule 28 landing: a pairing verdict is a TRIPLE, never "the nearest one". GapMs is absolute
    # milliseconds between the two mtimes; over the bound the pair does not exist at all, so the
    # caller must not compute any ratio from it. Observed failure this was written for: an orphan
    # txt paired with a file 225,128,823 ms (2.6 days) away and a ratio was still printed.
    param([double]$GapMs, [double]$BoundMs = 600000.0, [string]$Nearest = 'ok')
    $decision = 'none'
    if ($GapMs -lt 0) { $decision = 'none' }
    elseif ($GapMs -le $BoundMs) { $decision = $Nearest }
    [pscustomobject]@{ GapMs = $GapMs; BoundMs = $BoundMs; Decision = $decision
        Code = ('PAIRING_' + $decision.ToUpper() + '_GAP_' + ([long]$GapMs) + 'MS_BOUND_' + ([long]$BoundMs) + 'MS') }
}
function Test-XldRatioAllowed {
    # Enforcement, not prose (trap #28 / rule 16): a size/progress ratio may only be computed when
    # the pairing itself is a real pair. Decision = none/ambiguous => the ratio is REFUSED, because
    # an orphan paired with something 2.6 days away still produced a printed ratio once.
    param($Pairing)
    $dec = '' + $Pairing.Decision
    if ($dec -eq 'ok') {
        return [pscustomobject]@{ Ok = $true; Blocking = ''; GapMs = $Pairing.GapMs; BoundMs = $Pairing.BoundMs; Decision = $dec }
    }
    return [pscustomobject]@{ Ok = $false
        Blocking = ('RATIO-REFUSED_BY_PAIRING_' + $dec.ToUpper() + '_GAP_' + ([long]$Pairing.GapMs) + 'MS_BOUND_' + ([long]$Pairing.BoundMs) + 'MS')
        GapMs = $Pairing.GapMs; BoundMs = $Pairing.BoundMs; Decision = $dec }
}


function Format-XldPad2 {
    # trap #35 (lead sec? measured on this box, PS 5.1.19041.7725): the format operator does NOT
    # reject a STRING. '{0:D2}' -f '7' returns '7' -- silently, no exception, wrong width -- and
    # '{0:D2}' -f 'x' returns 'x'. The throwing shape is the CAST ([int]'x' -> RuntimeException).
    # So "Error formatting a string" and "silently unpadded" are the SAME root cause seen from two
    # hosts, and neither outcome is what the author of the format string meant.
    # Deterministic contract: integers and integer-looking strings come out exactly 2 chars wide,
    # anything else comes out as an explicit code. Never throws, never passes a string through.
    param($Value)
    $s = '' + $Value
    $n = 0
    if ([int]::TryParse($s.Trim(), [ref]$n)) {
        if ($n -lt 0)  { return [pscustomobject]@{ Text = ('-' + [Math]::Abs($n)); Padded = $false; Code = 'PADDING_NEGATIVE'; Input = $s } }
        if ($n -gt 99) { return [pscustomobject]@{ Text = ('' + $n);             Padded = $false; Code = 'PADDING_OVERFLOW';  Input = $s } }
        $t = ('' + $n)
        if ($t.Length -eq 1) { $t = '0' + $t }
        return [pscustomobject]@{ Text = $t; Padded = ($t.Length -eq 2); Code = 'PADDING_OK'; Input = $s }
    }

    return [pscustomobject]@{ Text = '??'; Padded = $false; Code = 'PADDING_NOT_A_NUMBER'; Input = $s }
}
