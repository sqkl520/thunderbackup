# tbsm-store.ps1 -- external storage layer for the Thunder auto-backup tool (PROTOTYPE).
#
# TARGET RUNTIME: Windows PowerShell 5.1 (Desktop, CLR4) + embedded C# via Add-Type.
#   This machine has NO .NET SDK, NO pwsh7, NO Go/Rust, and a broken WindowsApps python
#   stub, so PS 5.1 + Add-Type is the only stack that actually runs here and on the
#   distribution target. Verified: PSVersion 5.1.19041.7725, LanguageMode=FullLanguage.
#   C# is held at language level 5: no string interpolation, no tuples, no out-var.
#
# PS 5.1 TRAPS THIS FILE OBEYS (each one is a silent global failure, not a compile error):
#   1. BOM-less .ps1 is decoded as ANSI by 5.1 -> every non-ASCII literal silently
#      mojibakes. If a watched path literal corrupted, the tool would monitor a
#      nonexistent directory and back up 0 files with 0 errors. Rule: this file is
#      ASCII-only; Assert-TbsmEncoding() is called at module load (defined near the end of
#      this file) and throws if non-ASCII bytes appear without a BOM, so the rule is enforced
#      rather than merely stated. The sentence above this line used to claim that guard in the
#      present tense with no implementation behind it -- measured once as 'Assert-TbsmEncoding'
#      appearing exactly once, as prose, and 'function Assert' appearing zero times.
#      Any Chinese
#      that must appear arrives as DATA read with [Text.Encoding]::UTF8 (config, paths),
#      never as a source literal.
#   2. @($someGenericList) throws ArgumentException "Argument types do not match" in 5.1
#      for both empty and non-empty Generic.List. Rule: .ToArray() or [object[]] cast only.
#   3. [ordered]@{} pins each key's type to its INITIAL value, so a later assignment of a
#      different kind throws the same ArgumentException. Rule: plain @{} hashtable, or
#      build [pscustomobject]@{...} once at the end.
#
# READ-ONLY CONTRACT: nothing in this file writes to a Thunder directory. The store is
# always an explicit, separate root; Restore-TbsmVersion hard-refuses targets inside the
# install root / watched source roots unless the operator overrides twice (see C-section).
#
# EVERY design decision below is annotated in storage-spec.md as [OBSERVED] / [INFERRED]
# / [TO VERIFY] with the experiment that closes it.

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# The two Thunder paths a restore must never write into. Built from CODE POINTS, not
# source literals: "xunlei" = U+8FC5 U+96F7, "xiazai" = U+4E0B U+8F7D. A BOM-less .ps1 is decoded as ANSI by 5.1,
# which would turn the literal into mojibake (RT-22) and silently make the guard compare
# against a path that does not exist -- the most dangerous possible failure of a guard.
# This file is therefore kept pure ASCII, and Assert-TbsmSourceEncoding verifies it.
function Get-TbsmXunleiWord { ([string][char]0x8FC5) + [string][char]0x96F7 }            # xun-lei
function Get-TbsmDownloadWord { ([string][char]0x4E0B) + [string][char]0x8F7D }          # xia-zai
function Get-TbsmDownloadRootLiteral {
    param([string]$SystemDrive = 'C')
    ($SystemDrive + ':\' + (Get-TbsmXunleiWord) + (Get-TbsmDownloadWord))                # C:\<xunlei downloads>
}
function Get-TbsmThunderProtectedPaths {
    param([string]$SystemDrive = 'C')
    @('D:\Thunder', (Get-TbsmDownloadRootLiteral $SystemDrive))
}

# ============================================================================
# 1. NATIVE SURFACE
# ============================================================================
# Why P/Invoke instead of [System.IO.File]:
#  * FileShare has no FILE_SHARE_DELETE member, and FILE_SHARE_DELETE (0x4) is exactly
#    what lets us copy a file while Thunder renames/deletes it. Without it our backup
#    handle returns ERROR_ACCESS_DENIED to the downloader (redteam RT-05) -- the tool
#    would actively interfere with the product it is supposed to be invisible to.
#  * GetFileInformationByHandleEx(FileStandardInfo) gives AllocationSize / EndOfFile /
#    NumberOfLinks / DeletePending in one call. GetCompressedFileSizeW is ambiguous:
#    it succeeds and still leaves LastError=203 (RT-23, measured), which mis-classifies
#    healthy files as errors.
#  * FlushFileBuffers is the Win32 fsync: it pushes the file's data AND its metadata to
#    the volume. FileStream.Flush(true) does this too, but calling the primitive by name
#    makes the durability step auditable instead of implicit.
if (-not ('TbsM' -as [type])) {
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public static class TbsM {

    // ---- constants -------------------------------------------------------
    const uint GENERIC_READ    = 0x80000000;
    const uint GENERIC_WRITE   = 0x40000000;
    const uint OPEN_EXISTING   = 3;
    const uint CREATE_ALWAYS   = 2;
    const uint CREATE_NEW      = 1;
    const uint FILE_SHARE_ALL  = 0x00000007;   // READ|WRITE|DELETE
    const uint SEQ_SCAN        = 0x08000000;
    const uint WRITE_THROUGH   = 0x80000000;
    // ---- MoveFileExW flags: HARD RULE, no bare numbers anywhere ------------------
    // Real winbase.h values (verified on this box by the Lead's flag table experiment,
    // and by the ERROR_ALREADY_EXISTS(183) this file produced when 0x2 was mistaken for
    // REPLACE_EXISTING):
    //   0x01 REPLACE_EXISTING  0x02 COPY_ALLOWED      0x04 DELAY_UNTIL_REBOOT
    //   0x08 WRITE_THROUGH     0x10 CREATE_HARDLINK   0x20 FAIL_IF_EXISTS
    // Two publish shapes are legal and nothing else:
    //   MOVE_PUBLISH_NEW (0)   -- the normative blob publish. Target exists => fail 183,
    //                             which the caller reads as "already committed" (dedup).
    //                             Preferred over FAIL_IF_EXISTS: 0 grants nothing, so it
    //                             cannot be weakened by a caller OR-ing extra bits in.
    //   MOVE_REPLACE     (0x1) -- ONLY for index files (heads.json, store.json,
    //                             meta/*.json), which are derived caches with no
    //                             immutability claim.
    // BANNED: 0x04, 0x08, 0x10, 0x20 and any raw integer passed by a caller.
    // 0x04 DELAY_UNTIL_REBOOT is the worst of them: it RETURNS TRUE, DOES NOTHING NOW,
    // and registers a system-wide pending rename in
    //   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
    // i.e. it writes machine state that SURVIVES a reboot. For a tool whose contract is
    // "zero writes outside the store", a successful-looking call that mutates Session
    // Manager is the exact opposite of the promise, and Get-TbsmPendingRenameInventory is
    // the audit that proves we never leave one behind.
    const uint MOVE_REPLACE    = 0x00000001;   // index files only
    const uint MOVE_PUBLISH_NEW = 0x00000000;  // blobs: normative, fail-if-exists by omission
    const uint MOVE_COPY_BANNED = 0x00000002;  // declared so the value is documented, never used
    const uint MOVE_DELAY_BANNED = 0x00000004; // mutates Session Manager across reboot
    const uint MOVE_THROUGH_BANNED = 0x00000008;
    const uint MOVE_HARDLINK_BANNED = 0x00000010;
    const uint MOVE_FAILIF_BANNED = 0x00000020;
    // MEASURED on this box (tests\ioctl-probe.ps1, out-ioctl-probe.txt):
    //   FSCTL_SET_SPARSE     = 0x000900C4 -> ok, sparseBit=True, alloc collapses to 0
    //                        = 0x000900A4 -> ERR 1784 (inbuf=0) / ERR 4392 (inbuf=4)
    //   0x000900A4 is FSCTL_SET_REPARSE_POINT, NOT SET_SPARSE. That wrong value is in
    //   circulation in this project (redteam experiments\lib.ps1:27, 02-design\selftest.ps1:30)
    //   and is why the project concluded "this machine always returns 1784 for
    //   FSCTL_SET_SPARSE, so sparse is best-effort": the machine does support sparse, the
    //   control code was wrong. Any fixture built with 0x000900A4 was a fully allocated
    //   file, not a sparse one -- and MakePreallocated swallowed the return code, which is
    //   how a wrong constant survived as an environment fact.
    //   FSCTL_SET_ZERO_DATA  = 0x000980C8 -> ok, really deallocates the range
    //                        = 0x000900C8 -> ERR 1 ERROR_INVALID_FUNCTION
    const uint FSCTL_SET_SPARSE = 0x000900C4;
    const uint FSCTL_SET_REPARSE_POINT_WRONG = 0x000900A4;   // documented, never used
    const uint ATTR_SPARSE      = 0x00000200;

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa,
                                     uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool FlushFileBuffers(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(IntPtr h, int cls, out FSI info, int cb);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern uint GetFileAttributesW(string p);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileExW(string oldP, string newP, uint flags);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(IntPtr h, StringBuilder buf, uint cch, uint flags);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateHardLinkW(string newLink, string existing, IntPtr sd);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(IntPtr h, uint io, IntPtr inP, uint inL,
                                       IntPtr outP, uint outL, out int ret, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFilePointerEx(IntPtr h, long delta, out long newPtr, uint move);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetEndOfFile(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetLastError();

    [StructLayout(LayoutKind.Sequential)]
    public struct FSI {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory;
    }

    public class Snap {
        public bool Ok;
        public int Err;
        public long Eof;
        public long Alloc;
        public uint Links;
        public bool DeletePending;
        public bool IsDirectory;
        public bool Sparse;
        public uint Attrs;
        public double Density;   // Alloc/Eof, 1.0 when Eof==0
    }

    public class CopyRes {
        public long Bytes;
        public bool AbortedByTime;
        public bool AbortedByBytes;
        public bool IoError;
        public int Err;
        public long Ms;
        public string Dst;
    }

    // Extended-length prefix only at the Win32 boundary, only when it can matter.
    // The BCL and Join-Path get plain paths; CreateFileW/MoveFileExW get the \\?\ form
    // once a path approaches MAX_PATH (260), which is where a long Chinese Thunder task
    // title plus an episode name starts failing a rename with ERROR_PATH_NOT_FOUND.
    static string Ext(string p) {
        if (p == null || p.Length < 230) return p;
        if (p.StartsWith(@"\\?\")) return p;
        if (p.StartsWith(@"\??\")) return p;
        if (p.Length > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) {
            return @"\\?\" + p.Substring(0, 2) + @"\" + p.Substring(3);
        }
        if (p.StartsWith(@"\")) return @"\\?" + p;
        return p;
    }

    static IntPtr OpenR(string p) {
        return CreateFileW(Ext(p), GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, SEQ_SCAN, IntPtr.Zero);
    }

    // ---- 1b. FILE IDENTITY: (VolumeSerialNumber, 128-bit FileId) -------------
    // BACKGROUND. NTFS gives every file a 128-bit FileId that is stable across rename and
    // move WITHIN ONE VOLUME, and a per-volume VolumeSerialNumber. Read through
    // GetFileInformationByHandleEx with FILE_INFO_BY_HANDLE_CLASS.FileIdInfo = 18, whose
    // struct is exactly { ULONGLONG VolumeSerialNumber; UCHAR FileId[16]; } = 24 bytes.
    // Opening for this needs only FILE_READ_ATTRIBUTES (0x80000000) -- no read access to
    // the file's content, so it works for a standard user on files it cannot read.
    // Directories work too when the handle carries FILE_FLAG_BACKUP_SECTORS, so a Thunder
    // TASK DIRECTORY has an identity as well, which is the thing that survives the
    // "task dir renamed to the finished title" transition.
    [StructLayout(LayoutKind.Sequential)] public struct FID {
        public ulong VolumeSerial;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] FileId;
    }
    // Same entry point as the FileStandardInfo import above, different struct: the local
    // method name has to differ, so EntryPoint points back at the real export. Without it
    // the loader looks for a non-existent "GetFileInformationByHandleExId" export.
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    static extern bool GetFileInformationByHandleExId(IntPtr h, int cls, out FID info, int cb);
    const uint FILE_READ_ATTRIBUTES = 0x00000080;
    // FILE_FLAG_BACKUP_SECTORS is declared with RealPath below -- one definition, reused here.

    public static string FileIdHex(byte[] b) {
        if (b == null || b.Length != 16) return "";
        StringBuilder sb = new StringBuilder(32);
        for (int i = 0; i < 16; i++) sb.Append(b[i].ToString("x2"));
        return sb.ToString();
    }

    // Returns null when the identity cannot be obtained; Err carries the Win32 code so the
    // caller can DEGRADE LOUDLY instead of silently switching key.
    public static FID? QueryFileId(string p, out int err) {
        err = 0;
        uint flags = FILE_FLAG_BACKUP_SECTORS;   // valid for files AND directories
        IntPtr h = CreateFileW(Ext(p), FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, IntPtr.Zero,
                               OPEN_EXISTING, flags, IntPtr.Zero);
        if (h == (IntPtr)(-1)) {
            // some open-by-id / non-NTFS paths reject READ_ATTRIBUTES alone; fall back to
            // GENERIC_READ once so the degrade decision is based on a real error, not a
            // first-attempt artifact.
            h = CreateFileW(Ext(p), GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
        }
        if (h == (IntPtr)(-1)) { err = Marshal.GetLastWin32Error(); return null; }
        try {
            FID f;
            // GetFileInformationByHandleEx is the same entry point as the FSI overload
            // above; a second DllImport with a different struct is how you keep both.
            // the Id-typed import above, not the FSI one: same kernel32 entry point,
            // different out-struct, so C# overload resolution has to be given the right name
            bool ok = GetFileInformationByHandleExId(h, 18, out f, 24);
            if (!ok) { err = Marshal.GetLastWin32Error(); return null; }
            if (f.FileId == null) { err = -1; return null; }
            // all-zero FileId means the provider does not really support it (ReFS with an
            // older driver, some redirected paths); treat that as unavailable.
            bool allZero = true;
            for (int i = 0; i < 16; i++) if (f.FileId[i] != 0) { allZero = false; break; }
            if (allZero) { err = -2; return null; }
            return f;
        } finally { CloseHandle(h); }
    }
    public static FID? QueryFileId(string p) { int e; return QueryFileId(p, out e); }

    // PS-FRIENDLY IDENTITY RESULT. The Nullable<FID> above is the trap: PowerShell 5.1
    // unwraps a Nullable<T> that HAS a value into the bare T, so `$q.Value` is $null on a
    // perfectly successful call -- every query looked like "err=0 but no id", and a test that
    // compares identities then reported "rename preserved the id" for the trivial reason that
    // both sides were empty. Same family as the project's Nullable<T>.Value and RT-12c
    // ".Value unpacking" findings, and it was pointed at our own new code.
    // A class instance has no such surface: it is always constructed, never null, and each
    // field is read directly. Strong=$false means "degraded", and Err says why.
    public class FileIdentity {
        public string VolumeSerialHex = "";
        public string FileIdHex = "";
        public int Err = 0;
        public bool Strong = false;
    }
    public static FileIdentity Identity(string p) {
        FileIdentity r = new FileIdentity();
        int e;
        FID? q = QueryFileId(p, out e);
        if (!q.HasValue) { r.Err = e; return r; }
        FID f = q.Value;
        r.VolumeSerialHex = f.VolumeSerial.ToString("x16");
        r.FileIdHex = FileIdHex(f.FileId);
        r.Err = 0;
        r.Strong = (r.FileIdHex.Length == 32);
        return r;
    }

    // ---- 1. snapshot: one handle, all the cheap facts --------------------
    public static Snap Stat(string p) {
        Snap s = new Snap();
        s.Density = -1;
        s.Attrs = GetFileAttributesW(Ext(p));
        if (s.Attrs == 0xFFFFFFFFu) { s.Err = Marshal.GetLastWin32Error(); return s; }
        s.Sparse = (s.Attrs & ATTR_SPARSE) != 0;
        IntPtr h = OpenR(p);
        if (h == (IntPtr)(-1)) { s.Err = Marshal.GetLastWin32Error(); return s; }
        try {
            FSI f;
            if (!GetFileInformationByHandleEx(h, 1, out f, Marshal.SizeOf(typeof(FSI)))) {
                s.Err = Marshal.GetLastWin32Error(); return s;
            }
            s.Ok = true; s.Err = 0;
            s.Eof = f.EndOfFile; s.Alloc = f.AllocationSize; s.Links = f.NumberOfLinks;
            s.DeletePending = f.DeletePending; s.IsDirectory = f.Directory;
            s.Density = (f.EndOfFile > 0) ? ((double)f.AllocationSize / (double)f.EndOfFile) : 1.0;
        } finally { CloseHandle(h); }
        return s;
    }

    // ---- 2. reparse-resolved real path (junction/symlink safe placement checks) --
    // To ask a DIRECTORY what it really is, CreateFileW must be opened with
    // FILE_FLAG_BACKUP_SECTORS (0x02000000) and zero access; without that flag a directory
    // open fails with ERROR_ACCESS_DENIED(5). Measured here: the first version of this
    // function returned null for a junction, so the junction-based bypass in test D4 looked
    // "safe" for entirely the wrong reason -- the guard was blind, not satisfied.
    const uint FILE_FLAG_BACKUP_SECTORS = 0x02000000;
    public static string RealPath(string p) {
        IntPtr h = CreateFileW(Ext(p), 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SECTORS, IntPtr.Zero);
        if (h == (IntPtr)(-1)) { h = CreateFileW(Ext(p), 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero); }
        if (h == (IntPtr)(-1)) { h = CreateFileW(Ext(p), GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero); }
        if (h == (IntPtr)(-1)) { return null; }
        try {
            StringBuilder sb = new StringBuilder(1024);
            uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n == 0 || n > (uint)sb.Capacity) return null;
            string r = sb.ToString();
            if (r.StartsWith(@"\\?\")) r = r.Substring(4);
            if (r.StartsWith(@"\??\")) r = r.Substring(4);
            return r;
        } finally { CloseHandle(h); }
    }
    // The Win32 error from the last RealPath attempt, so a caller can tell "not a reparse
    // point / cannot open" apart from "resolved to something outside".
    public static int RealPathErr() { return Marshal.GetLastWin32Error(); }

    // ---- 3. the write path ----------------------------------------------
    // Correct streaming copy. THE ONLY SAFE THING TO WRITE IS (n), NOT (buf.Length).
    // If a caller passes a buffer it reuses across files (the shape of every
    // hand-rolled copy loop), the tail of a short file silently becomes the tail of
    // whatever was copied before it: wrong bytes, right size, self-consistent-looking
    // unless you hash every file. Test B constructs exactly that.
    public static CopyRes CopyInto(string src, string dst, byte[] buf, int useLen,
                                   long maxBytes, long deadlineMs, int flushEveryBytes) {
        CopyRes r = new CopyRes();
        r.Dst = dst;
        Stopwatch sw = Stopwatch.StartNew();
        IntPtr hs = OpenR(src);
        if (hs == (IntPtr)(-1)) { r.IoError = true; r.Err = Marshal.GetLastWin32Error(); r.Ms = sw.ElapsedMilliseconds; return r; }
        IntPtr hd = CreateFileW(Ext(dst), GENERIC_WRITE, 0, IntPtr.Zero, CREATE_ALWAYS, WRITE_THROUGH, IntPtr.Zero);
        if (hd == (IntPtr)(-1)) { CloseHandle(hs); r.IoError = true; r.Err = Marshal.GetLastWin32Error(); r.Ms = sw.ElapsedMilliseconds; return r; }
        try {
            FileStream fs = new FileStream(new SafeFileHandle(hs, true), FileAccess.Read);
            FileStream fd = new FileStream(new SafeFileHandle(hd, true), FileAccess.Write);
            hs = IntPtr.Zero; hd = IntPtr.Zero;    // the streams own the handles now
            long since = 0;
            int n;
            while ((n = fs.Read(buf, 0, buf.Length)) > 0) {
                fd.Write(buf, 0, useLen > 0 ? useLen : n);        // <- the whole difference
                r.Bytes += (useLen > 0 ? useLen : n);
                since += n;
                if (since >= flushEveryBytes) { FlushFileBuffers(fd.SafeFileHandle.DangerousGetHandle()); since = 0; }
                if (maxBytes > 0 && r.Bytes > maxBytes) { r.AbortedByBytes = true; break; }
                if (deadlineMs > 0 && sw.ElapsedMilliseconds > deadlineMs) { r.AbortedByTime = true; break; }
            }
            FlushFileBuffers(fd.SafeFileHandle.DangerousGetHandle());
            fd.Dispose(); fs.Dispose();
        } catch (Exception ex) {
            r.IoError = true;
            r.Err = Marshal.GetLastWin32Error();
            r.AbortedByBytes = false;
            if (hs != IntPtr.Zero) CloseHandle(hs);
            if (hd != IntPtr.Zero) CloseHandle(hd);
            r.Bytes = -1;
            System.Console.Error.WriteLine("copy-ex: " + ex.GetType().Name + " " + ex.Message);
        }
        r.Ms = sw.ElapsedMilliseconds;
        return r;
    }

    // BUGGY variant, kept ONLY so test B can prove the detection loop catches it.
    // Writes the full buffer every time; the last chunk of a short file is stale bytes.
    public static CopyRes CopyIntoBuggySharedBuffer(string src, string dst, byte[] buf, long flushEveryBytes) {
        CopyRes r = new CopyRes();
        r.Dst = dst;
        Stopwatch sw = Stopwatch.StartNew();
        IntPtr hs = OpenR(src);
        if (hs == (IntPtr)(-1)) { r.IoError = true; r.Err = Marshal.GetLastWin32Error(); r.Ms = sw.ElapsedMilliseconds; return r; }
        IntPtr hd = CreateFileW(Ext(dst), GENERIC_WRITE, 0, IntPtr.Zero, CREATE_ALWAYS, 0, IntPtr.Zero);
        if (hd == (IntPtr)(-1)) { CloseHandle(hs); r.IoError = true; r.Err = Marshal.GetLastWin32Error(); r.Ms = sw.ElapsedMilliseconds; return r; }
        FileStream fs = new FileStream(new SafeFileHandle(hs, true), FileAccess.Read);
        FileStream fd = new FileStream(new SafeFileHandle(hd, true), FileAccess.Write);
        try {
            int n;
            while ((n = fs.Read(buf, 0, buf.Length)) > 0) {
                fd.Write(buf, 0, buf.Length);   // BUG: ignores n
                r.Bytes += buf.Length;
            }
        } finally { fd.Dispose(); fs.Dispose(); }
        r.Ms = sw.ElapsedMilliseconds;
        return r;
    }

    public static byte[] NewBuf(int n) { return new byte[n]; }

    // Attribute mask only, for the cheap "is this a reparse point" test.
    // FILE_ATTRIBUTE_REPARSE_POINT = 0x400 (0x10 is DIRECTORY, 0x800 is COMPRESSED) --
    // it covers junctions, symlinks and mount points, and it costs one GetFileAttributesW.
    public static uint Attrs(string p) { return GetFileAttributesW(Ext(p)); }

    // ---- copy variants used ONLY by test B, to prove the detection loop works -------
    // V2: the classic buffer-reuse bug -- writes the WHOLE buffer, ignoring the short
    // read count. Result: destination is inflated and its tail holds the previous file's
    // bytes whenever the buffer is shared across files.
    public static long CopyV2FullBuffer(string src, string dst, byte[] buf) {
        IntPtr hs = OpenR(src);
        if (hs == (IntPtr)(-1)) return -1;
        FileStream fs = new FileStream(new SafeFileHandle(hs, true), FileAccess.Read);
        FileStream fd = new FileStream(Ext(dst), FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        long written = 0; int n;
        while ((n = fs.Read(buf, 0, buf.Length)) > 0) { fd.Write(buf, 0, buf.Length); written += buf.Length; }
        fd.Dispose(); fs.Dispose();
        return written;
    }
    // V3: the "optimization" of keeping one destination stream open across files.
    public static long CopyV3SharedStream(string src, FileStream fd, byte[] buf) {
        IntPtr hs = OpenR(src);
        if (hs == (IntPtr)(-1)) return -1;
        FileStream fs = new FileStream(new SafeFileHandle(hs, true), FileAccess.Read);
        long written = 0; int n;
        while ((n = fs.Read(buf, 0, buf.Length)) > 0) { fd.Write(buf, 0, n); written += n; }
        fs.Dispose();
        return written;
    }
    // V4: pre-allocate the destination to the source length first, then copy, and let a
    // deadline break out of the loop early. THIS is the dangerous shape: the size is
    // right no matter what, so a size check passes while the tail is all zeros.
    // Our protocol does not pre-allocate; this variant exists to show why.
    public static long CopyV4PreallocBreak(string src, string dst, byte[] buf, int stopAfterChunks) {
        long srcLen = new FileInfo(Ext(src)).Length;
        FileStream fd = new FileStream(Ext(dst), FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        fd.SetLength(srcLen);                       // size looks correct from the first instant
        IntPtr hs = OpenR(src);
        if (hs == (IntPtr)(-1)) { fd.Dispose(); return -1; }
        FileStream fs = new FileStream(new SafeFileHandle(hs, true), FileAccess.Read);
        long written = 0; int n; int chunks = 0;
        while ((n = fs.Read(buf, 0, buf.Length)) > 0) {
            fd.Write(buf, 0, n); written += n; chunks++;
            if (chunks >= stopAfterChunks) break;   // simulate the deadline firing
        }
        fd.Flush(true); fd.Dispose(); fs.Dispose();
        return written;
    }

    // Open with an explicit share mask, for the "do we block the downloader" test.
    public static IntPtr OpenWithShare(string path, uint access, uint share) {
        return CreateFileW(Ext(path), access, share, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
    }
    public static int RenameErr(string from, string to) {
        // Test helper only. Real code paths use Publish / PublishNew, never this.
        bool ok = MoveFileExW(Ext(from), Ext(to), MOVE_REPLACE);
        return ok ? 0 : Marshal.GetLastWin32Error();
    }
    public static int RenameNewErr(string from, string to) {
        bool ok = MoveFileExW(Ext(from), Ext(to), MOVE_PUBLISH_NEW);
        return ok ? 0 : Marshal.GetLastWin32Error();
    }
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool DeleteFileW(string p);
    // File.Delete swallows the Win32 code; DeleteFileW gives the real LastError, which is
    // what the "does our handle block the downloader's delete" test needs.
    public static int RemoveFileErr(string path) {
        return DeleteFileW(Ext(path)) ? 0 : Marshal.GetLastWin32Error();
    }
    public static void Close(IntPtr h) { if (h != (IntPtr)(-1) && h != IntPtr.Zero) CloseHandle(h); }

    // fsync a directory's parent is not a thing on Windows; the closest honest
    // guarantee is flushing the VOLUME handle (needs elevation) after the rename.
    public static int FlushVolume(string driveLetter) {   // "D" -> \\.\D:
        IntPtr h = CreateFileW(@"\\.\" + driveLetter + ":", GENERIC_WRITE,
                               FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return Marshal.GetLastWin32Error();
        try { return FlushFileBuffers(h) ? 0 : Marshal.GetLastWin32Error(); }
        finally { CloseHandle(h); }
    }

    // ---- 4. hashing ------------------------------------------------------
    public class HashRes { public string Hex; public long Bytes; public long Ms; public string Impl; public int Err; }

    static HashAlgorithm MakeAlgo(string name) {
        if (name == "SHA256Managed") return new SHA256Managed();
        if (name == "SHA256Cng")     return new SHA256Cng();
        if (name == "SHA384")        return SHA384.Create();
        if (name == "SHA1")          return SHA1.Create();
        if (name == "MD5")           return MD5.Create();
        return SHA256.Create();
    }

    public static HashRes Hash(string p, string algo, int bufSize) {
        HashRes r = new HashRes();
        r.Impl = algo;
        Stopwatch sw = Stopwatch.StartNew();
        IntPtr h = OpenR(p);
        if (h == (IntPtr)(-1)) { r.Err = Marshal.GetLastWin32Error(); return r; }
        try {
            FileStream fs = new FileStream(new SafeFileHandle(h, true), FileAccess.Read);
            h = IntPtr.Zero;
            using (HashAlgorithm a = MakeAlgo(algo)) {
                byte[] buf = new byte[bufSize];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0) { a.TransformBlock(buf, 0, n, null, 0); r.Bytes += n; }
                a.TransformFinalBlock(new byte[0], 0, 0);
                r.Hex = ToHexLower(a.Hash);
            }
            fs.Dispose();
        } catch (Exception ex) {
            r.Err = -1; r.Hex = null;
            System.Console.Error.WriteLine("hash-ex: " + ex.Message);
        } finally { if (h != IntPtr.Zero) CloseHandle(h); }
        r.Ms = sw.ElapsedMilliseconds;
        return r;
    }

    static string ToHexLower(byte[] b) {
        StringBuilder sb = new StringBuilder(b.Length * 2);
        for (int i = 0; i < b.Length; i++) { sb.Append(b[i].ToString("x2")); }
        return sb.ToString();
    }

    // size + first n + last n digest: the cheap key a lazy design reaches for.
    // Test E builds a pair that breaks it. Kept here as CANDIDATE FILTER ONLY.
    public static string HeadTail(string p, int n) {
        IntPtr h = OpenR(p);
        if (h == (IntPtr)(-1)) return null;
        try {
            FileStream fs = new FileStream(new SafeFileHandle(h, true), FileAccess.Read);
            h = IntPtr.Zero;
            using (SHA256 a = SHA256.Create()) {
                byte[] b = new byte[n];
                int got = fs.Read(b, 0, n);
                string h1 = ToHexLower(a.ComputeHash(b, 0, got));
                long tail = n;
                if (fs.Length < tail) tail = fs.Length;
                fs.Seek(-tail, SeekOrigin.End);
                got = fs.Read(b, 0, (int)tail);
                string h2 = ToHexLower(a.ComputeHash(b, 0, got));
                return h1.Substring(0, 24) + "/" + h2.Substring(0, 24);
            }
        } finally { if (h != IntPtr.Zero) CloseHandle(h); }
    }

    public static long CountNonZero(string p) {
        IntPtr h = OpenR(p);
        if (h == (IntPtr)(-1)) return -1;
        FileStream fs = new FileStream(new SafeFileHandle(h, true), FileAccess.Read);
        h = IntPtr.Zero;
        try {
            byte[] b = new byte[1 << 20]; long nz = 0; int n;
            while ((n = fs.Read(b, 0, b.Length)) > 0) { for (int i = 0; i < n; i++) if (b[i] != 0) nz++; }
            return nz;
        } finally { fs.Dispose(); }
    }

    // ---- 5. atomic publish: exactly two shapes, both named ---------------------
    // Rename inside one volume = atomic: an observer sees either the old name or the
    // new name, never a half file. Cross-volume "rename" is a copy and NOT atomic, so
    // staging must live on the same volume as the store root (checked at init).
    //
    // PublishNew is the NORMATIVE form for content-addressed blobs: flags are literally
    // MOVE_PUBLISH_NEW (0), so the call grants no replace permission at all. A blob is
    // therefore un-clobberable by our own code path, and ERROR_ALREADY_EXISTS(183) from
    // it is not an error but the dedup signal. This is deliberately stronger than
    // FAIL_IF_EXISTS(0x20): with 0 there is no bit for a future caller to OR away.
    //
    // Publish (REPLACE) is reserved for index files, which are derived caches.
    public static bool Publish(string tmp, string final, out int err) {
        bool ok = MoveFileExW(Ext(tmp), Ext(final), MOVE_REPLACE);
        err = ok ? 0 : Marshal.GetLastWin32Error();
        return ok;
    }
    public static bool PublishNew(string tmp, string final, out int err) {
        bool ok = MoveFileExW(Ext(tmp), Ext(final), MOVE_PUBLISH_NEW);
        err = ok ? 0 : Marshal.GetLastWin32Error();
        return ok;
    }

    // ---- 6. fixtures for the tests (NOT used on real Thunder data) ------
    public static long MakeFile(string path, long size, int seed) {
        if (File.Exists(path)) File.Delete(path);
        byte[] b = new byte[1 << 16];
        Random rnd = new Random(seed);
        rnd.NextBytes(b);
        using (FileStream f = new FileStream(path, FileMode.Create, FileAccess.Write)) {
            long left = size;
            while (left > 0) { int c = (left < b.Length) ? (int)left : b.Length; f.Write(b, 0, c); left -= c; }
            return f.Length;
        }
    }
    // FSCTL_SET_ZERO_DATA really deallocates a range on a sparse file; writing zeros does
    // not (it allocates). Punching a hole is the only way to build the sparse shape a
    // half-finished Thunder task has.
    [StructLayout(LayoutKind.Sequential)] struct ZERO_DATA { public long Start; public long Beyond; public long Length; }
    public static int ZeroRange(string path, long off, long len) {
        IntPtr h = CreateFileW(Ext(path), GENERIC_WRITE, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return -1;
        try {
            ZERO_DATA zd = new ZERO_DATA(); zd.Start = off; zd.Beyond = off + len; zd.Length = len;
            int cb = Marshal.SizeOf(typeof(ZERO_DATA));
            IntPtr p = Marshal.AllocHGlobal(cb);
            try {
                Marshal.StructureToPtr(zd, p, false);
                int ret;
                // the size parameters are DWORD: a plain C# int is an invalid conversion
                // here and Add-Type refuses to compile it, so cast explicitly
                bool ok = DeviceIoControl(h, FSCTL_SET_ZERO_DATA, p, (uint)cb, IntPtr.Zero, 0, out ret, IntPtr.Zero);
                return ok ? 0 : Marshal.GetLastWin32Error();
            } finally { Marshal.FreeHGlobal(p); }
        } finally { CloseHandle(h); }
    }
    // 0x000980C8 measured working (deallocates); 0x000900C8 returns ERROR_INVALID_FUNCTION(1).
    const uint FSCTL_SET_ZERO_DATA = 0x000980C8;
    // Preallocate a file, optionally sparse, and RETURN the Win32 outcome. The first version
    // of this helper was `void` and ignored DeviceIoControl's return: the E4 fixture then
    // measured a fully-allocated 512MB file while believing it was hashing holes, and every
    // density conclusion downstream was about the wrong artifact. rc: 0 = sparse confirmed and
    // sized; 1 = sized but not asked to be sparse; 10000+err = SetEndOfFile failed;
    // 20000+err = seek failed; 21000+d = seek landed somewhere other than the requested size;
    // -1 = open failed; anything else is the FSCTL_SET_SPARSE error code.
    // Call sites MUST capture it ($null = ... or $rc = ...): a value left in the success stream
    // becomes part of the enclosing PowerShell function's output.
    public static int MakePreallocated(string path, long size, bool sparse) {
        IntPtr h = CreateFileW(Ext(path), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_ALL, IntPtr.Zero, CREATE_ALWAYS, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) { return -1; }
        try {
            int ret = 0;
            int rc = 1;   // 1 == "not asked to be sparse", so 0 alone means "sparse confirmed"
            if (sparse) {
                // The P/Invoke here takes IntPtr, not SafeFileHandle: passing the wrong one is
                // a compile error ("no overload matches"), so it fails loudly rather than
                // silently leaving a non-sparse fixture behind.
                bool ok = DeviceIoControl(h, FSCTL_SET_SPARSE, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero);
                rc = ok ? 0 : Marshal.GetLastWin32Error();
            }
            long np;
            // Both halves checked. An unchecked seek silently stays at the old position and
            // SetEndOfFile then truncates to the WRONG length -- which is how a "size-1" off-by
            // one poisons every expected-size comparison that follows it.
            if (!SetFilePointerEx(h, size, out np, 0)) return 20000 + Marshal.GetLastWin32Error();
            if (np != size) return 21000 + (int)(np - size);
            if (!SetEndOfFile(h)) return 10000 + Marshal.GetLastWin32Error();
            return rc;
        } finally { CloseHandle(h); }
    }
    public static void Punch(string path, long off, int len, byte fill) {
        FileStream f = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite, 1 << 16);
        try { f.Seek(off, SeekOrigin.Begin); byte[] b = new byte[len]; for (int i = 0; i < len; i++) b[i] = fill; f.Write(b, 0, len); f.Flush(true); }
        finally { f.Dispose(); }
    }
    public static void FlipBytes(string path, long off, int len) {
        // FileAccess.Write is not enough: this method reads the current bytes so it can
        // invert them, and FileStream.Read throws "Stream does not support reading"
        // (measured) when the handle was opened write-only. ReadWrite on both sides.
        FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, 4096);
        try {
            f.Seek(off, SeekOrigin.Begin);
            byte[] b = new byte[len]; int got = 0;
            while (got < len) { int n = f.Read(b, got, len - got); if (n <= 0) break; got += n; }
            for (int i = 0; i < got; i++) b[i] = (byte)(b[i] ^ 0xFF);
            f.Seek(off, SeekOrigin.Begin); f.Write(b, 0, got); f.Flush(true);
        } finally { f.Dispose(); }
    }
    // ---- privilege handling: used ONLY to measure whether an ACL guard is a boundary ---
    // BACKGROUND. Windows represents "can bypass the DACL on open" as a privilege, not as
    // a group membership: SeBackupPrivilege bypasses read-side ACLs and SeRestorePrivilege
    // bypasses write-side ACLs when the handle is opened with FILE_FLAG_BACKUP_SECTORS.
    // A deny ACE does not stop a process that holds and ENABLES that privilege. Whether
    // that applies to us is testable, so it is tested instead of assumed.
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTR { public LUID Luid; public uint Attrs; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVS { public uint Count; public LUID_AND_ATTR Stats; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
    // LookupPrivilegeValueW, not LsaLookupPrivilegeValue: the LSA variant needs a policy
    // handle from LsaOpenPolicy and faults with a NULL one (measured: 0xC0000004
    // STATUS_ACCESS_VIOLATION straight out of the call). The advapi32 version accepts a
    // NULL system name meaning "local", which is what we want and needs no handle.
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValueW(string systemName, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll, ref TOKEN_PRIVS newStates, uint bufLen, IntPtr prev, out uint retLen);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(IntPtr h, byte[] buf, uint len, out uint written, IntPtr ov);
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;

    // Returns 0 on success; a nonzero value means the privilege is NOT enabled, which the
    // caller must report rather than assume (rule 11: no silent "unavailable means fine").
    public static int EnablePrivilege(string name) {
        LUID luid;
        if (!LookupPrivilegeValueW(null, name, out luid)) return 10000 + Marshal.GetLastWin32Error();
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok)) {
            return 20000 + Marshal.GetLastWin32Error();
        }
        try {
            TOKEN_PRIVS tp = new TOKEN_PRIVS();
            tp.Count = 1;
            tp.Stats.Luid = luid;
            tp.Stats.Attrs = SE_PRIVILEGE_ENABLED;
            uint retLen;
            bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, out retLen);
            if (!ok) return 30000 + Marshal.GetLastWin32Error();
            // AdjustTokenPrivileges returns TRUE even when it did nothing; the real answer
            // is ERROR_NOT_ALL_ASSIGNED. Skipping that check is how a privilege test lies.
            int e = Marshal.GetLastWin32Error();
            if (e == 1300) return 40000 + e;   // 1300 ERROR_NOT_ALL_ASSIGNED: not in our token
            return 0;
        } finally { CloseHandle(tok); }
    }
    // Open with backup semantics so the DACL is bypassed IF the privilege is enabled.
    public static int BypassWrite(string path, uint access) {
        IntPtr h = CreateFileW(Ext(path), access, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SECTORS, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return Marshal.GetLastWin32Error();
        try {
            byte[] b = new byte[1] { 0x7A };
            uint written;
            bool ok = WriteFile(h, b, 1, out written, IntPtr.Zero);
            if (!ok) return 10000 + Marshal.GetLastWin32Error();
            return 0;
        } finally { CloseHandle(h); }
    }
    public static IntPtr HoldOpen(string path) {
        IntPtr h = OpenR(path);
        return h;
    }
    public static bool HardLink(string newLink, string existing) {
        bool ok = CreateHardLinkW(newLink, existing, IntPtr.Zero);
        return ok;
    }
    public static int LastErr() { return Marshal.GetLastWin32Error(); }
    // README-grade capability boundary sentence. Built from \uXXXX escapes so this source
    // stays ASCII-only (the encoding guard rejects literal CJK in a BOM-less .ps1) while
    // still emitting correct Chinese at runtime for README/spec consumers.
    public static string BoundarySentence()
    { return
        "\u300c\u672c\u5de5\u5177\u80fd\u8bc1\u660e\u5b83\u5b58\u8fdb\u53bb\u7684\u5185\u5bb9\u6ca1\u88ab\u6539\u8fc7\uff1a\u6bcf\u6b21 verify \u90fd\u5bf9\u5168\u6587\u4ef6\u91cd\u7b97 SHA-256\uff0c\u540d\u5b57\u548c\u5185\u5bb9\u5bf9\u4e0d\u4e0a\u5c31\u4f1a\u88ab fsck \u62a5\u51fa\u6765\uff1b\u4e5f\u80fd\u4fdd\u8bc1\u5b83\u81ea\u5df1\u4e0d\u8986\u76d6\u5df2\u63d0\u4ea4\u7684 blob\uff08\u53d1\u5e03\u7528\u7684 MoveFileExW \u6807\u5fd7\u4e3a 0\uff0c\u76ee\u6807\u5df2\u5b58\u5728\u5373\u5931\u8d25 183\uff09\u3002\u4f46\u5b83\u4e0d\u80fd\u963b\u6b62\u540c\u4e00\u4e2a Windows \u8d26\u6237\u2014\u2014\u4e5f\u5c31\u662f\u8fd0\u884c\u8fc5\u96f7\u548c\u8fd0\u884c\u672c\u5de5\u5177\u7684\u90a3\u4e2a\u8d26\u6237\u2014\u2014\u6539\u5199\u6216\u5220\u9664\u5b58\u50a8\u5185\u5bb9\uff1a\u57fa\u4e8e ACL \u7684\u0022\u53ea\u8ffd\u52a0\u0022\u5728\u5355\u7528\u6237\u7ba1\u7406\u5458\u673a\u5668\u4e0a\u53ef\u88ab\u540c\u4e00\u8d26\u6237\u7528\u4e00\u6761 icacls /remove:d \u6216 /reset \u81ea\u884c\u89e3\u9664\uff0c\u5b9e\u6d4b\u6709\u6548\u4f46\u53ef\u64a4\u9500\u3002\u9632\u52d2\u7d22\u610f\u4e49\u4e0a\u7684\u4e0d\u53ef\u53d8\u6027\u5fc5\u987b\u843d\u5728\u672c\u5de5\u5177\u4e4b\u5916\u7684\u4fe1\u4efb\u8fb9\u754c\u4e0a\uff1a\u8fc5\u96f7\u4e0d\u6301\u6709\u51ed\u636e\u7684\u72ec\u7acb\u8d26\u6237\u3001\u72ec\u7acb\u8bbe\u5907\uff08NAS/\u79fb\u52a8\u76d8\u81ea\u5e26\u9274\u6743\uff09\uff0c\u6216\u7531\u7279\u6743\u63d0\u4f9b\u8005\u521b\u5efa\u7684 VSS \u5feb\u7167\u3002\u300d";
    }
    public static bool WFlush(IntPtr h) { return FlushFileBuffers(h); }
}
'@
}

# ============================================================================
# 2. LAYOUT + HEADER
# ============================================================================
# Why content addressing instead of a mirrored directory tree:
#   * dedup: Thunder keeps the same media in 59 cache shards and re-downloads the same
#     URL into new names. A mirror pays full price per copy; content addressing pays once.
#   * versions: a mirror has to invent filename mangling ("x.mkv.20261022-1730"), which
#     turns "list the versions of x" into a filename regex and makes retention a guess.
#   * restore ambiguity: NTFS is case-insensitive; a mirrored tree cannot hold both
#     `Movie.mkv` and `movie.mkv` from different tasks -- one silently overwrites the
#     other, and the user believes they have two backups.
#   * hard links: the engine itself imports CreateHardLinkW (module matrix, 00-recon
#     section 1.5). A mirror that "saves space" with hard links is not a backup at all:
#     deleting the source does not free the bytes, and one edit through either name
#     changes both. Content addressing keeps exactly one private copy per unique content.
#   * torn writes are self-describing: blob name == its own hash, so fsck can prove a
#     blob is intact by recomputing it, without any index.
function Get-TbsmPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $Root = (Get-TbsmFullPath $Root)
    [pscustomobject]@{
        Root        = $Root
        Header      = Join-Path $Root 'store.json'
        Blobs       = Join-Path $Root 'blobs'
        Tx          = Join-Path $Root 'tx'
        Meta        = Join-Path $Root 'meta'
        Chains      = Join-Path $Root 'meta\chain'
        Heads       = Join-Path $Root 'meta\heads.json'
        Runs        = Join-Path $Root 'meta\runs'
        Retry       = Join-Path $Root 'meta\retry.json'
        Quarantine  = Join-Path $Root 'quarantine'
        Logs        = Join-Path $Root 'logs'
        Status      = Join-Path $Root 'status.json'
        Skipped     = Join-Path $Root 'skipped.log'
        Undo        = Join-Path $Root 'restore-undo'
        TxMarker    = '.copying'
    }
}

# Path policy: PowerShell and the BCL work with PLAIN absolute paths (Join-Path,
# Test-Path, DirectoryInfo all choke on the \\?\ form: Join-Path reads the prefix as a
# drive and throws "value of argument drive is null"). The extended-length prefix is
# applied INSIDE the native boundary (see Ext() in the C# block), which is the only
# place MAX_PATH actually bites -- CreateFileW/MoveFileExW accept \\?\ and gain the
# 32k limit. Thunder task titles can be long Chinese names plus episode titles, so a
# rename failing at 260 chars mid-commit is a real accident this protects against.
function Get-TbsmFullPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path.Trim().Trim('"').Trim()
    if ($p.StartsWith('\\?\'))  { $p = $p.Substring(4) }
    if ($p.StartsWith('\\.\'))  { $p = $p.Substring(4) }
    try { $full = [IO.Path]::GetFullPath($p) } catch { return $p }
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    return $full
}

function Get-TbsmLeaf {
    param([string]$Path)
    if ($Path -like '\\?\*') { return $Path.Substring(4) }
    return $Path
}

function Start-TbsmStore {
    <#
      Creates the store skeleton and pins two invariants in the header:
        - blobFanout: 2+2 hex prefix dirs. 256*256 = up to 65k buckets so no single
          directory gets 100k entries (NTFS is fine, but enumeration + AV scans are not).
        - stagingOnSameVolume: atomic rename only exists inside one volume. If tx/ and
          blobs/ were on different volumes MoveFileExW degrades to copy+delete, which is
          NOT atomic -- that is the accident this check prevents.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [switch]$Force)
    $P = Get-TbsmPaths $Root
    if ((Test-Path -LiteralPath $P.Header) -and -not $Force) {
        throw "store already exists: $($P.Header) (use -Force to re-pin header)"
    }
    foreach ($d in @($P.Blobs, $P.Tx, $P.Meta, $P.Chains, $P.Runs, $P.Quarantine, $P.Logs, $P.Undo)) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path (Get-TbsmLeaf $d) | Out-Null }
    }
    $vol = [IO.Path]::GetPathRoot((Get-TbsmLeaf $P.Root))     # "D:\" ; GetPathRoot, not a regex
    $hdr = @{
        format        = 'tbsm-store-v1'
        storeId       = [guid]::NewGuid().ToString('N')
        root          = (Get-TbsmLeaf $P.Root)
        volume        = $vol
        createdAt     = (Get-Date).ToString('o')
        hashAlgo      = 'SHA256'
        blobFanout    = @(2, 2)
        txSuffix      = '.copying'
        psRuntime     = "$($PSVersionTable.PSVersion) / $($ExecutionContext.SessionState.LanguageMode)"
        writer        = 'tbsm-store.ps1 (prototype)'
        # Sentinel that marks this directory tree as OUR output. Used by the
        # self-backup guard even if path-prefix checks are misconfigured.
        selfSentinel  = 'store.json'
    }
    Write-TbsmJsonAtomic -Path $P.Header -Object $hdr
    [pscustomobject]$hdr
}

function Read-TbsmStoreHeader {
    param([Parameter(Mandatory)][string]$Root)
    $P = Get-TbsmPaths $Root
    if (-not (Test-Path -LiteralPath $P.Header)) { return $null }
    $txt = [IO.File]::ReadAllText((Get-TbsmLeaf $P.Header), [Text.Encoding]::UTF8)
    ConvertFrom-Json $txt
}

function Test-TbsmStoreRoot {
    <#  A directory containing store.json is, by definition, our output. Any candidate
        source file under such a directory is our own product -> never ingest it.
        This is the fourth, path-independent layer of the loop guard. #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxUp = 12)
    $cur = $Path
    for ($i = 0; $i -lt $MaxUp; $i++) {
        if ([string]::IsNullOrWhiteSpace($cur)) { return $false }
        try {
            $di = New-Object IO.DirectoryInfo (Get-TbsmLeaf $cur)
        } catch { return $false }
        if (-not $di.Exists) { return $false }
        if (Test-Path -LiteralPath (Join-Path $di.FullName 'store.json')) { return $true }
        if (-not $di.Parent) { return $false }
        $cur = $di.Parent.FullName
    }
    return $false
}

# ============================================================================
# 3. JSON / APPEND PRIMITIVES (all atomic, all fsynced)
# ============================================================================
function Write-TbsmJsonAtomic {
    <#  Same protocol as blob publish: .copying -> fsync -> rename. Index corruption is
        worse than blob corruption (it decides what the tool believes it has), so it does
        not get the sloppy "Set-Content" treatment. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Object, [int]$Depth = 8)
    $P = Get-TbsmFullPath $Path
    $leaf = Get-TbsmLeaf $P
    $dir  = Split-Path $leaf -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $tmp = $leaf + '.copying'
    $json = ($Object | ConvertTo-Json -Depth $Depth -Compress:$false)
    $enc = New-Object Text.UTF8Encoding($false)
    $fs = New-Object IO.FileStream($tmp, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 1MB)
    try {
        $b = $enc.GetBytes($json + "`r`n")
        $fs.Write($b, 0, $b.Length)
        $fs.Flush($true)                     # managed name for FlushFileBuffers
    } finally { $fs.Dispose() }
    $e = 0
    [void][TbsM]::Publish($tmp, $leaf, [ref]$e)
    if ($e -ne 0) { throw "index rename failed err=$e for $leaf" }
}

function Read-TbsmJson {
    # PS 5.1 TRAP 4 (measured here): a parameter may NOT be called $Null -- $null is a
    # read-only automatic variable, so binding it throws "Cannot overwrite variable Null
    # because it is read-only or constant" at the CALLER, far from the definition.
    param([Parameter(Mandatory)][string]$Path, $Default = $null)
    $P = Get-TbsmFullPath $Path
    if (-not (Test-Path -LiteralPath $P)) { return $Default }
    $txt = [IO.File]::ReadAllText((Get-TbsmLeaf $P), [Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($txt)) { return $Default }
    ConvertFrom-Json $txt
}

function Add-TbsmJsonLine {
    <#  Append-only journal. A chain file is never rewritten, so a crash mid-append can
        only ever cost the LAST line, and the reader drops unparsable tails instead of
        losing the whole history. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Object)
    $P = Get-TbsmFullPath $Path
    $leaf = Get-TbsmLeaf $P
    $dir = Split-Path $leaf -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $enc = New-Object Text.UTF8Encoding($false)
    $fs = New-Object IO.FileStream($leaf, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096)
    try {
        $b = $enc.GetBytes(($Object | ConvertTo-Json -Depth 10 -Compress) + "`r`n")
        $fs.Write($b, 0, $b.Length)
        $fs.Flush($true)
    } finally { $fs.Dispose() }
}

# ============================================================================
# 4. SNAPSHOT / IDENTITY
# ============================================================================
function Get-TbsmSnapshot {
    <#  ONE native call for eof / alloc / links / deletePending / sparse.
        Cost is ~0.1ms/file measured in the redteam run (RT-14/15: Get-Item is 1.05ms,
        fsutil is 31.7ms), so this is affordable across the whole tree every cycle.
        Returns $null (unknown) rather than a fake value: an unknown must degrade the
        decision, never satisfy it. #>
    param([Parameter(Mandatory)][string]$Path)
    $P = Get-TbsmFullPath $Path
    $s = [TbsM]::Stat((Get-TbsmLeaf $P))
    if (-not $s.Ok) {
        return [pscustomobject]@{ Path = $Path; Ok = $false; Err = $s.Err; Eof = -1; Alloc = -1;
            Density = -1; Links = 0; DeletePending = $false; Sparse = $s.Sparse; Attrs = $s.Attrs;
            Mtime = $null; Ctime = $null }
    }
    $fi = $null
    try { $fi = New-Object IO.FileInfo (Get-TbsmLeaf $P) } catch { }
    [pscustomobject]@{
        Path          = $Path
        Ok            = $true
        Err           = 0
        Eof           = $s.Eof
        Alloc         = $s.Alloc
        Density       = [math]::Round($s.Density, 6)
        Links         = $s.Links
        DeletePending = $s.DeletePending
        Sparse        = $s.Sparse
        Attrs         = $s.Attrs
        Mtime         = if ($fi) { $fi.LastWriteTimeUtc.ToString('o') } else { $null }
        Ctime         = if ($fi) { $fi.CreationTimeUtc.ToString('o') } else { $null }
    }
}

function Get-TbsmFileId {
    <#
    IDENTITY KEY = SHA256("v2|<volumeSerial>|<fileId128>")

    TWO PARTS ONLY. Relpath used to be the third and that made the re-key pointless:
    measured in tests\out-id-verify.txt, a rename preserved the FileId (True) but changed
    the whole key (False) -- the RT-07 defect repackaged, not fixed. See the key-material
    comment at the bottom of this function for the removal and for the measurement that
    killed the "FileId cannot tell a copy apart" argument (row 3 of fid-check: identical
    content copied to a new name gets a NEW FileId).

    Why the two parts that remain, each killing a specific failure of the other (all
    measured in tests\fid-check.ps1 and reproduced independently by the Lead):

     * FileId128 (GetFileInformationByHandleEx / FileIdInfo = 18, 24-byte struct) is the
       only part that SURVIVES A RENAME. Measured: a.txt->b.txt preserved=True, and the
       Thunder shape -- task directory renamed to the finished title with the file inside
       it -- preserved=True for both the inner file and the directory itself. A relpath
       hash, which is what this function used before, BROKE THE CHAIN ON EVERY RENAME
       (RT-07), and that was a defect, not a limitation.
     * relpath WAS the third part and has been REMOVED -- it is still recorded as a label
       an operator reads and a restore targets, but a label must not be part of an identity: that
       is exactly why a rename used to break the chain. The one argument for keeping it was
       "FileId alone cannot tell a copy apart", and measurement killed it: identical content
       copied to a new name gets a NEW FileId (fid-check row 3, True), so a copy is already a
     * VolumeSerial is mandatory because FileId is unique only WITHIN A VOLUME (Lead's
       one without the volume serial. Measured as genuinely scoped, not decorative: C:\Windows
        gives volumeSerial=9c8468a084687ea0, D:\ gives 19497a5f8026d083.

    HONEST LIMITS of this key (Lead's rulings 1-3, all restated here so nobody "discovers"
    them later):
      1. move/copy to another volume => new identity => a NEW entry. Conservative
         direction (extra history, never a wrong merge). Accepted.
      2. volume reformat / VSS rollback / restore-from-backup CAN hand an old FileId to a
         different file. Measured on this box: delete + recreate the same name gave
         index=1039789 sequence=352, then index=1039789 sequence=353: the MFT INDEX WAS REUSED
         and only the sequence moved; bytes[8..15] were zero in both, so FILE_ID_128 on NTFS is
         effectively a 64-bit id, and the sequence is what keeps two generations of one index
      apart. Keying the 48-bit index alone would merge a deleted file's history onto whoever
         gets that index next, and a format, a VSS rollback or a restore-from-backup can
         reset even the sequence -- so an identity HIT is NEVER proof of content. verify
         re-hashes, and commit binds (ctime, mtime, eof) as the four-tuple (see
         SUSPECT_IDENTITY_REUSE in tbsm-commit.ps1). No "same id => same bytes" shortcut
         exists anywhere in this store. 3. ids are per-volume, hence VolumeSerial in the key.

    DEGRADATION IS LOUD, NEVER SILENT: when FileIdInfo is unavailable (non-NTFS provider,
    ReFS without support, an ACL that blocks even READ_ATTRIBUTES), Identity='weak', the
    key falls back to the v1 relpath hash, and the caller MUST carry that flag into the
    chain record. A weak entry is allowed to break on rename -- that is exactly the old
    behaviour -- but it is labelled, so a chain never silently changes its meaning.
    #>
    param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$FullPath,
          [int]$FileIdErr = 0)
    $sr = (Get-TbsmLeaf (Get-TbsmFullPath $SourceRoot)).TrimEnd('\')
    $fp = (Get-TbsmLeaf (Get-TbsmFullPath $FullPath))
    $rel = $fp
    if ($fp.Length -gt $sr.Length -and $fp.Substring(0, $sr.Length).Equals($sr, [StringComparison]::OrdinalIgnoreCase)) {
        $rel = $fp.Substring($sr.Length).TrimStart('\')
    }
    $rel = $rel.Replace('/', '\')
    $norm = $rel.ToLowerInvariant()

    $vol = ''
    $fid = ''
    # Identity() returns a CLASS instance, never a Nullable, precisely so this line cannot
    # lie. The previous form was `$q = [TbsM]::QueryFileId(...)` then `if ($q -and $q.HasValue)`:
    # PS 5.1 unwraps a Nullable<FID> that has a value into a bare FID, which has no HasValue
    # member, so the test was falsy for EVERY file and the store silently stayed on the
    # degraded v1|relpath key while reporting identity=weak as if the filesystem had refused.
    # That is a silent key switch in the exact direction the design forbids.
    $FileIdErr = 0
    try {
        $idn = [TbsM]::Identity($fp)
        if ($idn.Strong) { $vol = $idn.VolumeSerialHex; $fid = $idn.FileIdHex }
        else { $FileIdErr = $idn.Err }
    } catch { $FileIdErr = -99 }
    $identity = if ($fid) { 'strong' } else { 'weak' }
    # no re-assignment here: $FileIdErr already carries the Win32 code from Identity(), and
    # the old trailing `if (-not $fid) { $FileIdErr = $e }` referred to a variable that no
    # longer exists after this refactor, which would have reset the code to $null.

    $sha = [Security.Cryptography.SHA256]::Create()
    # KEY MATERIAL IS v2|<volumeSerial>|<fileId128>  -- relpath is NOT in the key.
    # It used to be, and that made the re-key pointless: measured in tests\out-id-verify.txt,
    # a rename preserved the FileId (True) but changed the whole key (False), so the chain
    # still broke on every rename -- the RT-07 defect repackaged rather than fixed. The
    # argument for keeping relpath inside was "FileId alone cannot tell a copy apart", which
    # measurement killed: the same content copied to a new name gets a NEW FileId
    # (tests\out-fid-check.txt row 3, True). Relpath stays in the record as the human LABEL
    # the operator reads, and as the tie-breaker a human uses, but a label must not be an
    # identity -- that is the whole reason the rename broke history in the first place.
    $material = if ($fid) { ('v2|' + $vol + '|' + $fid) } else { ('v1|' + $norm) }
    $bytes = $sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes($material))
    [pscustomobject]@{
        FileId      = ([BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant())
        RelPath     = $rel
        Identity    = $identity          # strong = (vol,FileId,relpath); weak = relpath only
        VolumeSerial = $vol
        NtfsFileId  = $fid
        FileIdErr   = $FileIdErr         # Win32 code when identity is weak, 0 when strong
    }
}

# ============================================================================
# 5. THE ATOMIC WRITE PROTOCOL
# ============================================================================
#    pre-snapshot  ->  write tx/<run>-<seq>.copying  ->  FlushFileBuffers
# ->  hash staged copy  ->  hash source  ->  post-snapshot source  ->
#    all equal?  ->  dedupe  ->  atomic rename into blobs/<xx>/<yy>/<hash>
# ->  append chain record (fsync)  ->  [budget] re-hash the BLOB to set verified=true
#
#    Anything that fails before the rename leaves a file in tx/ that the index can
#    never reference (blobs are content-named; tx files are run-named), so Recovery
#    can delete it without consulting anything. That asymmetry is the whole point of
#    putting staging OUTSIDE blobs/.
function Start-TbsmStaging {
    param([Parameter(Mandatory)][string]$StoreRoot,
          [Parameter(Mandatory)][string]$RunId,
          [int]$BufferSize = 1048576,
          [long]$MaxBytes = 0,
          [int]$DeadlineMs = 0,
          [switch]$BuggySharedBuffer)      # test-only: reproduces the buffer-reuse bug
    $P = Get-TbsmPaths $StoreRoot
    # Deterministic, collision-free staging name: runId + pid + a per-run counter.
    # A random name can collide between two runs and silently cross-overwrite staging.
    $script:TbsmSeq = [int]$script:TbsmSeq + 1
    $tmp = Join-Path (Get-TbsmLeaf $P.Tx) ("{0}-{1}-{2}.copying" -f $RunId, $PID, $script:TbsmSeq)
    $buf = [TbsM]::NewBuf($BufferSize)
    [pscustomobject]@{ Path = $tmp; Buffer = $buf; Store = $P; RunId = $RunId
                       MaxBytes = $MaxBytes; DeadlineMs = $DeadlineMs; Buggy = [bool]$BuggySharedBuffer }
}

function Copy-TbsmToStaging {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][object]$Stage)
    $src = Get-TbsmLeaf (Get-TbsmFullPath $Source)
    $dst = Get-TbsmLeaf $Stage.Path
    if ($Stage.Buggy) {
        return [TbsM]::CopyIntoBuggySharedBuffer($src, $dst, $Stage.Buffer, 16MB)
    }
    return [TbsM]::CopyInto($src, $dst, $Stage.Buffer, 0, $Stage.MaxBytes, $Stage.DeadlineMs, 16MB)
}

function Get-TbsmBlobPath {
    param([Parameter(Mandatory)][string]$StoreRoot, [Parameter(Mandatory)][string]$Hex)
    $P = Get-TbsmPaths $StoreRoot
    # fanout 2+2: 65536 possible buckets, one per ~1 unique blob in a 100k-file store.
    Join-Path (Join-Path (Join-Path (Get-TbsmLeaf $P.Blobs) $Hex.Substring(0, 2)) $Hex.Substring(2, 2)) $Hex
}

function Publish-TbsmBlob {
    <#  Content-named publish. Returns dedup|published|error.
        PublishNew (no REPLACE) is deliberate: if the blob already exists, someone else
        committed that content, and clobbering it with an identically-named file would
        erase the guarantee that "a blob never changes once published" -- which is what
        makes fsck and version history trustworthy. #>
    param([Parameter(Mandatory)][object]$Stage, [Parameter(Mandatory)][string]$Hex)
    $P = $Stage.Store
    $final = Get-TbsmBlobPath $P.Root $Hex
    $leafFinal = Get-TbsmLeaf $final
    $dir = Split-Path $leafFinal -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $leafStage = Get-TbsmLeaf $Stage.Path
    if (Test-Path -LiteralPath $leafFinal) {
        # Content already in the store: this version costs one directory entry, not a copy.
        $saved = (New-Object IO.FileInfo $leafStage).Length
        Remove-Item -LiteralPath $leafStage -Force
        return [pscustomobject]@{ Result = 'dedup'; Blob = $final; BytesSaved = $saved }
    }
    $e = 0
    $ok = [TbsM]::PublishNew($leafStage, $leafFinal, [ref]$e)
    if (-not $ok) {
        if ($e -eq 183) {  # ERROR_ALREADY_EXISTS -> another commit won the race: dedup
            $saved = 0L
            try { $saved = (New-Object IO.FileInfo $leafStage).Length } catch { }
            Remove-Item -LiteralPath $leafStage -Force -ErrorAction SilentlyContinue
            return [pscustomobject]@{ Result = 'dedup'; Blob = $final; BytesSaved = $saved }
        }
        return [pscustomobject]@{ Result = 'error'; Blob = $final; Win32Err = $e }
    }
    [pscustomobject]@{ Result = 'published'; Blob = $final; BytesSaved = 0 }
}

# ============================================================================
# 6. SELF-BACKUP LOOP GUARD
# ============================================================================
function Get-TbsmRealAncestor {
    <#  Resolve a path that may not exist yet: walk up to the nearest EXISTING ancestor,
        resolve that through the reparse chain, then re-attach the remaining literal
        segments. Needed because placement runs BEFORE init, when the store root does not
        exist, and a fail-closed resolver would otherwise refuse every legitimate first run
        (measured: smoke step 4 went ok=True -> ok=False the moment E_RESOLVE_FAILED was
        introduced, with the store root simply not there yet).
        Returns @{ Path=...; Resolved=$true/$false; Err=<win32 or 0> }. Resolved=$false means
        "not even the nearest ancestor could be resolved", which is a real failure and the
        caller must fail closed. #>
    param([Parameter(Mandatory)][string]$Path)
    $leafPath = Get-TbsmLeaf (Get-TbsmFullPath $Path)
    $cur = $leafPath
    $tail = New-Object Collections.ArrayList
    while ($cur -and -not [IO.Directory]::Exists($cur) -and -not [IO.File]::Exists($cur)) {
        $parent = [IO.Path]::GetDirectoryName($cur)
        if (-not $parent -or $parent -eq $cur) { break }
        $null = $tail.Add(([IO.Path]::GetFileName($cur)))
        $cur = $parent
    }
    $r = $null
    $err = 0
    if ($cur -and ([IO.Directory]::Exists($cur) -or [IO.File]::Exists($cur))) {
        $r = [TbsM]::RealPath($cur)
        $err = $(if ($r) { 0 } else { [TbsM]::RealPathErr() })
    }
    if (-not $r) {
        return [pscustomobject]@{ Path = $leafPath; Resolved = $false; Err = $(if ($err) { $err } else { -1 }); Existed = $cur }
    }
    $out = $r
    for ($i = $tail.Count - 1; $i -ge 0; $i--) { $out = [IO.Path]::Combine($out, '' + $tail[$i]) }
    [pscustomobject]@{ Path = (Get-TbsmFullPath $out); Resolved = $true; Err = 0; Existed = $cur }
}

function Test-TbsmPlacement {
    <#
      Answer to redteam RT-08: a backup tool that watches its own output either
      (a) recurses until the disk is full, or (b) spends every cycle hashing itself.
      Four independent layers, because one misconfigured path field must not be enough:

        L1 config validation (here, at startup, hard error):
            store root inside a watched root      -> E_STORE_INSIDE_WATCH
            a watched root inside the store root  -> E_WATCH_INSIDE_STORE
            store root is a volume root           -> E_STORE_AT_VOLUME_ROOT
            store/volume mismatch for tx and blobs-> E_TX_CROSS_VOLUME
        L2 path-prefix test per file (in the scan loop).
        L3 sentinel: any candidate under a directory containing store.json is ours.
        L4 naming: *.copying is our staging suffix and is never a legitimate source.
        C-layer at placement: watch child with NumberOfLinks>1 -> E_WATCH_HARDLINK;
        any reparse-resolution failure -> E_RESOLVE_FAILED (fail-closed, never a
        silent fallback to string compare).

      THE THREE PLACEMENT LAYERS DO NOT COVER EACH OTHER (spec wording, shared with the
      criteria layer): the literal path prefix defeats a direct write; per-level reparse
      resolution defeats a junction or symlink; NumberOfLinks defeats a hardlink. Each
      layer's failure signal is indistinguishable in the log from "no risk exists", so
      every layer must have a counter-example fixture fired in the same smoke run
      (project rule 11: a guard never shown catching anything is not verified).

      L1 resolves reparse points with GetFinalPathNameByHandleW, because a junction
      inside the download dir that points at the store defeats a pure string compare.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StoreRoot,
          [Parameter(Mandatory)][string[]]$WatchRoots,
          [switch]$AllowStoreInWatch)     # test-only escape hatch, so L2/L3/L4 can be shown working alone

    $violations = @()
    # Per-file findings (one file's shape: reparse point, hard link, unreadable link count). They
    # are ALSO in $violations, so every existing caller and test reading .Violations/.Ok keeps
    # seeing exactly what it saw before; the group exists so a caller can tell "skip this one file"
    # apart from "the library must not live here at all".
    $perFileViolations = @()
    $notes = @()
    # FAIL-CLOSED ON RESOLUTION (Lead ruling after D4). Returning null and falling back to
    # a string compare turns "the guard could not run" into "the guard passed" -- the exact
    # shape that made the junction test look green. A resolution failure is now its own
    # violation, with the Win32 code attached. Resolution goes through the nearest EXISTING
    # ancestor so a not-yet-created store root is not mistaken for a failure (Get-TbsmRealAncestor).
    # The flag itself is FILE_FLAG_BACKUP_SECTORS (winbase.h spelling; the prose name for the
    # behaviour is "backup semantics", so a grep for BACKUP_SEMANTICS finds nothing). It is
    # only required for DIRECTORIES: measured, opening a file without it succeeds, opening a
    # directory without it fails ERROR_ACCESS_DENIED(5). That asymmetry is why the first
    # version of RealPath looked fine in every file-level test and was blind on every
    # directory.
    $sr = Get-TbsmFullPath $StoreRoot
    $srA = Get-TbsmRealAncestor -Path $StoreRoot
    $srReal = $srA.Path
    if (-not $srA.Resolved) {
        $violations += [pscustomobject]@{
            Code = 'E_RESOLVE_FAILED'
            Detail = ("cannot resolve store root {0} or any existing ancestor of it via GetFinalPathNameByHandleW (lastErr={1}); refusing to fall back to string compare" -f $sr, $srA.Err)
        }
    }

    foreach ($w in $WatchRoots) {
        if ([string]::IsNullOrWhiteSpace($w)) { continue }
        $wr = Get-TbsmFullPath $w
        $wrA = Get-TbsmRealAncestor -Path $w
        $wrReal = $wrA.Path
        if (-not $wrA.Resolved) {
            $violations += [pscustomobject]@{
                Code = 'E_RESOLVE_FAILED'
                Detail = ("cannot resolve watched root {0} or any existing ancestor of it via GetFinalPathNameByHandleW (lastErr={1}); refusing to fall back to string compare" -f $wr, $wrA.Err)
            }
        }

        if (-not $AllowStoreInWatch -and (Test-TbsmPathInside -Path $srReal -Prefix $wrReal)) {
            $violations += [pscustomobject]@{ Code = 'E_STORE_INSIDE_WATCH'; Detail = "$srReal is inside watched root $wrReal" }
        }
        if (Test-TbsmPathInside -Path $wrReal -Prefix $srReal) {
            $violations += [pscustomobject]@{ Code = 'E_WATCH_INSIDE_STORE'; Detail = "watched root $wrReal is inside the store $srReal" }
        }

        # Reparse points BELOW the watch root: resolving only the two roots does not help,
        # because the junction is an intermediate node. Measured in test D4: with
        # <watch>\link-to-store -> <store>, both string tests said "no problem" and this
        # function returned Ok=True. So we scan one level of children for reparse points
        # and resolve each. One directory enumeration per watch root, at init time only.
        # A junction nested deeper is still missed here, which is exactly why the per-file
        # layer (Test-TbsmOwnArtifact L2-resolved-via-reparse) exists and is not optional.
        #
        # A HARDLINK is invisible to every reparse test: attrs=0x20, no reparse bit, and
        # GetFinalPathNameByHandleW returns whichever name you opened it by, so resolving
        # the watched name says "inside the watch" and resolving the store name says
        # "inside the store" -- both true, both useless. Measured in tests\g-hardlink.ps1.
        # The only signal is NumberOfLinks>1 from FileStandardInfo, which we already read.
        # This scan therefore checks link counts of watch-root children at placement time.
        if (-not $AllowStoreInWatch) {
            try {
                foreach ($d in @([IO.Directory]::EnumerateDirectories((Get-TbsmLeaf $wr)))) {
                    $attr = [TbsM]::Attrs((Get-TbsmLeaf $d))
                    if (($attr -band 0x400) -eq 0) { continue }     # not a reparse point
                    $res = [TbsM]::RealPath((Get-TbsmLeaf $d))
                    if (-not $res) {
                        $violations += [pscustomobject]@{
                            Code = 'E_RESOLVE_FAILED'
                            Detail = ("reparse point {0} could not be resolved (lastErr={1}); treated as a violation, not as a pass" -f $d, [TbsM]::RealPathErr())
                        }
                        continue
                    }
                    if (Test-TbsmPathInside -Path (Get-TbsmFullPath $res) -Prefix $srReal) {
                        $violations += [pscustomobject]@{
                            Code = 'E_WATCH_REPARSE_POINTS_INTO_STORE'
                            Detail = "$d is a reparse point resolving inside the store ($res)"
                        }
                    }
                }
            } catch { }
            try {
                # A symlink and a hard link are DIFFERENT SHAPES and must be separately judgeable
                # (Lead's defect #2, decided by the criteria layer in M11): `mklink /H` gives
                # attrs=0x20 with no reparse bit and NumberOfLinks>1; `mklink /D` (or /H on a file
                # via symlink) gives the reparse bit, and Stat() on it opens the TARGET, so its
                # "2 hard links" sentence was describing the target of a symlink, not the watched
                # file. Checking the reparse bit FIRST is what makes the two cases print apart.
                #
                # These findings are also scoped per FILE (Lead's defect #3): the file itself is
                # already refused by the per-file gate (E_HARDLINK / G4_NA_REPARSE), so a hard link
                # somewhere in a 40,000-file tree must not stop the other 39,999 from being backed
                # up. They therefore go into $perFileViolations, which is reported and returned but
                # does NOT make Ok=False fatal for the pass. Structural violations (store inside the
                # watched tree, volume root, reparse pointing INTO the store) stay fatal: those are
                # about where the library lives, not about one file's shape.
                foreach ($fl in @([IO.Directory]::EnumerateFiles((Get-TbsmLeaf $wr)))) {
                    $lf = Get-TbsmLeaf $fl
                    $attr = [TbsM]::Attrs($lf)
                    $sn = [TbsM]::Stat($lf)
                    if (($attr -band 0x400) -ne 0) {
                        $perFileViolations += [pscustomobject]@{
                            Code   = 'E_WATCH_REPARSE_POINT'
                            Path   = $fl
                            Scope  = 'per-file'
                            Detail = ("{0} carries the reparse-point attribute (attrs=0x{1:X4}): it is a name that resolves somewhere else, so copying it does not produce an independent copy" -f $fl, $attr)
                        }
                        continue
                    }
                    if (-not $sn.Ok) { continue }
                    if ([int]$sn.Links -eq 0) {
                        $perFileViolations += [pscustomobject]@{
                            Code   = 'HARDLINK_STATE_UNKNOWN'
                            Path   = $fl
                            Scope  = 'per-file'
                            Detail = ("{0} could not have its link count read (links=0 means unreadable, NOT one link); treated as unknown, which fails closed" -f $fl)
                        }
                        continue
                    }
                    if ([int]$sn.Links -gt 1) {
                        $perFileViolations += [pscustomobject]@{
                            Code   = 'E_WATCH_HARDLINK'
                            Path   = $fl
                            Scope  = 'per-file'
                            Detail = ("{0} has {1} hard links and no reparse point (attrs=0x{2:X4}); one of those names may be a store blob (a hardlink is the same object under two names, not a copy)" -f $fl, $sn.Links, $attr)
                        }
                    }
                }
            } catch { }
        }
    }
    # Mirror them into $violations so .Ok and .Violations stay exactly what every existing caller
    # (the store's own hard-link test included) already reasons about. HardViolations below is the
    # subset that must stop a pass; PerFileViolations is the subset that only stops one file.
    foreach ($pv in $perFileViolations) { $violations += $pv }
    $drive = (Get-TbsmLeaf $srReal)
    if ($drive -match '^[A-Za-z]:\\?$') {
        $violations += [pscustomobject]@{ Code = 'E_STORE_AT_VOLUME_ROOT'; Detail = "store root must not be a volume root: $srReal" }
    }
    foreach ($w2 in $WatchRoots) {
        if ([string]::IsNullOrWhiteSpace($w2)) { continue }
        $a = ([IO.Path]::GetPathRoot((Get-TbsmLeaf $srReal))).ToUpperInvariant()
        $b = ([IO.Path]::GetPathRoot((Get-TbsmFullPath $w2))).ToUpperInvariant()
        if ($a -ne $b) {
            # Not a blocker (the store may legitimately live on another disk), but it is
            # the condition under which a "rename" from a staging dir on the store volume
            # to a target on the source volume silently becomes a COPY, i.e. non-atomic.
            $notes += "cross-volume: store on $a, watched root '$w2' on $b -- staging and publish stay inside $a, so a restore into $b is copy+rename, not atomic"
        }
    }
    [pscustomobject]@{
        Ok          = ($violations.Count -eq 0)
        StoreRoot   = $srReal
        Violations  = $violations
        # HardViolations = the findings that must stop a PASS (where the library lives).
        # PerFileViolations = the findings that must stop one FILE (its shape). Callers that halt
        # on Violations blindly turn a single hard link into a whole backup round doing nothing,
        # which Lead ruled a usability defect: 39,999 clean files do not lose their backup because
        # one file has two names. Both lists are printed, so "we skipped it" is never silent.
        HardViolations     = @(@($violations) | Where-Object { $perFileViolations -notcontains $_ })
        PerFileViolations  = @($perFileViolations)
        Notes       = $notes
    }
}

function Get-TbsmPendingRenameInventory {
    <#  Read-only audit of HKLM\...\Session Manager\PendingFileRenameOperations.

        Why this exists as a first-class check: MoveFileExW with DELAY_UNTIL_REBOOT (0x4)
        returns TRUE, does nothing to the files, and instead APPENDS to this registry
        value -- machine state that survives a reboot and that Windows applies at boot to
        EVERY pending entry, including other software's. The Lead's flag probe left two
        entries here while enumerating flag values, which is precisely how a "harmless"
        flag mistake becomes a machine-wide side effect. A tool that promises zero writes
        outside its store must be able to show it never registered one.

        REG_MULTI_SZ, pairs: "oldname\0newname" where names are \??\device-prefixed, and a
        leading '*' marks a delete-only dir entry. We decode with REG_MULTI_SZ semantics
        and never write. Reported, never modified -- removing entries risks other
        software's pending renames, which is a worse accident than leaving a ghost whose
        source file is already gone (boot then skips it).     #>
    [CmdletBinding()]
    param([switch]$AsJson, [string[]]$MatchPaths = @())
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $out = [pscustomobject]@{
        Exists = $false; Count = 0; Entries = @(); OurToolEntries = 0; RegAccess = 'read-only'
        MatchRoots = @(); OurToolList = @(); Reason = ''
    }
    # EVERY key a caller may read is declared up front, including Reason and OurToolList. Two
    # measured reasons: (1) assigning $out.Reason in the catch raised "The property 'Reason'
    # cannot be found on this object", so the ERROR HANDLER crashed -- a registry denial would
    # have taken the whole doctor down instead of reporting one line; (2) a key the object never
    # had reads as $null, and $null prints as an empty/zero row, which is the shape of a check
    # that silently did not run.
    # MATCHING SCOPE, widened by ruling: the first version only looked for '\03-src\store\*',
    # and in a 55-entry value it caught 0 while 2 entries sat in work\04-tests and others in the
    # install root. A rename blocked anywhere in the three roots we actually operate in is the
    # same problem, so the matcher takes: workspace root, install root, store root -- plus the
    # file-name shape 'tbsm-*' wherever it appears. Values here arrive as '\??\D:\path' (the
    # native \Device form marker), so the prefix is stripped before comparing; comparing raw
    # against normalized is how you get a confident false negative.
    $roots = @()
    # $PSScriptRoot, NOT $MyInvocation.MyCommand.Path: inside a FUNCTION that value is null
    # (measured: Split-Path raised "Cannot bind argument to parameter 'Path' because it is
    # null"), and it names the script being RUN rather than this file when the module is
    # dot-sourced. $PSScriptRoot is the directory of the file the function was defined in.
    $modDir = $PSScriptRoot
    $workRoot = (Get-TbsmFullPath (Join-Path $modDir '..\..\..'))       # ...\work\03-src\store -> workspace
    $roots += $workRoot
    foreach ($mp in @($MatchPaths)) { if ($mp) { $roots += (Get-TbsmFullPath $mp) } }
    $normRoots = @($roots | Where-Object { $_ } | ForEach-Object { (Get-TbsmLeaf $_).TrimEnd('\').ToLowerInvariant() } | Select-Object -Unique)
    $out.MatchRoots = $normRoots
    try {
        $v = Get-ItemProperty -Path $key -Name PendingFileRenameOperations -ErrorAction Stop
        $out.Exists = $true
        $raw = @($v.PendingFileRenameOperations)
        $pairs = @()
        foreach ($e in $raw) {
            $sp = ('' + $e) -split "`0"
            # Measured on this machine: an entry arrives as  *1\??\D:\path  -- the *N flag comes
            # BEFORE the \?? native marker. Stripping only '^\\\?\?\\' therefore matches nothing,
            # every path keeps its prefix, Test-TbsmPathInside is false for all of them, and the
            # matcher reports 0 ours on a value that demonstrably contains ours. That is the
            # "raw compared against normalized" false negative, and I wrote it into this file as
            # a warning in the same edit that contained the bug.
            # *1 = delete on boot, *2 = rename on boot (the DELAY_UNTIL_REBOOT flags).
            $rawFrom = '' + $sp[0]
            $flag = ''
            if ($rawFrom -match '^\*(\d+)') { $flag = $matches[1] }
            $from = ($rawFrom -replace '^\*\d+', '') -replace '^\\\?\?\\', ''
            $rawTo = $(if ($sp.Count -gt 1) { '' + $sp[1] } else { '' })
            $to = ($rawTo -replace '^\*\d+', '') -replace '^\\\?\?\\', ''
            $pairs += [pscustomobject]@{ From = $from; To = $to; Flag = $flag; RawFrom = $rawFrom }
        }
        $out.Entries = $pairs
        $out.Count = $pairs.Count
        $ours = @($pairs | Where-Object {
            $hit = $false
            foreach ($r in $normRoots) {
                if (Test-TbsmPathInside -Path $_.From -Prefix $r) { $hit = $true }
                if ($_.To -and (Test-TbsmPathInside -Path $_.To -Prefix $r)) { $hit = $true }
            }
            if (($_.From -match '\\tbsm-') -or ($_.To -match '\\tbsm-')) { $hit = $true }
            $hit
        })
        $out.OurToolEntries = $ours.Count
        $out.OurToolList = @($ours | ForEach-Object { ('' + $_.From) + ' -> ' + ('' + $_.To) })
    } catch {
        $out.Entries = @(); $out.Count = 0
        $out.Reason = $_.Exception.Message
    }
    if ($AsJson) { return ($out | ConvertTo-Json -Depth 5 -Compress) }
    return $out
}

function Test-TbsmPathInside {
    param([string]$Path, [string]$Prefix)
    if (-not $Path -or -not $Prefix) { return $false }
    $p = (Get-TbsmLeaf $Path).TrimEnd('\').ToLowerInvariant()
    $q = (Get-TbsmLeaf $Prefix).TrimEnd('\').ToLowerInvariant()
    if ($p -eq $q) { return $true }
    return $p.StartsWith($q + '\')
}

function Test-TbsmOwnArtifact {
    <#  L2+L3+L4 combined. Returns $true when the candidate must NOT be ingested
        because we wrote it. Reason strings go to skipped.log so "we skipped it"
        is always visible -- an invisible skip is indistinguishable from a bug. #>
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][object]$StorePaths,
          [AllowEmptyCollection()][string[]]$WatchRoots = @())
    $fp = Get-TbsmFullPath $Path
    # L4a naming: the staging suffix. Anything still named *.copying is an in-flight or
    # abandoned write of ours, never a user's finished file.
    if ($fp.EndsWith($StorePaths.TxMarker, [StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{ Own = $true; Layer = 'L4-naming-suffix'; Reason = 'staging suffix .copying' }
    }
    # L4b naming: the staging file NAME shape (<runId>-<pid>-<seq>.<ext>) inside a tx/
    # directory anywhere in the tree. A store moved under a different root still matches.
    if ($fp -match '\\tx\\[^\\/]+-\d+-\d+\.[^\\/]+$') {
        return [pscustomobject]@{ Own = $true; Layer = 'L4-naming-txpattern'; Reason = 'run-named staging path shape' }
    }
    # L2 path prefix, literal form.
    if (Test-TbsmPathInside -Path $fp -Prefix $StorePaths.Root) {
        return [pscustomobject]@{ Own = $true; Layer = 'L2-path-prefix'; Reason = 'under store root' }
    }
    # L2r path prefix, RESOLVED form: a junction or symlink inside the download tree that
    # points at the store defeats a pure string compare, and the files behind it are ours.
    $real = [TbsM]::RealPath((Get-TbsmLeaf $fp))
    if ($real) {
        if (Test-TbsmPathInside -Path $real -Prefix $StorePaths.Root) {
            return [pscustomobject]@{ Own = $true; Layer = 'L2-resolved-via-reparse'; Reason = "reparse target inside store: $real" }
        }
    }
    # L3 sentinel: an ancestor directory holds store.json, so this whole subtree is ours
    # even if the store was moved or bind-mounted to an unexpected path.
    if (Test-TbsmStoreRoot -Path (Get-TbsmLeaf $fp)) {
        return [pscustomobject]@{ Own = $true; Layer = 'L3-sentinel'; Reason = 'ancestor directory holds store.json' }
    }
    [pscustomobject]@{ Own = $false; Layer = $null; Reason = $null }
}

# ============================================================================
# 7. CHAIN / HEADS / STATUS
# ============================================================================
function Add-TbsmChainRecord {
    param([Parameter(Mandatory)][object]$StorePaths,
          [Parameter(Mandatory)][string]$FileId,
          [Parameter(Mandatory)][hashtable]$Record)
    $chain = Join-Path $StorePaths.Chains ($FileId + '.jsonl')
    Add-TbsmJsonLine -Path $chain -Object $Record
}

function Get-TbsmChain {
    <#  Reads the append-only journal and drops a torn final line (crash between the
        4KB write and the fsync can leave a partial JSON object). Dropping one trailing
        record is recoverable on the next scan; failing to parse the file would lose the
        whole version history of that file. #>
    param([Parameter(Mandatory)][object]$StorePaths, [Parameter(Mandatory)][string]$FileId)
    $chain = Join-Path $StorePaths.Chains ($FileId + '.jsonl')
    $P = Get-TbsmFullPath $chain
    if (-not (Test-Path -LiteralPath $P)) { return @() }
    $lines = [IO.File]::ReadAllLines((Get-TbsmLeaf $P), [Text.Encoding]::UTF8)
    $out = @()
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $l = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($l)) { continue }
        try { $out += (ConvertFrom-Json $l) }
        catch { $out += [pscustomobject]@{ op = 'TORN'; line = $i; raw = $l.Substring(0, [Math]::Min(80, $l.Length)) } }
    }
    $out
}

function Write-TbsmStatus {
    <#  status.json is the ONLY thing the user has to read to know whether the tool
        actually did something. Budget aborts, deferrals, quarantine and unverified
        versions MUST appear here; a silent skip is a design defect (verdict.md:
        "leaks must be visible"). #>
    param([Parameter(Mandatory)][object]$StorePaths, [Parameter(Mandatory)][hashtable]$Status)
    Write-TbsmJsonAtomic -Path $StorePaths.Status -Object $Status
}

function Write-TbsmSkipLine {
    param([Parameter(Mandatory)][object]$StorePaths, [string]$Source, [string]$Stage, [string]$Reason)
    $line = '{0}`t{1}`t{2}`t{3}' -f (Get-Date).ToString('o'), $Stage, $Reason, $Source
    $enc = New-Object Text.UTF8Encoding($false)
    $fs = New-Object IO.FileStream((Get-TbsmLeaf $StorePaths.Skipped), [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096)
    try { $b = $enc.GetBytes($line + "`r`n"); $fs.Write($b, 0, $b.Length); $fs.Flush($true) } finally { $fs.Dispose() }
}

# ============================================================================
# 8. THE INGEST CYCLE (store side of the commit protocol = G7/H2)
# ============================================================================
function Invoke-TbsmIngest {
    <#
      -Gate is the seam where the criteria layer plugs in. The store does NOT decide
      "is this download finished"; it decides "am I allowed to believe that claim, and
      can I prove what I wrote". Default gate is deliberately strict so the prototype
      cannot manufacture a bad backup on its own.

      Budget: MaxSeconds / MaxBytes / MaxFiles. Hitting one is not allowed to look like
      success: the run writes abortedBy + the deferred list into status.json AND
      skipped.log. Silent truncation of a work queue is how a backup tool becomes a
      backup tool that quietly stops covering half your library.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StoreRoot,
        [Parameter(Mandatory)][string[]]$SourceRoots,
        [scriptblock]$Gate,
        [int]$MaxSeconds = 60,
        [long]$MaxBytes = 0,
        [int]$MaxFiles = 0,
        [int]$BufferSize = 1048576,
        [int]$PerFileDeadlineMs = 0,
        [int]$MaxFileBytes = 0,
        [switch]$VerifyAfterCommit,
        [switch]$SkipUnchanged,
        [int]$RehashEveryRuns = 0,
        [int]$RunOrdinal = 1,
        [switch]$AllowStoreInWatch,
        [string]$RunId = ('run-' + (Get-Date).ToString('yyyyMMdd-HHmmss'))
    )
    $P = Get-TbsmPaths $StoreRoot
    if (-not (Read-TbsmStoreHeader $StoreRoot)) { throw "no store header at $($P.Header): run init first" }

    $place = Test-TbsmPlacement -StoreRoot $StoreRoot -WatchRoots $SourceRoots -AllowStoreInWatch:$AllowStoreInWatch
    if (@($place.HardViolations).Count -gt 0) {
        # Only STRUCTURAL findings stop the ingest. A per-file finding (this file is a hard link, or
        # this file is a reparse point) is handled file by file: the gate below answers E_HARDLINK /
        # G4_NA_REPARSE for that path and the pass keeps going. Halting on it was the usability
        # defect Lead filed as #3 -- one aliased name froze an entire round of backups.
        $codes = (@($place.HardViolations) | ForEach-Object { $_.Code }) -join ','
        throw "placement refused [$codes]: $(@($place.HardViolations)[0].Detail)"
    }
    if (@($place.PerFileViolations).Count -gt 0) {
        foreach ($pv in @($place.PerFileViolations)) { Write-TbsmSkipLine -StorePaths (Get-TbsmPaths $StoreRoot) -Source $pv.Path -Stage 'placement-per-file' -Reason $pv.Code }
    }

    if (-not $Gate) {
        $Gate = {
            param($ctx)
            # Minimal, conservative stand-in for the criteria layer.
            # NOTE direction of the density test: LOW density proves "not finished",
            # HIGH density proves nothing (RT-13: non-sparse preallocation is 1.00 at 3%
            # real data). It is a one-way necessary condition, never a sufficient one.
            if (-not $ctx.Snapshot.Ok) { return [pscustomobject]@{ Decision = 'WAIT'; Reason = 'snapshot-failed err=' + $ctx.Snapshot.Err } }
            if ($ctx.Snapshot.DeletePending) { return [pscustomobject]@{ Decision = 'SKIP'; Reason = 'delete-pending' } }
            if ($ctx.Snapshot.Eof -le 0)     { return [pscustomobject]@{ Decision = 'SKIP'; Reason = 'empty-file' } }
            # C-layer guard E_HARDLINK (Lead ruling, measured in tests\g-hardlink.ps1):
            # NumberOfLinks > 1 means the watched name and some OTHER name are the same
            # file object, so a copy through it is not an independent copy -- a write or a
            # delete on either name lands on the store's own bytes. Reject, do not warn.
            # links == 0 is NOT "one link": it is "unknown", and unknown fails closed.
            if ($ctx.Snapshot.Attrs -ne 0xFFFFFFFF -and $ctx.Snapshot.Links -eq 0) {
                return [pscustomobject]@{ Decision = 'SKIP'; Reason = 'HARDLINK_STATE_UNKNOWN(links-not-readable)' }
            }
            if ($ctx.Snapshot.Links -gt 1) {
                return [pscustomobject]@{ Decision = 'SKIP'; Reason = ('E_HARDLINK(links=' + $ctx.Snapshot.Links + ')' + $ctx.RelPath) }
            }
            if ($ctx.Snapshot.Density -lt 0.999) { return [pscustomobject]@{ Decision = 'WAIT'; Reason = ('low-alloc-density {0:N4}' -f $ctx.Snapshot.Density) } }
            if (-not $ctx.NoWriter)          { return [pscustomobject]@{ Decision = 'WAIT'; Reason = 'writer-holds-it' } }
            [pscustomobject]@{ Decision = 'READY'; Reason = 'gate-default' }
        }
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $st = @{
        runId = $RunId; startedUtc = (Get-Date).ToUniversalTime().ToString('o')
        scanned = 0; ready = 0; committed = 0; deduped = 0
        wait = 0; skipped = 0; ownArtifacts = 0; errors = 0; failedCommit = 0
        suspectReuse = 0
        unchanged = 0
        bytesCopied = 0L; bytesSavedByDedup = 0L
        abortedBy = $null; deferred = @(); alerts = @()
        orphansReclaimed = 0; quarantineMoved = 0
        unverified = 0
    }

    # Fast-path index: the cheap identity of the last verified version per fileId.
    # RehashEveryRuns forces a full re-read periodically so a writer that preserves
    # size+mtime+alloc cannot hide a content change forever.
    $headIdx = @{}
    $SkipUnchanged = [bool]$SkipUnchanged
    if ($RehashEveryRuns -gt 0 -and ($RunOrdinal % $RehashEveryRuns) -eq 0) {
        $SkipUnchanged = $false
        $st.alerts += ("re-hash pass {0}: fast path disabled for this run (every {1} runs)" -f $RunOrdinal, $RehashEveryRuns)
    }
    if ($SkipUnchanged) {
        $hh = Read-TbsmJson -Path $P.Heads -Default @{ heads = @{} }
        foreach ($prop in $hh.heads.PSObject.Properties) { $headIdx[$prop.Name] = $prop.Value }
    # Both axes counted into status.json, with the raw scan-line count next to them: an absent
    # axis is NOT-MEASURED, and a reader must be able to tell that apart from a measured false.
    $st.fastPathIndex = $headIdx.Count
    $st.axisScanLines = @($hh.heads.PSObject.Properties).Count
    $st.axisContentPresent = 0
    $st.axisCompletionPresent = 0
    $st.axisNotMeasured = 0
    foreach ($ap in $hh.heads.PSObject.Properties) {
        $an = @($ap.Value.PSObject.Properties.Name)
        $ac = ($an -contains 'contentVerified')
        $ak = ($an -contains 'completionClaimed')
        if ($ac) { $st.axisContentPresent = $st.axisContentPresent + 1 }
        if ($ak) { $st.axisCompletionPresent = $st.axisCompletionPresent + 1 }
        if (-not ($ac -and $ak)) { $st.axisNotMeasured = $st.axisNotMeasured + 1 }
    }
    }

    # ---- orphan reclaim BEFORE ingesting: last run may have died at any step -------
    $rec = Repair-TbsmTransactions -StorePaths $P -DryRun:$false
    $st.orphansReclaimed = $rec.DeletedTx.Count
    $st.quarantineMoved  = $rec.Quarantined.Count

    $candidates = @()
    foreach ($sr in $SourceRoots) {
        if ([string]::IsNullOrWhiteSpace($sr)) { continue }
        $dir = Get-TbsmLeaf (Get-TbsmFullPath $sr)
        if (-not (Test-Path -LiteralPath $dir)) {
            $st.alerts += "source root missing: $sr"
            Write-TbsmSkipLine -StorePaths $P -Stage 'SCAN' -Reason "source-root-missing" -Source $sr
            continue
        }
        # Native enumeration instead of Get-ChildItem: RT-15 measured Get-Item at 1.05ms
        # per file vs 0.25ms native; at 100k files that is the difference between a
        # 25s and a 105s pass before any hashing.
        $enum = [IO.Directory]::EnumerateFiles($dir, '*.*', [IO.SearchOption]::AllDirectories)
        foreach ($f in $enum) { $candidates += $f; if ($candidates.Count -ge 200000) { break } }
    }

    foreach ($f in $candidates) {
        if ($sw.ElapsedMilliseconds -gt ($MaxSeconds * 1000)) { $st.abortedBy = 'time'; break }
        if ($MaxFiles -gt 0 -and ($st.committed + $st.deduped) -ge $MaxFiles) { $st.abortedBy = 'files'; break }
        if ($MaxBytes -gt 0 -and $st.bytesCopied -ge $MaxBytes) { $st.abortedBy = 'bytes'; break }
        $st.scanned = $st.scanned + 1

        $own = Test-TbsmOwnArtifact -Path $f -StorePaths $P
        if ($own.Own) {
            $st.ownArtifacts = $st.ownArtifacts + 1
            Write-TbsmSkipLine -StorePaths $P -Source $f -Stage 'SELF-GUARD' -Reason ("{0}: {1}" -f $own.Layer, $own.Reason)
            continue
        }

        $snap = Get-TbsmSnapshot -Path $f
        $ids  = $null
        $srcRoot = $null
        foreach ($sr in $SourceRoots) {
            if (Test-TbsmPathInside -Path $f -Prefix $sr) { $srcRoot = $sr; break }
        }
        if (-not $srcRoot) { $srcRoot = (Split-Path (Get-TbsmLeaf $f) -Parent) }
        $ids = Get-TbsmFileId -SourceRoot $srcRoot -FullPath $f

        # H2: the probe handle and the copy share mask MUST include DELETE, or our
        # backup blocks Thunder's rename/delete (RT-05 measured ERROR_ACCESS_DENIED).
        $noWriter = (Test-TbsmNoWriter -Path $f)
        $ctx = [pscustomobject]@{ Path = $f; Snapshot = $snap; FileId = $ids.FileId; RelPath = $ids.RelPath; NoWriter = $noWriter }
        $g = & $Gate $ctx
        if ($g.Decision -eq 'SKIP') {
            $st.skipped = $st.skipped + 1
            Write-TbsmSkipLine -StorePaths $P -Source $f -Stage 'GATE' -Reason $g.Reason
            continue
        }
        if ($g.Decision -ne 'READY') {
            $st.wait = $st.wait + 1
            Write-TbsmSkipLine -StorePaths $P -Source $f -Stage 'GATE-WAIT' -Reason $g.Reason
            if ($st.deferred.Count -lt 50) { $st.deferred += [pscustomobject]@{ path = $f; reason = $g.Reason } }
            continue
        }
        $st.ready = $st.ready + 1

        # ---- incremental fast path (opt-in, bounded staleness) --------------------
        # Without it every cycle re-copies and re-hashes everything: measured here at
        # 451,200 bytes read and copied by a run that produced ZERO new blobs. Scaled to
        # 100k files / 200 GB that turns a nightly pass into a weekend pass, and the extra
        # read is itself IO against the machine that is trying to download.
        #
        # The comparison below is against the cheap METADATA of a version that was
        # integrity-verified after commit: size + mtime + ctime + allocation density +
        # attribute mask. It is NOT a truncated content hash -- RT-16, and test E1 which
        # constructs the colliding pair, rules that out as an identity. The residual risk is
        # a writer that rewrites bytes while preserving size/mtime/ctime (RT-02 says that is
        # possible), which would be missed until the next forced re-hash pass; that window
        # is bounded by -RehashEveryRuns, which ignores the fast path every Nth run.
        #
        # A hardlink is a second failure mode the metadata tuple cannot see: the blob and a
        # watched name are the same object, so bytes can change under us with mtime moving
        # but the head entry still claiming verified. E_HARDLINK rejects links>1 at the
        # gate, and the head record carries the link count so a later fsck can notice the
        # count grew after commit.
        if ($SkipUnchanged -and $headIdx.ContainsKey($ids.FileId)) {
            $hd = $headIdx[$ids.FileId]
            # Two-axis read, plus the check this path structurally could not see before: the
            # head records the SOURCE size at commit time, so comparing it against the source's
            # current EOF can never notice that the BLOB holds fewer bytes than that size.
            # movie.dat is exactly that shape: head.size=4 MiB, blob=1 MiB, and the only input
            # that could falsify the skip was missing from the input set of this fast path.
            $hdNames = @($hd.PSObject.Properties.Name)
            $hdContent = $null
            if ($hdNames -contains 'contentVerified') { $hdContent = [bool]$hd.contentVerified }
            elseif ($hdNames -contains 'verified') { $hdContent = [bool]$hd.verified }
            $blobOk = $false
            if ($hdContent -eq $true) {
                $hbh = ('' + $hd.hash) -replace '^.*:', ''
                $hbp = Get-TbsmBlobPath $P.Root $hbh
                if (Test-Path -LiteralPath $hbp) {
                    $blobOk = ([long](Get-Item -LiteralPath $hbp).Length -eq [long]$hd.size)
                }
            }
            if (($hdContent -eq $true) -and $blobOk -and
                ('' + $hd.size)   -eq ('' + $snap.Eof) -and
                ('' + $hd.mtime)  -eq ('' + $snap.Mtime) -and
                ('' + $hd.ctime)  -eq ('' + $snap.Ctime) -and
                ([double]$hd.density) -eq [double]$snap.Density -and
                ('' + $hd.links)  -eq ('' + $snap.Links)) {
                $st.unchanged = $st.unchanged + 1
                continue
            }
        }

        # FOUR-TUPLE BINDING on an identity hit, independent of -SkipUnchanged. If a head
        # exists for this identity but (ctime, mtime, eof) do not ALL match, the id may have
        # been handed to a different file (reformat, VSS rollback, restore-from-backup, or
        # plain MFT-index reuse). We still commit -- the content is what it is -- but we never
        # take the unchanged shortcut and we never merge into the old history silently.
        $reuseSuspect = $false
        $priorHash = ''
        if ($headIdx.ContainsKey($ids.FileId)) {
            $hd2 = $headIdx[$ids.FileId]
            $priorHash = ('' + $hd2.hash)
            if (([bool]$hd2.hash) -and
                ((('' + $hd2.ctime) -ne ('' + $snap.Ctime)) -or
                 (('' + $hd2.mtime) -ne ('' + $snap.Mtime)) -or
                 (('' + $hd2.size)   -ne ('' + $snap.Eof)))) { $reuseSuspect = $true }
        }
        if ($reuseSuspect) { $st.suspectReuse = $st.suspectReuse + 1 }

        $r = Complete-TbsmCommit -StorePaths $P -RunId $RunId -SourcePath $f -Snapshot $snap -FileId $ids.FileId `
                                 -RelPath $ids.RelPath -Gate $g -BufferSize $BufferSize -PerFileDeadlineMs $PerFileDeadlineMs `
                                 -MaxFileBytes $MaxFileBytes -VerifyAfterCommit:$VerifyAfterCommit `
                                 -ReuseSuspect:$reuseSuspect -PriorHash $priorHash `
                                 -Identity $ids.Identity -VolumeSerial $ids.VolumeSerial -NtfsFileId $ids.NtfsFileId -FileIdErr $ids.FileIdErr
        if ($r.Result -eq 'committed' -or $r.Result -eq 'dedup') {
            # PS 5.1 has no ternary operator (added in 7.0); spelled out on purpose.
            if ($r.Result -eq 'committed') { $st.committed = $st.committed + 1 } else { $st.deduped = $st.deduped + 1 }
            $st.bytesCopied = $st.bytesCopied + $r.BytesCopied
            $st.bytesSavedByDedup = $st.bytesSavedByDedup + $r.BytesSaved
            if ($r.Unverified) { $st.unverified = $st.unverified + 1 }
        } elseif ($r.Result -eq 'retry-budget') {
            $st.abortedBy = 'per-file-timeout'
            $st.failedCommit = $st.failedCommit + 1
            # Measured on the first run of test B: a per-file deadline abort appeared in
            # status.json but left skipped.log at zero lines, so "read skipped.log" was not
            # a complete answer to "what did the tool fail to back up?". Budget aborts are
            # now logged like any other skip.
            Write-TbsmSkipLine -StorePaths $P -Source $f -Stage 'BUDGET' -Reason ('per-file-' + $r.Detail)
            if ($st.deferred.Count -lt 50) { $st.deferred += [pscustomobject]@{ path = $f; reason = 'per-file-timeout' } }
        } else {
            $st.failedCommit = $st.failedCommit + 1
            Write-TbsmSkipLine -StorePaths $P -Source $f -Stage 'COMMIT' -Reason ($r.Result + ' ' + $r.Detail)
        }
    }

    $st.durationMs = [int]$sw.ElapsedMilliseconds
    $st.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    if ($st.abortedBy) {
        $st.alerts += ("BUDGET ABORT by {0}: {1} files still queued in this pass; they will be picked up next run" -f $st.abortedBy, ($candidates.Count - $st.scanned))
    }
    $st.candidatesInPass = $candidates.Count
    Write-TbsmStatus -StorePaths $P -Status $st
    Write-TbsmJsonAtomic -Path (Join-Path $P.Runs ($RunId + '.json')) -Object $st
    [pscustomobject]$st
}

function Test-TbsmNoWriter {
    <#  GENERIC_WRITE + share=READ|DELETE succeeds only if no other process holds it for
        writing, and tolerates readers (AV / preview / search indexer). ProbeExclusive
        (share=0) is the wrong question: any unrelated reader fails it, which converts a
        "busy" false positive into a permanently missed backup (RT-04). #>
    param([Parameter(Mandatory)][string]$Path)
    [Win32IoProbe]::NoWriter((Get-TbsmLeaf (Get-TbsmFullPath $Path)))
}

function Get-TbsmNoWriterErr {
    param([Parameter(Mandatory)][string]$Path)
    [Win32IoProbe]::NoWriterErr((Get-TbsmLeaf (Get-TbsmFullPath $Path)))
}

# The probe type is separate because win32io.ps1 (project lib) exposes the same
# semantics with a read-only handle; storage needs the write probe with DELETE share.
if (-not ('Win32IoProbe' -as [type])) {
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win32IoProbe {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string p, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    public static bool NoWriter(string path) {
        IntPtr h = CreateFileW(path, 0x40000000u, 0x5u, IntPtr.Zero, 3u, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return false;
        CloseHandle(h); return true;
    }
    public static int NoWriterErr(string path) {
        IntPtr h = CreateFileW(path, 0x40000000u, 0x5u, IntPtr.Zero, 3u, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return Marshal.GetLastWin32Error();
        CloseHandle(h); return 0;
    }
}
'@
}

# ============================================================================
# 9. DOCTOR -- one command that answers "is this store actually able to see?"
# ============================================================================
function Get-TbsmDoctor {
    <#
    WHY THIS EXISTS: every guard in this store fails in a direction that is invisible in a
    log line. "identity=weak" for one file and "identity=weak" for ALL files print the same
    words, and the HasValue bug is the proof: the store ran, committed, and reported fine
    while the strong key never engaged once. Lead's ruling after that: doctor prints the
    weak COUNT, not a yes/no, because the only visible symptom of a silently dead primitive
    is the count jumping from 0 to everything.

    READ-ONLY BY CONSTRUCTION: no file is created, no handle opened for write, no registry
    write, no Thunder directory touched. `fsutil hardlink list` and `vssadmin list` are query
    forms only (measured: both work unelevated on this box; taking a snapshot is NOT done).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StoreRoot, [string[]]$SourceRoots = @())
    $P = Get-TbsmPaths $StoreRoot
    $rows = New-Object Collections.ArrayList   # NOT @() with +=: see Row() below
    function Row($k, $v, $note) { [void]$rows.Add([pscustomobject]@{ Check = $k; Value = ('' + $v); Note = ('' + $note) }) }
    # WHY an ArrayList and .Add(): `$rows += x` where $rows had been bound to a single object
    # raises "PSObject does not contain a method named 'op_Addition'" -- which is exactly what
    # this function did on its first run. And mutating a parent local through $script: leaks
    # across the two dot-sources that every test harness performs. PowerShell's dynamic
    # scoping makes the parent's ArrayList visible to Row() without any of that.

    # --- 1. identity strength, as a COUNT -----------------------------------
    $headsObj = Read-TbsmJson -Path $P.Heads -Default @{ heads = @{}; weakIdentityCount = -1 }
    $props = @($headsObj.heads.PSObject.Properties)
    $weak = 0; $strong = 0
    foreach ($pr in $props) { if ('' + $pr.Value.identity -eq 'weak') { $weak++ } else { $strong++ } }
    Row 'heads.total' $props.Count 'entries in the head index'
    Row 'identity.strong' $strong 'keyed by (VolumeSerial, FileId128)'
    Row 'identity.weak' $weak 'KEYED BY RELPATH ONLY -- breaks on rename. A count, not a yes/no: 0 -> all is the only visible symptom of a dead identity primitive.'
    if ($headsObj.weakIdentityCount -ge 0 -and $headsObj.weakIdentityCount -ne $weak) {
        Row 'identity.count.disagree' ('stored=' + $headsObj.weakIdentityCount + ' recount=' + $weak) 'the index disagrees with the records; trust the recount'
    }
    # live probe of the primitive itself, independent of the index: if this returns no id for
    # a file we just made, every strong head is historical, not current.
    $probe = $null
    foreach ($pr in $props) { $cand = Get-TbsmBlobPath $P.Root (('' + $pr.Value.hash) -replace '^.*:', ''); $cand = Get-TbsmLeaf $cand; if (Test-Path -LiteralPath $cand) { $probe = $cand; break } }
    if ($probe) {
        $pi = [TbsM]::Identity($probe)
        Row 'identity.primitive.live' ([string]$pi.Strong) ('direct QueryFileId on a real path; Err=' + $pi.Err + ' when False')
    } else { Row 'identity.primitive.live' 'untested' 'no blob on disk to probe; nothing verified' }

    # --- 2. placement, with the fail-closed resolution codes ----------------
    # The parameter is -WatchRoots. Passing -SourceRoots here produced
    # "Get-TbsmDoctor : A parameter cannot be found that matches parameter name
    # 'SourceRoots'" -- the message NAMED THE ENCLOSING FUNCTION, not Test-TbsmPlacement,
    # while Get-Command on both names looked perfectly healthy. Rule for reading PS 5.1
    # binding errors: the command in the prefix is the frame that REPORTED it, not the one
    # that was called wrong; check the inner calls of that function first.
    $pl = Test-TbsmPlacement -StoreRoot $P.Root -WatchRoots $SourceRoots
    Row 'placement.ok' ([string]$pl.Ok) 'store not inside a watch root, no watch root inside the store, no volume root'
    foreach ($v in @($pl.Violations)) {
        Row ('placement.' + ('' + $v.Code)) ('' + $v.Detail) 'hard reject; ingest refuses this pair'
    }

    # --- 3. hardlinks: per-file link counts + fsutil availability ----------
    # Three non-overlapping layers, restated here because they are easy to collapse:
    # literal path prefix, per-level reparse resolution, and NumberOfLinks. A hardlink has no
    # reparse bit and GetFinalPathNameByHandleW returns the name you opened, so the link count
    # is the ONLY signal there is.
    $linkRows = @()
    foreach ($pr in $props) {
        $bp = Get-TbsmBlobPath $P.Root (('' + $pr.Value.hash) -replace '^.*:', '')
        $bpl = Get-TbsmLeaf $bp
        if (Test-Path -LiteralPath $bpl) {
            $st = [TbsM]::Stat($bpl)
            if (-not $st.Ok) { $linkRows += @{ Key = ('' + $pr.Name).Substring(0, 12); Links = -1; Err = $st.Err } }
            elseif ([int]$st.Links -ne 1) { $linkRows += @{ Key = ('' + $pr.Name).Substring(0, 12); Links = [int]$st.Links; Err = 0 } }
        }
    }
    Row 'blob.links.abnormal' $linkRows.Count 'NumberOfLinks != 1, or unresolvable: a second name can rewrite a "committed" blob'
    $axPresent = 0
    $axAbsent = 0
    $axDetail = @()
    foreach ($pr in $props) {
        $pn = @($pr.Value.PSObject.Properties.Name)
        $acT = 'NOT-MEASURED'
        if ($pn -contains 'contentVerified') { $acT = 'present' }
        $akT = 'NOT-MEASURED'
        if ($pn -contains 'completionClaimed') { $akT = 'present' }
        if (($acT -eq 'present') -and ($akT -eq 'present')) {
            $axPresent = $axPresent + 1
        } else {
            $axAbsent = $axAbsent + 1
            $axDetail += ((('' + $pr.Name).Substring(0, 12)) + ' content=' + $acT + ' completion=' + $akT)
        }
    }
    Row 'heads.axis.fields.present' $axPresent ('both axes on the head, absolute count out of ' + @($props).Count + ' heads scanned')
    Row 'heads.axis.notmeasured' $axAbsent 'at least one axis NEVER MEASURED (not false): no re-hash measured it and no criteria verdict adjudicated it'
    foreach ($ad in $axDetail) {
        Row ('heads.axis.' + $ad.Substring(0, 12)) $ad 'NOT-MEASURED is not a judgement, it is the absence of one'
    }

    foreach ($lr in $linkRows) { Row ('blob.links.' + $lr.Key) ('links=' + $lr.Links + ' err=' + $lr.Err) 'STORE_INTEGRITY_AT_RISK / HARDLINK_STATE_UNKNOWN' }
    $fsutil = $null
    try {
        $fsutil = & fsutil hardlink list $probe 2>&1
        Row 'fsutil.hardlink.list' ("exit=" + $LASTEXITCODE + ' names=' + @($fsutil).Count) 'works unelevated (measured); paths come back VOLUME-RELATIVE without a drive letter, so match them as suffixes, never as absolute'
    } catch { Row 'fsutil.hardlink.list' 'unavailable' ($_ | Out-String).Split("`n")[0] }

    # --- 4. transactions and budget aborts ---------------------------------
    # Invoke-TbsmFsck lives in the commit layer, which this file does not dot-source (store
    # must load standalone). If the layer is absent the check prints NOT LOADED rather than
    # being skipped: a skipped check and a passing check look identical in a log, which is
    # rule 11, and this file is the one place a human reads to find out what was verified.
    $ck = $null
    if (Get-Command Invoke-TbsmFsck -ErrorAction SilentlyContinue) {
        $ck = Invoke-TbsmFsck -StoreRoot $P.Root
        Row 'fsck.shallow.checked' $ck.Checked 'existence only; -Deep re-hashes and costs a full read of the store'
        Row 'fsck.missing' (@($ck.Missing).Count) 'BLOB_ABSENT: the copy is gone, action is re-ingest from the source'
        Row 'fsck.corrupt' (@($ck.Corrupt).Count) 'HASH_MISMATCH: bytes changed inside the store, action is investigate'
        Row 'tx.orphan' $ck.OrphanTx '*.copying left behind by a crash; repaired only past the grace window'
    } else {
        Row 'fsck' 'NOT LOADED' 'tbsm-commit.ps1 not dot-sourced; nothing below this line was verified'
    }

    # --- 5. rename inventory (read-only registry read) ---------------------
    # Real shape (measured against the function, not assumed): Exists / Count / Entries /
    # OurToolEntries / OurToolList / MatchRoots / RegAccess. Inventing a key is how a dead
    # check prints the same words as a clean one.
    $inv = Get-TbsmPendingRenameInventory -MatchPaths @($StoreRoot)
    Row 'rename.pending.present' ([string]$inv.Exists) 'PendingFileRenameOperations is where a blocked rename hides'
    Row 'rename.pending.count' $inv.Count ('ours=' + $inv.OurToolEntries + '; access=' + $inv.RegAccess)
    Row 'rename.pending.matchroots' (@($inv.MatchRoots).Count) (@($inv.MatchRoots) -join '; ')
    foreach ($txt in @($inv.OurToolList)) {
        # KNOWN RESIDUE OF THIS PROJECT, not a violation, and deliberately NOT cleaned.
        # Two entries point at work\04-tests\_mf_probe\a.src and b.dst, left by the Lead
        # MOVEFILE_DELAY_UNTIL_REBOOT probe. Both source files are already gone, so at boot these
        # are no-ops that touch no bytes. There is no per-entry delete on a REG_MULTI_SZ:
        # clearing them means reading and writing back the whole value, and this machine holds
        # 108 elements (54 pairs) of which 53 belong to other software. One bad write-back breaks
        # those too, and this tool is read-only by contract. Rule: any API parameter that writes
        # the registry must be checked for REVOCATION GRANULARITY before use --
        # DELAY_UNTIL_REBOOT returns TRUE, does nothing at that moment, and cannot be undone
        # per entry.
        Row 'rename.pending.known-residue' $txt 'project residue; permanent no-op at boot; NOT a violation and NOT cleaned (whole-value write-back would risk 53 third-party pairs)'
    }

    # --- 6. capability boundary, stated where the operator reads it ---------
    Row 'acl.boundary' 'not a boundary for an administrator' ([TbsM]::BoundarySentence())
    Row 'vss' 'provider present; snapshots NOT taken by this tool' 'capability claim stays unverified; see tests\out-f-ransom.txt F4'

    [pscustomobject]@{
        StoreRoot  = (Get-TbsmFullPath $StoreRoot)
        Checks     = $rows
        Violations = @($pl.Violations)
        Fsck       = $ck
    }
}

function Assert-TbsmEncoding {
    <#
        Load-time guard for PS 5.1 TRAP 1 (the line that names this function used to be a
        comment claiming a guard that did not exist -- measured: 'Assert-TbsmEncoding' appeared
        once, as prose, and 'function Assert' appeared zero times. A claim with no implementation
        behind it is worse than no claim, because the next reader stops checking.)

        WHY THIS MATTERS PHYSICALLY: PowerShell 5.1 decodes a BOM-less .ps1 using the ANSI code
        page, not UTF-8. If a watched-path literal corrupts, the tool monitors a directory that
        does not exist, backs up 0 files, and reports 0 errors. That failure is silent in both
        directions, so the check belongs at LOAD time rather than on demand: an on-demand guard
        is only as good as somebody remembering to call it.

        THREE ASSERTIONS, in the order the Lead specified:
          (1) does this file contain non-ASCII bytes?
          (2) if it does, is there a UTF-8 BOM declaring the encoding?
          (3) non-ASCII without BOM  => throw, naming the code page that would decode it.
        Absolute values (byte count, first three bytes, non-ASCII count, BOM, code page) are
        RETURNED, not just a boolean, because "True" alone cannot be audited later. Output stays
        silent when the state is good -- an alarm that fires on every load has unknowable signal
        to noise, which is the same as no signal -- but the values are handed back so a test can
        print them, and tests\enc-guard.ps1 does exactly that including a fixture this guard MUST
        reject.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AsJson
    )
    $leaf = Get-TbsmLeaf $Path
    if (-not (Test-Path -LiteralPath $leaf)) { throw ("E_SOURCE_MISSING: " + $leaf) }
    $bytes = [IO.File]::ReadAllBytes($leaf)
    $non = 0
    for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 127) { $non++ } }
    $bom = (($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF))
    $first3 = ('{0},{1},{2}' -f [int]$bytes[0], [int]$bytes[1], [int]$bytes[2])
    $cp = [Text.Encoding]::Default.WebName
    $bad = (($non -gt 0) -and (-not $bom))
    $res = [pscustomobject]@{
        Path      = $leaf
        Bytes     = $bytes.Length
        First3    = $first3
        NonAscii  = $non
        Bom       = [bool]$bom
        AnsiCodePage = $cp
        Verdict   = $(if ($bad) { 'FAIL_NON_ASCII_WITHOUT_BOM' } elseif ($bom -and $non -gt 0) { 'OK_BOM_DECLARED' } elseif ($non -eq 0) { 'OK_ASCII_ONLY' } else { 'OK_BOM_ONLY_NO_NON_ASCII' })
    }
    if ($bad) {
        # The message must say what would HAPPEN, not just that a rule was broken: a reader who
        # sees "non-ASCII bytes found" may believe the file is merely untidy. It is not -- 5.1
        # would decode it through $cp, turning literals into mojibake at parse time.
        # Measured, first version: the message printed a literal "{0}" and "{1}". Cause: in
        # ('a' + 'b' + 'c' -f x,y,z) the -f operator binds to the LAST operand only, so the
        # format list applied to 'c' and the placeholders in the earlier fragments were never
        # substituted. A guard whose diagnostic message is itself garbled is a trap: it fires,
        # looks authoritative, and tells the reader nothing. Built by concatenation instead.
        $em = 'E_SOURCE_ENCODING: ' + $leaf + ' holds ' + $non + ' non-ASCII byte(s) with NO ' +
              'UTF-8 BOM; Windows PowerShell 5.1 would decode this file as ' + $cp + ', ' +
              'corrupting every non-ASCII literal (a corrupted watched path means 0 files ' +
              'backed up and 0 errors reported). Fix: make the source ASCII-only and carry ' +
              'non-ASCII text as UTF-8 DATA read with [Text.Encoding]::UTF8, or save the file ' +
              'with a BOM.'
        throw $em
    }
    if ($AsJson) { return ($res | ConvertTo-Json -Compress -Depth 3) }
    return $res
}

# ---- load-time call ---------------------------------------------------------
# Runs on every dot-source of this module. Storing the result keeps normal operation silent
# (no alarm on success) while leaving the audited numbers reachable: tests\enc-guard.ps1 prints
# them, and $TbsmSourceEncoding is available to any harness that wants to assert on them.
$TbsmSourceEncoding = $null
$TbsmSourceEncoding = Assert-TbsmEncoding -Path $PSCommandPath
