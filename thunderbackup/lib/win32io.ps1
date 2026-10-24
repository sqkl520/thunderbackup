# win32io.ps1 -- the minimal native surface this tool actually needs.
# Target: Windows PowerShell 5.1 (FullLanguage + Add-Type) and pwsh 7.
# C# is held at language level 5: no string interpolation, no tuples, no out-var.
#
# SCOPE DISCIPLINE -- what lives here and what does not:
#  LIVES HERE (verified working): two file-handle probes. They cannot be expressed
#    with .NET/PowerShell cmdlets at all, because [System.IO.File]::Open has no
#    FILE_SHARE_NONE equivalent and no way to ask "does a writer hold this".
#  DOES NOT LIVE HERE (deliberately): allocation-range and USN queries. I first
#    hand-rolled FSCTL_GET_RETRIEVAL_POINTERS / FSCTL_QUERY_USN_JOURNAL here and
#    BOTH silently produced garbage: the ioctl 0x00090073 returns ERROR_INVALID_PARAMETER
#    (the working code is 0x00090064), yet even with 0x00090064 the returned
#    RETRIEVAL_POINTERS header decoded to pointer-shaped values that were nearly
#    identical for two different files, and GetDiskFreeSpaceW's out-parameters came
#    back 0 under my Add-Type declaration, making the cluster size a divide-by-zero.
#    `fsutil file queryallocranges` and `fsutil usn queryjournal` give the same data
#    correctly, are read-only, and are ~30 ms each -- acceptable because they are only
#    called on files that already passed the cheap filters. One instrument, verified,
#    beats two unverified ones. Those helpers are below, in PowerShell, not C#.
#  LIVES HERE but is NOT a criterion: Get-FileHolder (RestartManager). See its own header:
#    47-240 ms per call, and it answers "who holds this", never "is this done".
#
# EVERY operation here is OPEN-EXISTING + QUERY or CLOSE. Nothing writes file content.

if (-not ('Win32Io' -as [type])) {
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Win32Io
{
    const uint GENERIC_READ  = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3;
    const uint SHARE_READ_DELETE = 0x00000005;
    const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr templ);

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr h);

    static readonly IntPtr INVALID = new IntPtr(-1);

    public class ProbeResult
    {
        public string Path;
        public bool Success;
        public int  Win32Err;
        public string Mode;
    }

    static ProbeResult DoProbe(string path, string mode, uint access, uint share)
    {
        ProbeResult r = new ProbeResult();
        r.Path = path; r.Mode = mode;
        IntPtr h;
        try { h = CreateFileW(path, access, share, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero); }
        catch { r.Success = false; r.Win32Err = -1; return r; }
        if (h != INVALID && h != IntPtr.Zero) { CloseHandle(h); r.Success = true; r.Win32Err = 0; }
        else { r.Success = false; r.Win32Err = Marshal.GetLastWin32Error(); }
        return r;
    }

    /// <summary>
    /// GENERIC_READ with dwShareMode = 0: succeeds only if NOTHING else holds the file.
    /// Strictest possible reading of "is this file mine alone right now". Also fails
    /// when an unrelated reader (an AV scan, Explorer's thumbnail provider, a search
    /// indexer pass) holds it, which makes it over-strict: the cost of a false failure
    /// here is a MISSED backup, recoverable on the next rescan. Use it as a tiebreaker,
    /// never as the only gate.
    ///
    /// DOCTOR-ONLY (criteria-spec C12/M14, measured): share=0 blocks every other process's
    /// rename/delete of the target. Holding a Thunder temp or final file this way makes its
    /// ReplaceFileW fail with ERROR_SHARING_VIOLATION(32) and MoveFileWithProgressW fail
    /// with ERROR_ACCESS_DENIED(5). Never call this on the scan/copy hot path -- only from
    /// "doctor --strict" against the tool's OWN fixture files.
    /// </summary>
    public static ProbeResult ProbeExclusive(string path) { return DoProbe(path, "exclusive", GENERIC_READ, 0); }

    /// <summary>
    /// GENERIC_WRITE with dwShareMode = READ|DELETE: fails (err=32/33) unless we can obtain
    /// a write handle while everyone else keeps their handles open.
    ///
    /// CORRECTED CLAIM (measured, criteria-spec M11 + selftest A15): the earlier sentence
    /// "succeeds only if no other process holds the file open for WRITING, and tolerates
    /// concurrent readers" is FALSE. Win32 share validation is BIDIRECTIONAL: our requested
    /// share mask must be compatible with every existing handle's access mask too, so a
    /// plain read-only holder (share=READ) makes this probe fail with 32 even though nobody
    /// is writing. It answers exactly one question -- "can I get a write handle right now" --
    /// and CANNOT distinguish a writer from a reader. Therefore it must never be used as
    /// evidence of completion, only as evidence of "do not touch this round".
    /// The mask also grants DELETE so our own handle never blocks a pending rename.
    /// </summary>
    public static ProbeResult ProbeNoWriter(string path) { return DoProbe(path, "no-writer", GENERIC_WRITE, SHARE_READ_DELETE); }
}
'@
}

function ConvertTo-ExtendedPath {
    param([string]$Path)
    if ($Path.StartsWith('\\?\')) { return $Path }
    if ($Path.StartsWith('\\.')) { return $Path }
    if ($Path -match '^[A-Za-z]:\\' -or $Path.StartsWith('\\')) { return '\\?\' + $Path }
    return $Path
}

function Test-FileSettled {
    <#
      Both handle probes in one call. Returns booleans plus the raw Win32 error so the
      criteria layer can tell 32 (sharing violation, i.e. someone holds it) from
      33 (lock violation) from 2/3 (path gone) from 5 (ACL) -- collapsing those into a
      single "busy" flag would lose the distinction that matters for retry policy.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)] [string]$Path,
          [ValidateSet('no-writer', 'exclusive', 'both')] [string]$Mode = 'both')
    process {
        $p = ConvertTo-ExtendedPath $Path
        $o = [ordered]@{ Path = $Path }
        if ($Mode -eq 'both' -or $Mode -eq 'no-writer') {
            $r = [Win32Io]::ProbeNoWriter($p)
            $o['NoWriter'] = $r.Success; $o['NoWriterErr'] = $r.Win32Err
        }
        if ($Mode -eq 'both' -or $Mode -eq 'exclusive') {
            $r = [Win32Io]::ProbeExclusive($p)
            $o['Exclusive'] = $r.Success; $o['ExclusiveErr'] = $r.Win32Err
        }
        [pscustomobject]$o
    }
}

function Get-FileHole {
    <#
      THE completion-side filter, replacing the old relative "allocation density" test.

        hole = EndOfFile - AllocationSize
        hole > 0  =>  the file is NOT fully allocated => definitely NOT complete.
        hole <= 0 =>  allocation is complete. Says NOTHING about content.

      Why absolute beats relative (measured 2026-10-22 on C:\<download-root>, 59 in-progress
      .xltd + 6 finished files, using the fast instrument below, no admin):

        hole>0            catches 59/59 incomplete, false-alarms 0/6 finished
        density >= 0.999  WRONGLY PASSES 11/59 incomplete files
        smallest observed hole = 4,096 B = exactly one NTFS cluster
        finished files report hole in [-3496 .. 0]  (allocation rounds UP to a cluster,
        so "complete" files have slightly MORE allocated than the file length: hole is
        negative). That is why the test needs no epsilon and no tuned threshold.

      A relative threshold degrades with file size, which is the real reason to abandon
      it: one 64 KB hole in a 33 MB file is density 0.99805, but in a 1 GB file the same
      hole is 0.99994 -- any fixed threshold that passes small files fails big ones, and
      a downloader leaves holes of roughly constant size while files grow without bound.
      The absolute test has a constant margin of one cluster. Independent of file size.

      Still one-directional. A preallocation done with SetFileValidData/SetEndOfFile on
      a NON-sparse file reports alloc >= eof while the bytes were never written, so
      hole <= 0 never means "complete". Thunder imports SetFileValidData (see
      DownloadSDK.dll import table, next to XFSNativeFile::ResizeFile), so this is a
      live possibility, not a hypothetical.

      Instrument: GetFileInformationByHandleEx(FileStandardInfo) -- 0.25 ms/file, no
      admin, and it agrees with `fsutil file queryallocranges` ON THE SIGN of hole while
      disagreeing on magnitude (fsutil sums whole allocated runs: 65,536; the handle
      query returns cluster-rounded total allocation: 45,056, for the same file). Sign is
      all the criterion needs, and fsutil at 31.7 ms/file cannot be used across a tree
      (100,000 files = 53 min/round), so the handle query is what ships.

      Two traps this function exists to avoid:
        (1) Compute the fields INSIDE C#. In PowerShell 5.1, reading a member of
            Nullable<T> returned from a static method ($f.Value.EndOfFile) silently
            yields empty -- no error, EndOfFile becomes $null, and `eof - alloc` then
            looks like a huge hole for every file. That misfires toward WAIT, i.e.
            toward missing backups, which is the silent-failure direction.
        (2) FILE_SHARE_DELETE is 0x04, not 0x40. Using 0x43 makes CreateFileW fail with
            err=87 ERROR_INVALID_PARAMETER. The share mask here is 0x07 (READ|WRITE|
            DELETE) so probing never blocks the downloader's own rename.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not ('FileHoleProbe' -as [type])) {
        Add-Type -Language CSharp @'
using System;
using System.Text;                    // StringBuilder, used by VolumeFs() below. Without it
using System.IO;                      // Path.GetDirectoryName, the volume-cache key below.
                                      // Add-Type fails to compile the WHOLE type -- but the
                                      // PowerShell wrapper function still gets defined, so
                                      // every call returns $null and every caller reads that
                                      // as "graceful degrade". A missing using directive
                                      // therefore looks exactly like correct behaviour.
                                      // The assertion after Add-Type below is what makes this
                                      // fail loudly instead of silently.
using System.Runtime.InteropServices;
public static class FileHoleProbe {
  [StructLayout(LayoutKind.Sequential)]
  public struct FSI {
    public long AllocationSize; public long EndOfFile; public uint NumberOfLinks;
    [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
    [MarshalAs(UnmanagedType.U1)] public bool Directory;
  }
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateFileW(string p, uint access, uint share, IntPtr sa,
                                   uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandleEx(IntPtr h, int cls, out FSI info, int cb);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern uint GetFileAttributesW(string p);

  const uint GENERIC_READ   = 0x80000000;      // must live in C#: PS 5.1 parses this as Int32
  const uint OPEN_EXISTING  = 3;
  const uint SHARE_RWD      = 0x07;            // READ|WRITE|DELETE (DELETE is 0x04)
  const uint SEQ_SCAN       = 0x00000080;
  const int  FileStandardInfo = 1;             // 0 gives err=24 ERROR_BAD_LENGTH
  const uint SPARSE_ATTR    = 0x00000200;      // 0x20 is ARCHIVE, not sparse
  // Measured, not remembered. After FSCTL_SET_COMPRESSION the attribute reads back as
  // 0x820 = COMPRESSED|ARCHIVE: FILE_ATTRIBUTE_COMPRESSED is 0x800. 0x00000004 is
  // READONLY. Using 0x4 for "compressed" does not produce an error -- it silently
  // disables the exemption below, so every user-compressed file looks permanently
  // incomplete and is never backed up. Found by compressing a file and reading the
  // attribute back, which is the only way to catch an attribute-mask typo.
  const uint COMPRESSED_ATTR= 0x00000800;
  const uint ENCRYPTED_ATTR = 0x00004000;
  const uint OFFLINE_ATTR   = 0x00001000;      // remote/HSM placeholder: bytes not local
  const uint REPARSE_ATTR   = 0x00000400;      // symlink/junction: handle may miss target

  // Four exemptions, each one measured on this box. The hole test is only applied when
  // ALL of them hold; otherwise the caller is told the rule is not applicable and must
  // use a different criterion instead of guessing from the sign.
  //   1. not compressed / encrypted / offline / reparse -- alloc and eof no longer mean
  //      what the test assumes (a compressed 32,770 B file reported hole=+28,674 with an
  //      UNCHANGED SHA256: complete, yet hole>0 forever).
  //   2. volume is NTFS -- on exFAT a 8,388,608 B file with ZERO bytes written reported
  //      alloc=8,388,608, hole=0. The sign test is blind there, i.e. it answers "done" to
  //      everything. A criterion that fails toward "allow" on the backup volume is worse
  //      than no criterion, so NTFS is checked with GetVolumeInformationW, not assumed.
  //   3. eof >= 64 KiB -- MFT-resident small files are not cluster-rounded at all
  //      (1 B -> alloc 8, hole -7; 512 B -> alloc == eof == 512), and a 16 KiB sidecar
  //      that is exactly cluster-aligned lands on hole == 0 like a finished file.
  //      Small files are cheap to hash outright, so there is nothing to gain here.
  //   4. hole must not be read as proof in the other direction either: a non-sparse file
  //      extended then truncated hides a missing tail (SetLength(4 MiB-100) gave
  //      eof=4,194,204 alloc=4,194,304 hole=-100 -- 100 bytes never written, hole
  //      NEGATIVE). The smallest visible shortfall is one full cluster.
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool GetVolumePathNameW(string p, StringBuilder o, uint sz);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool GetVolumeInformationW(string root, StringBuilder name, int nlen,
      out uint serial, out uint maxcomp, out uint flags, StringBuilder fs, int flen);

  // Volume name per PATH costs two kernel round-trips and is identical for every file under
  // the same root, so memoise by volume root. Measured here: asking the volume for every
  // file took the probe from 0.23 ms to 1.83 ms/file -- a 100,000-file sweep from ~23 s to
  // ~183 s. That cost was the whole argument for "periodic full rescan is cheap enough that
  // lost change-events only cost latency", so it is worth protecting.
  static System.Collections.Generic.Dictionary<string,string> volCache =
      new System.Collections.Generic.Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
  static object volLock = new object();

  static string VolumeFs(string path) {
    try {
      // Cache key = the DIRECTORY, not the volume root. GetVolumePathNameW takes the file
      // path, so caching by root still paid one kernel round-trip per file: measured 1.81
      // ms/file, i.e. the cache bought nothing. One question per directory is what buys the
      // cost back (a 59-file directory then pays it once).
      string dir = Path.GetDirectoryName(path);
      if (dir == null) dir = ".";
      lock (volLock) { string hit; if (volCache.TryGetValue(dir, out hit)) return hit; }
      StringBuilder vp = new StringBuilder(260);
      if (!GetVolumePathNameW(path, vp, 260)) return "?";
      string root = vp.ToString();
      StringBuilder nm = new StringBuilder(260), fs = new StringBuilder(32);
      uint ser = 0, mx = 0, fl = 0;
      string ans;
      if (!GetVolumeInformationW(root, nm, 260, out ser, out mx, out fl, fs, 32)) ans = "?";
      else ans = fs.ToString();
      // "?" is deliberately NOT cached. Unknown means "do not apply the hole rule", and
      // pinning that for the process lifetime would silently switch the criterion off
      // everywhere after one transient failure.
      if (ans != "?") { lock (volLock) { volCache[dir] = ans; } }
      return ans;
    } catch { return "?"; }
  }

  const long HOLE_MIN_EOF = 65536;             // exemption 3

  public static string Row(string path) {
    uint at = GetFileAttributesW(path);
    bool sparse     = (at & SPARSE_ATTR)     != 0;
    bool compressed = (at & COMPRESSED_ATTR) != 0;
    bool encrypted  = (at & ENCRYPTED_ATTR)  != 0;
    bool offline    = (at & OFFLINE_ATTR)    != 0;
    bool reparse    = (at & REPARSE_ATTR)    != 0;
    IntPtr h = CreateFileW(path, GENERIC_READ, SHARE_RWD, IntPtr.Zero,
                           OPEN_EXISTING, SEQ_SCAN, IntPtr.Zero);
    if (h == (IntPtr)(-1)) return "ERR|open=" + Marshal.GetLastWin32Error() + "|attrs=0x" + at.ToString("X");
    try {
      FSI f;
      if (!GetFileInformationByHandleEx(h, FileStandardInfo, out f, Marshal.SizeOf(typeof(FSI))))
        return "ERR|api=" + Marshal.GetLastWin32Error() + "|attrs=0x" + at.ToString("X");
      string vol = VolumeFs(path);
      System.Collections.Generic.List<string> why = new System.Collections.Generic.List<string>();
      if (compressed) why.Add("compressed");
      if (encrypted)  why.Add("encrypted");
      if (offline)    why.Add("offline");
      if (reparse)    why.Add("reparse");
      if (vol != "NTFS") why.Add("volume=" + vol);
      if (f.EndOfFile < HOLE_MIN_EOF) why.Add("eof<64KiB");
      string unusable = (why.Count == 0) ? "USABLE" : "UNUSABLE";
      return "OK|" + f.EndOfFile + "|" + f.AllocationSize + "|" + (f.EndOfFile - f.AllocationSize) +
             "|" + sparse + "|" + compressed + "|" + encrypted + "|" + unusable +
             "|" + f.DeletePending + "|" + f.NumberOfLinks + "|0x" + at.ToString("X") +
             "|" + offline + "|" + reparse + "|" + vol + "|" + string.Join(",", why.ToArray());
    } finally { CloseHandle(h); }
  }
}
'@
    }

    # LOUD ASSERTION, deliberately fatal.
    # Without it, a compile failure of Add-Type leaves the PowerShell function DEFINED but
    # the type MISSING, so every call returns $null -- and $null is also what a correct
    # "cannot measure, degrade" looks like. Callers cannot tell the two apart, and every
    # downstream test then reports the guard as working. Observed on this box: the only
    # symptom was one missing `using System.Text;`.
    if (-not ('FileHoleProbe' -as [type])) {
        throw 'Get-FileHole: FileHoleProbe failed to compile. Returning here would be indistinguishable from a correct graceful-degrade, so this is fatal by design.'
    }

    $r = ([FileHoleProbe]::Row($Path)) -split '\|'
    if ($r[0] -ne 'OK') {
        return $null   # degrade: unknown is never treated as "complete"
    }
    $usable = ($r[7] -eq 'USABLE')
    [pscustomobject]@{
        Path            = $Path
        EndOfFile       = [int64]$r[1]
        AllocationSize  = [int64]$r[2]
        Hole            = [int64]$r[3]
        Sparse          = ($r[4] -eq 'True')
        Compressed      = ($r[5] -eq 'True')
        Encrypted       = ($r[6] -eq 'True')
        # Applicable means: all four exemptions hold, so the sign of Hole means something.
        Measurable      = $usable
        DeletePending   = ($r[8] -eq 'True')
        Links           = [uint32]$r[9]
        Attributes      = $r[10]
        Offline         = ($r[11] -eq 'True')
        Reparse         = ($r[12] -eq 'True')
        VolumeFileSystem= $r[13]
        NotApplicableReason = $r[14]
        # ONE-WAY filter. True  => allocation is not complete: never back up on the
        # strength of "it stopped changing", and route to a content check instead.
        # False => either hole<=0 (NOT proof of completion) or the rule is not
        # applicable to this file, which the caller must read from .Measurable.
        NotCompleteByAllocation = ($(if ($usable) { [int64]$r[3] -gt 0 } else { $false }))
    }
}

function Get-AllocRangeInfo {
    <#
      Allocation density via fsutil (read-only query). Returns $null when the probe is
      unavailable so callers degrade instead of treating an unknown as "complete".
      Cost ~30 ms per call (child process): call it only on a file you are about to
      back up, never across a whole tree.

      Why this matters: a downloader that pre-allocates a sparse file sets Length to
      the FINAL size up front. "Length has not changed for N seconds" is then true at
      the instant the content is emptiest. Comparing allocated clusters against Length
      is the objective way to see through that, and it reads as zeros so a copy yields
      a file of the right size with the wrong bytes in it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer) { return $null }
    $len = [long]$item.Length
    if ($len -le 0) {
        return [pscustomobject]@{ Path = $Path; Length = 0; AllocatedBytes = 0; Density = 1.0; Ranges = 0; Sparse = $false; Source = 'trivial' }
    }
    # NOT Invoke-Expression. This string used to be built by concatenating a path inside literal
    # double quotes and handing the result to the interpreter. A watched filename is
    # attacker-influenceable -- a download title comes off a remote server and Thunder mkdirs it
    # verbatim -- so one embedded `"` would have closed the quote and run whatever followed as
    # PowerShell, as the backup tool, with the user's privileges, against the user's own library.
    # The call operator passes the path as one ARGUMENT: quoting becomes PowerShell's problem
    # instead of a string-concatenation problem, and there is no interpreter in the path at all.
    # build-check.ps1's static scan flags Invoke-Expression for exactly this shape.
    $o = $null
    try { $o = (& fsutil file queryallocranges offset=0 length=$len $Path 2>&1 | Out-String) } catch { return $null }
    if (-not $o) { return $null }
    $bytes = 0L; $n = 0
    foreach ($m in [regex]::Matches($o, 'Length:\s+0x([0-9a-fA-F]+)')) {
        $bytes += [Convert]::ToInt64($m.Groups[1].Value, 16); $n++
    }
    if ($n -eq 0) { return $null }   # no ranges parsed => unknown, not "empty"
    $dens = [double]$bytes / [double]$len
    if ($dens -gt 1.0) { $dens = 1.0 }
    $sparse = ($item.Attributes -band [IO.FileAttributes]::SparseFile) -ne 0
    [pscustomobject]@{
        Path           = $Path
        Length         = $len
        AllocatedBytes = $bytes
        Density        = [math]::Round($dens, 6)
        Ranges         = $n
        Sparse         = $sparse
        Source         = 'fsutil queryallocranges'
    }
}

function Get-FileId {
    <#
      The file's IDENTITY, independent of its name. This is what makes criterion G7
      de-Xunlei-able: instead of "I saw *.xltd disappear and a final name appear" (which
      depends on Thunder's naming convention), the tool can observe "the object with this
      FileId was renamed". A rename does not change FileId, so the identity survives the
      event that the criterion is about.

      MEASURED HERE (2026-10-22): FileInformationClass 18 = FileIdInfo, buffer 24 bytes:
        ULONG64 VolumeSerialNumber at +0 ; FILE_ID_128 (16 bytes) at +8.
      Read with CreateFileW(access=FILE_READ_ATTRIBUTES 0x80, share=READ|WRITE|DELETE,
      OPEN_EXISTING, flags=0). Two reasons for that exact combination, both measured:
        * FILE_READ_ATTRIBUTES is enough for metadata and is NEVER share-checked, so the
          query succeeds on the two .xltd files Thunder holds open (the same mask pair that
          made the 6x8 share matrix return OK on a file RM says is held).
        * FILE_FLAG_BACKUP_SEMANTICS must NOT be used: it needs SE_BACKUP_NAME, and on a
          non-elevated token it fails with ERROR_ACCESS_DENIED(5) on files that are fully
          readable. That bug made every probe in an earlier version of mine fail.
      No admin, no child process, one syscall.

      What the id is NOT: it is volume-local (never compare ids across volumes), it is
      recycled when the MFT slot is reused, and it does not survive a copy-then-delete --
      ReplaceFileW / CopyFile+delete produce a NEW id. So "same FileId" proves "same file
      object, renamed in place"; it does not prove "same content".

      A DIRECTORY CANNOT BE QUERIED WITH THIS ACCESS MASK. Measured: CreateFileW on
      D:\Example\thunder-work, C:\Windows and the cache dir all fail with ERROR_ACCESS_DENIED(5)
      using access=0x80/0x0 and flags=0; adding FILE_FLAG_BACKUP_SEMANTICS (0x02000000) makes
      it succeed. That flag is deliberately NOT used, because on a non-elevated token it is
      what broke every file probe in an earlier version of mine. So directories come back as
      Error='open=5' and the wrapper labels them IsDirectory -- callers must not read a
      missing id as corruption. .IsDirectory therefore only ever comes back True for real
      files, from FileStandardInfo.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Path)
    process {
        if (-not ('FileIdProbe' -as [type])) {
            Add-Type -Language CSharp @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class FileIdProbe {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateFileW(string p, uint access, uint share, IntPtr sa,
                                   uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandleEx(IntPtr h, int cls, IntPtr info, int cb);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);

  const uint READ_ATTR   = 0x00000080;
  const uint SHARE_RWD   = 0x00000007;
  const uint OPEN_EXIST  = 3;
  const int  FileIdInfo      = 18;    // FILE_ID_INFO: u64 VolumeSerialNumber + 16-byte FileId
  const int  FileStandardInfo = 1;    // reuse the same handle for the directory flag

  public static string Row(string path) {
    IntPtr h = CreateFileW(path, READ_ATTR, SHARE_RWD, IntPtr.Zero, OPEN_EXIST, 0, IntPtr.Zero);
    if (h == (IntPtr)(-1)) return "ERR|open=" + Marshal.GetLastWin32Error();
    try {
      IntPtr buf = Marshal.AllocHGlobal(24);
      try {
        for (int i = 0; i < 24; i += 4) Marshal.WriteInt32(buf, i, 0);
        if (!GetFileInformationByHandleEx(h, FileIdInfo, buf, 24))
          return "ERR|idinfo=" + Marshal.GetLastWin32Error();
        ulong vol = (ulong)Marshal.ReadInt64(buf, 0);
        StringBuilder sb = new StringBuilder(32);
        for (int i = 15; i >= 0; i--) {            // big-endian hex of the 16-byte id
          byte b = Marshal.ReadByte(buf, 8 + i);
          sb.Append(b.ToString("x2"));
        }
        string id = sb.ToString();
        bool isDir = false; uint links = 0;
        IntPtr sbuf = Marshal.AllocHGlobal(24);   // FILE_STANDARD_INFO is 24 bytes native
        try {
          for (int i = 0; i < 24; i += 4) Marshal.WriteInt32(sbuf, i, 0);
          if (GetFileInformationByHandleEx(h, FileStandardInfo, sbuf, 24)) {
            links = (uint)Marshal.ReadInt32(sbuf, 16);
            isDir = Marshal.ReadByte(sbuf, 21) != 0;
          }
        } finally { Marshal.FreeHGlobal(sbuf); }
        return "OK|" + vol.ToString("x16") + "|" + id + "|" + isDir + "|" + links;
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseHandle(h); }
  }
}
'@
        }
        if (-not ('FileIdProbe' -as [type])) {
            throw 'Get-FileId: FileIdProbe failed to compile. $null would look like "no id available", so this is fatal by design.'
        }
        $r = ([FileIdProbe]::Row($Path)) -split '\|'
        if ($r[0] -ne 'OK') {
            # open=5 on a directory is the expected shape, not a defect. Label it so the
            # caller never reads "no id" as "damaged file".
            $isDirPath = (Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue)
            return [pscustomobject]@{ Path = $Path; Error = $r[1]; FileId = $null;
                                      VolumeSerial = $null; IsDirectory = [bool]$isDirPath; Links = 0;
                                      Identity = $null }
        }
        [pscustomobject]@{
            Path         = $Path
            Error        = ''
            VolumeSerial = $r[1]
            FileId       = $r[2]
            IsDirectory  = ($r[3] -eq 'True')
            Links        = [uint32]$r[4]
            # One string to key a table by. Volume-scoped on purpose: an id seen on another
            # volume is a different file, and silently joining on FileId alone across volumes
            # would invent renames that never happened.
            Identity     = $r[1] + ':' + $r[2]
        }
    }
}

function Get-FileHolder {
    <#
      WHO holds this file open, by name and pid. RestartManager, read-only query.

      禁止按文档结构体封送 —— 那条路径两个 agent 各踩过一次（一次乱码、一次 0xC0000409）。

      HARD PROHIBITION -- read this before touching the implementation:
        ** 禁止按文档结构体封送。Do NOT marshal RM_PROCESS_INFO as a struct (or an array
        of structs). That path has now been walked twice, by two different agents, and it
        failed two different ways: mojibake process names (my own XlRm, and the redteam
        RT3, whose struct also omits the leading RM_UNIQUE_PROCESS so strAppName reads the
        pid/FILETIME bytes), then a whole-host crash with 0xC0000409 / exit code
        3221226356 when array marshalling ran past the buffer. **
      The working surface is raw bytes: allocate a block, zero it, let RmGetList fill it,
      and ReadInt32 / PtrToStringUni at fixed offsets. Verified on this machine against
      Thunder's own files: pid=<pid> name=[<engine>] (= DownloadSDKServer.exe) on the
      .xltd files, pid=<pid> name=[迅雷] (= Thunder.exe) on TaskDb.dat.

      FUNCTIONAL BOUNDARY -- fixed by the criteria spec, not by taste:
        * Call it ONLY from on-demand diagnostics (doctor / verbose attribution), after a
          cheap probe has already failed. NEVER inside a scan hot path, and NEVER as a
          completion criterion. It answers "who is holding this", which says nothing about
          whether the file is finished.
        * Measured cost, n=6 each on this box: 20-43 ms (avg 31) when NOTHING holds the file,
          232-324 ms (avg 270) when something does -- vs 0.285 ms for Get-FileHole, so 70x
          to 1100x more expensive. 100,000 files would be ~52 min idle, ~7.5 h held.
          The number is the boundary.
        * One RestartManager session is started and ended per call. RmEndSession runs in
          finally, so a throw cannot leak a session.
        * Registering a resource with RM does not restart, suspend, or close anything;
          nothing here calls RmShutdown / RmRestart.

      LAYOUT -- NOW MEASURED, not assumed (2026-10-22, 01-re\rm-stride2.ps1):
        Two concurrent holders were created on a fixture file and the filled block was
        dumped as raw bytes. Record 0's pid sits at byte 0, record 1's pid at byte **668**,
        and strAppName sits at +12 inside BOTH records. So:
          pid @ +0 ; FILETIME @ +4 (8) ; strAppName UTF-16 @ +12 (256 WCHAR, 512 B) ;
          strServiceShortName @ +524 (64 WCHAR, 128 B) ; ApplicationType @ +652 ;
          AppStatus @ +656 ; TSSessionId @ +660 ; bRestartable @ +664 ; STRIDE = 668.
        ** An earlier note in 01-re\q3-temp-file-rules.md said "stride 656". That was wrong
        and is corrected there: 656 only ever appeared to work because every real query on
        this box returned needed=1 -- with one record the stride is unobservable, and the
        656 attempt was simply the first one tried. **
        The recSize guard below clamps anything smaller than 668 up to 668. That clamp is
        load-bearing, not tidiness: it is what makes a caller-supplied 656 harmless, and it
        is the exact opposite of the mistake that crashed the host (allocating needed*656
        while reading fields out to +664 walks off the end of the last record ->
        0xC0000409). Do not remove it. Validate with two holders after any change.

      WHY the struct path is banned -- it is not that structs are impossible, it is that they
      are WRONG SILENTLY unless two invariants hold, and neither is testable on a box where
      every query returns needed=1. Measured tonight (01-re\rm-spec-struct-test.ps1 + the
      isolation matrix):
        * A struct whose Marshal.SizeOf is EXACTLY 668 does decode correctly at needed=1
          (int pid + int ftLo + int ftHi + ByValTStr(256) + ByValTStr(64) + 4x uint
          => 668; got back pid=<pid> name=[Windows PowerShell] type=1000, clean).
        * The recipe written in 02-design\criteria-spec.md line 585 cannot even be sized on
          this box: `[MarshalAs(UnmanagedType.U4)] bool` sitting next to a `ByValTStr` makes
          Marshal.SizeOf THROW "cannot be marshaled as an unmanaged structure". Isolated:
          ByValTStr(64) alone = 128 B ok; plus [U4]bool -> THROWS; bool replaced by uint ->
          132 B ok. So that line was never executed as written.
        * Drop the name SizeConst to 64 (also line 585) and the record stops being 668, so
          record 1+ is read at the wrong stride: strServiceShortName lands INSIDE the previous
          record's strAppName -- that is where the mojibake names came from, and allocating
          n*sizeof while RM writes n*668 is where 0xC0000409 came from.
        * Under holder churn the array path is worse than garbage: a second handle appearing
          between the size probe and the fill makes RmGetList return rc=234 while the CLR
          marshals back a ZEROED element that decodes as `pid=0 name=[]` -- a fabricated
          holder that type-checks. The loop below turns that into one retry plus an Error.
      So: if you ever switch this back to a struct, assert sizeof==668 at run time AND handle
      the MORE_DATA retry. Without both, the failure mode is a confident wrong answer.

      ApplicationType is the RM_APP_TYPE enum, decoded for you in .Holders[].TypeText:
        0 RmUnknownApp, 1 RmMainWindow, 2 RmOtherWindow, 3 RmService, 4 RmExplorer,
        5 RmConsole, 1000 RmCritical.
        Observed: Thunder's .xltd holder = 2 (RmOtherWindow); a console powershell.exe =
        5 (RmConsole); the harness parent = 1000 (RmCritical). Nothing here is a service.

      rc=234 IS SUCCESS HERE. The first RmGetList call (count=0, info=NULL) is a size
      probe; it returns ERROR_MORE_DATA(234) and sets pcNeeded. Treating a non-zero rc as
      failure is the second bug that produced my earlier wrong conclusion that Thunder's
      handles were invisible to RM. needed==0 after that probe is the only true
      "no holder" answer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string]$Path,
        [int]$RecordSize = 668,
        [switch]$ResolveProcess      # adds Path/ImagePath via Get-Process; costs one more query
    )
    process {
        if (-not ('RmHolders' -as [type])) {
            Add-Type -Language CSharp @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class RmHolders {
  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern int RmStartSession(out uint sess, uint flags, StringBuilder key);
  [DllImport("rstrtmgr.dll", SetLastError=true)]
  static extern int RmEndSession(uint sess);
  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern int RmRegisterResources(uint sess, uint nFiles, string[] files,
                                        uint nApps, IntPtr apps, uint nSvcs, IntPtr svcs);
  [DllImport("rstrtmgr.dll", SetLastError=true)]
  static extern int RmGetList(uint sess, out uint needed, ref uint count, IntPtr info, ref uint reasons);

  public class Holder {
    public int Pid; public string Name; public string Service;
    public int ApplicationType; public int AppStatus; public int SessionId; public bool Restartable;
  }
  public class Result {
    public string Error = "";            // "" means the query itself ran fine
    public int ProbeRc;                  // 234 = ERROR_MORE_DATA = expected
    public int FillRc;
    public uint Needed; public uint Written; public uint RebootReasons;
    public int RecSize;                  // EFFECTIVE size after the clamp, not the request
    public List<Holder> Holders = new List<Holder>();
  }

  // Offsets, not a struct. See the PowerShell header for why.
  const int OFF_PID = 0, OFF_NAME = 12, OFF_SVC = 524, OFF_TYPE = 652,
            OFF_STATUS = 656, OFF_SESS = 660, OFF_RESTART = 664;

  static string Cut(IntPtr p, int off, int maxChars) {
    string s = Marshal.PtrToStringUni((IntPtr)((long)p + off), maxChars);
    if (s == null) return "";
    int i = s.IndexOf('\0');
    if (i >= 0) s = s.Substring(0, i);
    return s.Trim();
  }

  // Raw dump, used only by 01-re\rm-stride-test.ps1 to MEASURE the record stride instead
  // of assuming it. Returns the filled block plus pcNeeded, so the caller can search for
  // each holder's pid and find the real record boundaries.
  public static byte[] Raw(string path, int recSize, out uint neededOut) {
    neededOut = 0;
    uint sess = 0;
    StringBuilder key = new StringBuilder(64);
    if (RmStartSession(out sess, 0, key) != 0) return null;
    try {
      if (RmRegisterResources(sess, 1, new string[] { path }, 0, IntPtr.Zero, 0, IntPtr.Zero) != 0) return null;
      uint needed = 0, count = 0, reasons = 0;
      RmGetList(sess, out needed, ref count, IntPtr.Zero, ref reasons);
      neededOut = needed;
      if (needed == 0) return new byte[0];
      int sz = (int)(needed * 4096);                 // deliberately huge: stride-agnostic
      IntPtr buf = Marshal.AllocHGlobal(sz);
      try {
        for (int i = 0; i < sz; i += 4) Marshal.WriteInt32(buf, i, 0);
        uint c2 = needed;
        if (RmGetList(sess, out needed, ref c2, buf, ref reasons) != 0) return null;
        byte[] data = new byte[sz];
        Marshal.Copy(buf, data, 0, sz);
        return data;
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { RmEndSession(sess); }
  }

  public static Result Query(string path, int recSize) {
    Result r = new Result();
    if (recSize < OFF_RESTART + 4) recSize = OFF_RESTART + 4;   // never read outside a record
    r.RecSize = recSize;                                        // report what was ACTUALLY used
    uint sess = 0;
    StringBuilder key = new StringBuilder(64);
    int rc = RmStartSession(out sess, 0, key);
    if (rc != 0) { r.Error = "RmStartSession=" + rc; return r; }
    try {
      rc = RmRegisterResources(sess, 1, new string[] { path }, 0, IntPtr.Zero, 0, IntPtr.Zero);
      if (rc != 0) { r.Error = "RmRegisterResources=" + rc; return r; }

      // Size probe. info=NULL, count=0. The documented return value for "there ARE
      // holders" is ERROR_MORE_DATA(234) -- that is the success signal, not a failure.
      uint count = 0;
      rc = RmGetList(sess, out r.Needed, ref count, IntPtr.Zero, ref r.RebootReasons);
      r.ProbeRc = rc;
      if (r.Needed == 0) {
        if (rc != 0 && rc != 234) r.Error = "RmGetList(probe)=" + rc;
        return r;                                  // needed==0 is the ONLY true no-holder answer
      }

      // +1 record of slack, and recSize>=668: reading OFF_STATUS/OFF_SESS out of a
      // needed*656-sized block ran past the end and killed the host with 0xC0000409 twice.
      //
      // Bounded retry, because the holder set CHURNS under us (measured: a two-holder fixture
      // came back probeRc=234 needed=1 then fillRc=234 -- a second holder appeared between
      // the size probe and the fill). RmGetList then writes NOTHING usable. The struct-array
      // path returns rc=234 with a zeroed element that decodes as "pid=0 name=[]", i.e. a
      // fabricated holder; here it becomes an Error plus one retry, and if the retry also
      // says MORE_DATA we report the error rather than an empty answer.
      for (int attempt = 0; attempt < 3; attempt++) {
        int sz = (int)((r.Needed + 1) * (uint)recSize);
        IntPtr buf = Marshal.AllocHGlobal(sz);
        try {
          for (int i = 0; i < sz; i += 4) Marshal.WriteInt32(buf, i, 0);   // no uninitialised reads
          uint c2 = r.Needed;
          rc = RmGetList(sess, out r.Needed, ref c2, buf, ref r.RebootReasons);
          r.FillRc = rc; r.Written = c2;
          if (rc == 234 && r.Needed > c2 && attempt < 2) { continue; }     // grew; try again bigger
          if (rc != 0 || c2 == 0) { r.Error = "RmGetList(fill)=" + rc; return r; }
          for (uint i = 0; i < c2; i++) {
            IntPtr p = (IntPtr)((long)buf + (long)i * recSize);
            Holder h = new Holder();
            h.Pid           = Marshal.ReadInt32(p, OFF_PID);
            h.Name          = Cut(p, OFF_NAME, 255);
            h.Service       = Cut(p, OFF_SVC, 63);
            h.ApplicationType = Marshal.ReadInt32(p, OFF_TYPE);
            h.AppStatus     = Marshal.ReadInt32(p, OFF_STATUS);
            h.SessionId     = Marshal.ReadInt32(p, OFF_SESS);
            h.Restartable   = Marshal.ReadInt32(p, OFF_RESTART) != 0;
            r.Holders.Add(h);
          }
        } finally { Marshal.FreeHGlobal(buf); }
        break;
      }
      return r;
    } finally { RmEndSession(sess); }
  }
}
'@
        }
        # LOUD ASSERTION, same reason as Get-FileHole: a failed Add-Type would otherwise
        # leave the function returning $null, and $null looks like "no holder".
        if (-not ('RmHolders' -as [type])) {
            throw 'Get-FileHolder: RmHolders failed to compile. $null would be indistinguishable from a correct no-holder answer, so this is fatal by design.'
        }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = [RmHolders]::Query($Path, [int]$RecordSize)
        $sw.Stop()

        $rmAppType = @{ 0='RmUnknownApp'; 1='RmMainWindow'; 2='RmOtherWindow'; 3='RmService';
                        4='RmExplorer'; 5='RmConsole'; 1000='RmCritical' }
        foreach ($h in $r.Holders) {
            # switch is a STATEMENT in PS 5.1 -- it cannot be inlined as an expression here.
            $tt = if ($rmAppType.ContainsKey($h.ApplicationType)) { $rmAppType[$h.ApplicationType] }
                   else { 'RM_APP_TYPE_' + $h.ApplicationType }
            $h | Add-Member -NotePropertyName TypeText -NotePropertyValue $tt -Force
            if ($ResolveProcess) {
                $p = Get-Process -Id $h.Pid -ErrorAction SilentlyContinue
                if ($p) {
                    $h | Add-Member -NotePropertyName ProcessPath -NotePropertyValue $p.Path -Force
                    $h | Add-Member -NotePropertyName ProcessName -NotePropertyValue $p.ProcessName -Force
                }
            }
        }
        [pscustomobject]@{
            Path         = $Path
            Error        = $r.Error                                   # '' = query succeeded
            HolderCount  = [int]$r.Holders.Count
            Needed       = [uint32]$r.Needed
            Written      = [uint32]$r.Written
            ProbeRc      = [int]$r.ProbeRc                            # 234 = expected, NOT failure
            FillRc       = [int]$r.FillRc
            RebootReasons= [uint32]$r.RebootReasons
            RecordSize   = [int]$r.RecSize        # EFFECTIVE, after the clamp
            ElapsedMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
            Holders      = @($r.Holders)
        }
    }
}

function Get-SparseFlag {
    <#  Free signal, no child process: the SparseFile attribute alone separated 59/59
        in-progress .xltd files from 6/6 completed files on this machine. Prefer this
        as the always-on screen and reserve Get-AllocRangeInfo for confirmation. #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Path)
    process {
        $i = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if (-not $i) { return $null }
        [pscustomobject]@{
            Path       = $Path
            Sparse     = ($i.Attributes -band [IO.FileAttributes]::SparseFile) -ne 0
            Compressed = ($i.Attributes -band [IO.FileAttributes]::Compressed) -ne 0
            Encrypted  = ($i.Attributes -band [IO.FileAttributes]::Encrypted) -ne 0
            Attributes = '' + $i.Attributes
        }
    }
}

function Get-UsnJournalState {
    <#  Query only; never creates or deletes a journal.
        Verified on this machine: C:\ HAS a journal (32 MB, v4) but
        "Write range tracking: Disabled", which means a USN record can tell us WHICH
        file was written, never WHICH BYTE RANGE. That caps what a journal-driven
        design can know, and is why the completion decision still needs the
        size/handle/allocation checks on top of the notification stream. #>
    [CmdletBinding()]
    param([string]$VolumeRoot = 'C:\')
    $o = $null
    try { $o = (& fsutil usn queryjournal $VolumeRoot) 2>&1 | Out-String } catch { }
    if (-not $o -or $o -notmatch 'Usn Journal ID') {
        return [pscustomobject]@{ Present = $false; VolumeRoot = $VolumeRoot; Raw = ($o -join '') }
    }
    $jid = if ($o -match 'Usn Journal ID\s*:\s*(0x[0-9a-fA-F]+)') { $Matches[1] } else { $null }
    $next = if ($o -match 'Next Usn\s*:\s*(0x[0-9a-fA-F]+)') { $Matches[1] } else { $null }
    $max = if ($o -match 'Maximum Size\s*:\s*0x[0-9a-fA-F]+\s*\(([^)]+)\)') { $Matches[1].Trim() } else { $null }
    $ver = if ($o -match 'Maximum record version supported\s*:\s*(\d+)') { [int]$Matches[1] } else { 0 }
    $wrt = if ($o -match 'Write range tracking:\s*(\w+)') { $Matches[1] } else { 'Unknown' }
    [pscustomobject]@{
        Present           = $true
        VolumeRoot        = $VolumeRoot
        JournalId         = $jid
        NextUsn           = $next
        MaxSize           = $max
        MaxRecordVersion  = $ver
        WriteRangeTracking= $wrt
        RangeAware        = ($wrt -eq 'Enabled')
    }
}
