using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SyScan.Scanner.Ntfs;

public sealed class UsnRecordEntry
{
    public ulong FileReferenceNumber { get; set; }
    public ulong ParentFileReferenceNumber { get; set; }
    public long Usn { get; set; }
    public DateTime TimestampUtc { get; set; }
    public uint ReasonRaw { get; set; }
    public string FileName { get; set; } = string.Empty;
    public List<string> ReasonDescriptions { get; set; } = new();

    public bool IsFileCreate => (ReasonRaw & 0x00000100) != 0;
    public bool IsFileDelete => (ReasonRaw & 0x00000200) != 0;
    public bool IsRenameOldName => (ReasonRaw & 0x00002000) != 0;
    public bool IsRenameNewName => (ReasonRaw & 0x00004000) != 0;
    public bool IsClose => (ReasonRaw & 0x80000000) != 0;
    public bool IsSuspicious { get; set; }
}

public sealed class DeletionInvestigationResult
{
    public List<UsnRecordEntry> RecentDeletions { get; set; } = new();
    public List<UsnRecordEntry> RenamedBeforeDelete { get; set; } = new();
    public List<UsnRecordEntry> SuspiciousGameDeletions { get; set; } = new();
    public int TotalRecordsAnalyzed { get; set; }
    public bool VolumeJournalAccessible { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}

public static class UsnJournalReader
{
    // Win32 Constants
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
    private const uint FSCTL_READ_USN_JOURNAL = 0x000900bb;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct READ_USN_JOURNAL_DATA_V0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    private static readonly Dictionary<uint, string> ReasonMap = new()
    {
        { 0x00000001, "DATA_OVERWRITE" },
        { 0x00000002, "DATA_EXTEND" },
        { 0x00000004, "DATA_TRUNCATION" },
        { 0x00000010, "NAMED_DATA_OVERWRITE" },
        { 0x00000020, "NAMED_DATA_EXTEND" },
        { 0x00000040, "NAMED_DATA_TRUNCATION" },
        { 0x00000100, "FILE_CREATE" },
        { 0x00000200, "FILE_DELETE" },
        { 0x00000400, "EA_CHANGE" },
        { 0x00000800, "SECURITY_CHANGE" },
        { 0x00001000, "RENAME_OLD_NAME" },
        { 0x00002000, "RENAME_OLD_NAME" },
        { 0x00004000, "RENAME_NEW_NAME" },
        { 0x00008000, "INDEXABLE_CHANGE" },
        { 0x00010000, "BASIC_INFO_CHANGE" },
        { 0x00020000, "HARD_LINK_CHANGE" },
        { 0x00040000, "COMPRESSION_CHANGE" },
        { 0x00080000, "ENCRYPTION_CHANGE" },
        { 0x00100000, "OBJECT_ID_CHANGE" },
        { 0x00200000, "REPARSE_POINT_CHANGE" },
        { 0x00400000, "STREAM_CHANGE" },
        { 0x00800000, "TRANSACTED_CHANGE" },
        { 0x80000000, "CLOSE" }
    };

    public static List<UsnRecordEntry> ParseBuffer(byte[] buffer, int offset, int length)
    {
        var records = new List<UsnRecordEntry>();
        int current = offset;

        while (current + 60 <= offset + length)
        {
            uint recordLen = BitConverter.ToUInt32(buffer, current);
            if (recordLen == 0 || current + recordLen > offset + length)
                break;

            ushort majorVersion = BitConverter.ToUInt16(buffer, current + 4);
            if (majorVersion == 2)
            {
                ulong frn = BitConverter.ToUInt64(buffer, current + 8);
                ulong parentFrn = BitConverter.ToUInt64(buffer, current + 16);
                long usn = BitConverter.ToInt64(buffer, current + 24);
                long fileTime = BitConverter.ToInt64(buffer, current + 32);
                uint reason = BitConverter.ToUInt32(buffer, current + 40);
                ushort fileNameLength = BitConverter.ToUInt16(buffer, current + 56);
                ushort fileNameOffset = BitConverter.ToUInt16(buffer, current + 58);

                string fileName = string.Empty;
                if (fileNameLength > 0 && current + fileNameOffset + fileNameLength <= offset + length)
                {
                    fileName = Encoding.Unicode.GetString(buffer, current + fileNameOffset, fileNameLength);
                }

                DateTime timestamp = DateTime.UtcNow;
                if (fileTime > 0)
                {
                    try { timestamp = DateTime.FromFileTimeUtc(fileTime); } catch { }
                }

                var record = new UsnRecordEntry
                {
                    FileReferenceNumber = frn,
                    ParentFileReferenceNumber = parentFrn,
                    Usn = usn,
                    TimestampUtc = timestamp,
                    ReasonRaw = reason,
                    FileName = fileName
                };

                // Decode reasons
                foreach (var kvp in ReasonMap)
                {
                    if ((reason & kvp.Key) != 0)
                    {
                        record.ReasonDescriptions.Add(kvp.Value);
                    }
                }

                string lower = fileName.ToLowerInvariant();
                if (lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".bat") ||
                    lower.EndsWith(".ps1") || lower.EndsWith(".sys") || lower.Contains("cheat") ||
                    lower.Contains("vape") || lower.Contains("inject") || lower.Contains("drip"))
                {
                    record.IsSuspicious = true;
                }

                records.Add(record);
            }

            current += (int)recordLen;
        }

        return records;
    }

    public static DeletionInvestigationResult CorrelateDeletions(List<UsnRecordEntry> records)
    {
        var result = new DeletionInvestigationResult
        {
            TotalRecordsAnalyzed = records.Count
        };

        var byFrn = new Dictionary<ulong, List<UsnRecordEntry>>();
        foreach (var r in records)
        {
            if (!byFrn.ContainsKey(r.FileReferenceNumber))
            {
                byFrn[r.FileReferenceNumber] = new List<UsnRecordEntry>();
            }
            byFrn[r.FileReferenceNumber].Add(r);

            if (r.IsFileDelete)
            {
                result.RecentDeletions.Add(r);
                if (r.IsSuspicious)
                {
                    result.SuspiciousGameDeletions.Add(r);
                }
            }
        }

        // Identify rename-and-delete sequences: FRN that had RENAME_OLD/NEW then FILE_DELETE
        foreach (var kvp in byFrn)
        {
            var frnHistory = kvp.Value;
            bool hadRename = false;
            bool hadDelete = false;

            foreach (var step in frnHistory)
            {
                if (step.IsRenameOldName || step.IsRenameNewName)
                    hadRename = true;
                if (step.IsFileDelete)
                    hadDelete = true;
            }

            if (hadRename && hadDelete)
            {
                result.RenamedBeforeDelete.AddRange(frnHistory);
            }
        }

        return result;
    }

    public static DeletionInvestigationResult ScanLiveVolumeJournal(string driveLetter = "C:", int maxRecords = 10000)
    {
        var result = new DeletionInvestigationResult();
        string volumePath = $@"\\.\{driveLetter.TrimEnd('\\')}";

        IntPtr handle = CreateFile(
            volumePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (handle == IntPtr.Zero || handle.ToInt64() == -1)
        {
            result.VolumeJournalAccessible = false;
            result.StatusMessage = "USN Change Journal requires Administrator privileges to open volume handle.";
            return result;
        }

        try
        {
            int journalDataSize = Marshal.SizeOf<USN_JOURNAL_DATA_V0>();
            IntPtr pJournalData = Marshal.AllocHGlobal(journalDataSize);

            bool querySuccess = DeviceIoControl(
                handle,
                FSCTL_QUERY_USN_JOURNAL,
                IntPtr.Zero,
                0,
                pJournalData,
                (uint)journalDataSize,
                out uint bytesReturned,
                IntPtr.Zero);

            if (!querySuccess)
            {
                result.VolumeJournalAccessible = false;
                result.StatusMessage = "Failed to query USN journal metadata from volume.";
                Marshal.FreeHGlobal(pJournalData);
                return result;
            }

            var journalData = Marshal.PtrToStructure<USN_JOURNAL_DATA_V0>(pJournalData);
            Marshal.FreeHGlobal(pJournalData);

            result.VolumeJournalAccessible = true;

            // Prepare read request: read backward from NextUsn or last chunk
            const int BUFFER_SIZE = 64 * 1024;
            byte[] managedBuffer = new byte[BUFFER_SIZE];
            IntPtr pBuffer = Marshal.AllocHGlobal(BUFFER_SIZE);

            var readData = new READ_USN_JOURNAL_DATA_V0
            {
                StartUsn = Math.Max(0, journalData.NextUsn - (10L * 1024 * 1024)), // last 10MB of USN events
                ReasonMask = 0xFFFFFFFF,
                ReturnOnlyOnClose = 0,
                Timeout = 0,
                BytesToWaitFor = 0,
                UsnJournalID = journalData.UsnJournalID
            };

            IntPtr pReadData = Marshal.AllocHGlobal(Marshal.SizeOf<READ_USN_JOURNAL_DATA_V0>());
            Marshal.StructureToPtr(readData, pReadData, false);

            var allRecords = new List<UsnRecordEntry>();

            bool readSuccess = DeviceIoControl(
                handle,
                FSCTL_READ_USN_JOURNAL,
                pReadData,
                (uint)Marshal.SizeOf<READ_USN_JOURNAL_DATA_V0>(),
                pBuffer,
                (uint)BUFFER_SIZE,
                out uint readBytes,
                IntPtr.Zero);

            if (readSuccess && readBytes > 8)
            {
                Marshal.Copy(pBuffer, managedBuffer, 0, (int)readBytes);
                // First 8 bytes of output buffer is the NextUSN
                int recordsOffset = 8;
                int recordsLength = (int)readBytes - 8;
                allRecords.AddRange(ParseBuffer(managedBuffer, recordsOffset, recordsLength));
            }

            Marshal.FreeHGlobal(pReadData);
            Marshal.FreeHGlobal(pBuffer);

            var correlation = CorrelateDeletions(allRecords);
            correlation.VolumeJournalAccessible = true;
            correlation.StatusMessage = $"Successfully scanned USN Journal. Found {allRecords.Count} records.";
            return correlation;
        }
        catch (Exception ex)
        {
            result.StatusMessage = $"USN Journal read error: {ex.Message}";
            return result;
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}

