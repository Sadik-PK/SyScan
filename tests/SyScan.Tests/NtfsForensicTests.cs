using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SyScan.Scanner.Ntfs;
using Xunit;

namespace SyScan.Tests;

public class NtfsForensicTests
{
    [Fact]
    public void UsnJournalReader_ParsesSyntheticRecordV2()
    {
        // Build a synthetic USN_RECORD_V2 buffer
        // Size: 60 bytes header + filename bytes
        string fileName = "injector.exe";
        byte[] fileNameBytes = Encoding.Unicode.GetBytes(fileName);
        ushort nameLen = (ushort)fileNameBytes.Length;
        ushort nameOffset = 60;
        uint recordLen = (uint)(nameOffset + nameLen);

        byte[] buffer = new byte[recordLen];
        BitConverter.GetBytes(recordLen).CopyTo(buffer, 0); // RecordLength
        BitConverter.GetBytes((ushort)2).CopyTo(buffer, 4); // MajorVersion 2
        BitConverter.GetBytes((ushort)0).CopyTo(buffer, 6); // MinorVersion 0
        BitConverter.GetBytes((ulong)123456).CopyTo(buffer, 8); // FRN
        BitConverter.GetBytes((ulong)987654).CopyTo(buffer, 16); // Parent FRN
        BitConverter.GetBytes((long)1000).CopyTo(buffer, 24); // USN
        BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(buffer, 32); // Timestamp
        BitConverter.GetBytes((uint)0x00000200).CopyTo(buffer, 40); // Reason: FILE_DELETE
        BitConverter.GetBytes(nameLen).CopyTo(buffer, 56); // FileNameLength
        BitConverter.GetBytes(nameOffset).CopyTo(buffer, 58); // FileNameOffset
        fileNameBytes.CopyTo(buffer, nameOffset);

        var records = UsnJournalReader.ParseBuffer(buffer, 0, buffer.Length);

        Assert.Single(records);
        Assert.Equal("injector.exe", records[0].FileName);
        Assert.True(records[0].IsFileDelete);
        Assert.True(records[0].IsSuspicious);
        Assert.Contains("FILE_DELETE", records[0].ReasonDescriptions);
    }

    [Fact]
    public void UsnJournalReader_CorrelatesRenameAndDeleteSequences()
    {
        var records = new List<UsnRecordEntry>
        {
            // Event 1: File created
            new UsnRecordEntry
            {
                FileReferenceNumber = 555,
                FileName = "vape_client.exe",
                ReasonRaw = 0x00000100, // FILE_CREATE
                TimestampUtc = DateTime.UtcNow.AddMinutes(-10)
            },
            // Event 2: File renamed before delete
            new UsnRecordEntry
            {
                FileReferenceNumber = 555,
                FileName = "temp_123.tmp",
                ReasonRaw = 0x00002000, // RENAME_OLD_NAME
                TimestampUtc = DateTime.UtcNow.AddMinutes(-5)
            },
            // Event 3: File deleted
            new UsnRecordEntry
            {
                FileReferenceNumber = 555,
                FileName = "temp_123.tmp",
                ReasonRaw = 0x00000200, // FILE_DELETE
                TimestampUtc = DateTime.UtcNow.AddMinutes(-2)
            }
        };

        var result = UsnJournalReader.CorrelateDeletions(records);

        Assert.Single(result.RecentDeletions);
        Assert.Equal(3, result.RenamedBeforeDelete.Count);
        Assert.Contains(result.RenamedBeforeDelete, r => r.FileName == "vape_client.exe");
    }

    [Fact]
    public void TimestompDetector_DetectsFutureDates()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"timestomp_test_{Guid.NewGuid():N}.exe");
        try
        {
            File.WriteAllText(tempFile, "fake binary content");
            // Set future date
            File.SetCreationTimeUtc(tempFile, DateTime.UtcNow.AddDays(10));

            var analysis = TimestompDetector.AnalyzeFile(tempFile);
            Assert.True(analysis.TimestompDetected);
            Assert.Contains("future", analysis.DetectionReason, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }
}

