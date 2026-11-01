using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SyScan.Scanner.IPC;

namespace SyScan.Scanner.Recon;

public static class SystemReconnaissance
{
    [DllImport("kernel32.dll")]
    private static extern ulong GetTickCount64();

    public static SystemReconData Collect()
    {
        var data = new SystemReconData
        {
            OsVersion = Environment.OSVersion.VersionString,
            OsBuild = Environment.OSVersion.Version.Build.ToString(),
            Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            CurrentUserName = Environment.UserName,
            BootTimeUtc = DateTime.UtcNow.AddMilliseconds(-(double)GetTickCount64())
        };

        // Determine administrator status
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            data.CurrentUserSid = identity.User?.Value ?? string.Empty;
            var principal = new WindowsPrincipal(identity);
            data.IsAdministrator = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            data.IsAdministrator = false;
        }

        // Dynamically discover all fixed local drives
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                {
                    data.Drives.Add(new DriveReconInfo
                    {
                        Name = drive.Name,
                        VolumeLabel = drive.VolumeLabel,
                        DriveFormat = drive.DriveFormat,
                        TotalSizeBytes = drive.TotalSize,
                        AvailableFreeBytes = drive.AvailableFreeSpace,
                        IsReady = drive.IsReady
                    });
                }
            }
        }
        catch { }

        // Discover User Profiles
        try
        {
            string usersDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "..", "Users");
            string fullUsersDir = Path.GetFullPath(usersDir);
            if (Directory.Exists(fullUsersDir))
            {
                foreach (var dir in Directory.GetDirectories(fullUsersDir))
                {
                    string dirName = Path.GetFileName(dir);
                    if (!dirName.Equals("Public", StringComparison.OrdinalIgnoreCase) &&
                        !dirName.Equals("Default", StringComparison.OrdinalIgnoreCase) &&
                        !dirName.Equals("All Users", StringComparison.OrdinalIgnoreCase))
                    {
                        data.UserProfiles.Add(dir);
                    }
                }
            }
        }
        catch { }

        return data;
    }
}

