using System;
using System.Security.Cryptography.X509Certificates;

namespace SyScan.Scanner.FileSystem;

public record DigitalSignatureInfo(
    bool IsSigned,
    string? Subject,
    string? Issuer,
    string? Thumbprint,
    DateTime? ValidFrom,
    DateTime? ValidTo,
    bool IsTrustedVendor
);

public static class AuthenticodeVerifier
{
    private static readonly string[] KnownTrustedVendors =
    [
        "Microsoft Corporation",
        "Valve Corp",
        "Epic Games Inc",
        "Riot Games",
        "Rockstar Games",
        "Electronic Arts",
        "Ubisoft Entertainment",
        "EasyAntiCheat",
        "BattlEye Innovations",
        "Unity Technologies",
        "Mojang AB",
        "Take-Two Interactive"
    ];

    public static DigitalSignatureInfo Verify(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            var baseCert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            if (baseCert == null)
            {
                return new DigitalSignatureInfo(false, null, null, null, null, null, false);
            }

            using var cert = new X509Certificate2(baseCert);
            string subject = cert.Subject;
            string issuer = cert.Issuer;
            string thumbprint = cert.Thumbprint;
            DateTime validFrom = cert.NotBefore;
            DateTime validTo = cert.NotAfter;

            bool isTrusted = false;
            foreach (var vendor in KnownTrustedVendors)
            {
                if (subject.Contains(vendor, StringComparison.OrdinalIgnoreCase) ||
                    issuer.Contains(vendor, StringComparison.OrdinalIgnoreCase))
                {
                    isTrusted = true;
                    break;
                }
            }

            return new DigitalSignatureInfo(
                IsSigned: true,
                Subject: subject,
                Issuer: issuer,
                Thumbprint: thumbprint,
                ValidFrom: validFrom,
                ValidTo: validTo,
                IsTrustedVendor: isTrusted
            );
        }
        catch
        {
            // Unsigned or signature extraction failed
            return new DigitalSignatureInfo(false, null, null, null, null, null, false);
        }
    }
}
