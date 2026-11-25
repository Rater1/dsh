using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

internal static class CheckDshRunFixture
{
    private const int AccessDenied = 5;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);

    private static int OpenExisting(string path, uint access)
    {
        // OPEN_EXISTING with sharing for read, write and delete. No writes are made.
        using (var handle = CreateFileW(path, access, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero))
            return handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
    }

    public static int Main(string[] args)
    {
        try
        {
            if (args.Length != 0) return 3;
            var parent = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var root = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar);
            if (!Regex.IsMatch(root, "^" + Regex.Escape(parent) + @"\\DshRun-Acl-[0-9a-f]{32}$", RegexOptions.IgnoreCase) ||
                (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
                return 3;

            var sids = File.ReadAllLines(Path.Combine(root, "identities.txt"));
            if (sids.Length != 2 || sids[0] == sids[1]) return 3;
            bool holder;
            using (var identity = WindowsIdentity.GetCurrent())
            {
                holder = identity.User.Equals(new SecurityIdentifier(sids[0]));
                if (!holder && !identity.User.Equals(new SecurityIdentifier(sids[1]))) return 3;
                if (!holder && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 3;
            }

            var marker = Path.Combine(root, "public.txt");
            var credential = Path.Combine(root, "credential.fixture");
            var config = Path.Combine(root, "service.fixture.json");
            var probe = Path.Combine(root, "Check-DshRunFixture.exe");
            var codes = new Dictionary<string, int>();
            codes["public_read"] = OpenExisting(marker, 0x1);
            codes["credential_read"] = OpenExisting(credential, 0x1);
            codes["config_write"] = OpenExisting(config, 0x2);
            codes["config_append"] = OpenExisting(config, 0x4);
            codes["config_delete"] = OpenExisting(config, 0x10000);
            codes["config_change_acl"] = OpenExisting(config, 0x40000);
            codes["config_change_owner"] = OpenExisting(config, 0x80000);
            codes["probe_write"] = OpenExisting(probe, 0x2);
            codes["root_add_file"] = OpenExisting(root, 0x2);
            codes["root_delete_child"] = OpenExisting(root, 0x40);
            codes["root_delete"] = OpenExisting(root, 0x10000);
            codes["root_change_acl"] = OpenExisting(root, 0x40000);
            codes["parent_delete_child"] = OpenExisting(parent, 0x40);

            bool pass = codes["public_read"] == 0 && File.ReadAllText(marker) == "Public synthetic control";
            if (holder)
            {
                pass = pass && codes["credential_read"] == 0 && codes["config_write"] == 0 &&
                    File.ReadAllText(credential).StartsWith("SYNTHETIC-CREDENTIAL-ONLY-", StringComparison.Ordinal);
            }
            else
            {
                foreach (var code in codes)
                    if (code.Key != "public_read" && code.Value != AccessDenied) pass = false;
            }

            var result = new StringBuilder();
            result.Append("{\"role\":\"").Append(holder ? "holder" : "agent");
            result.Append("\",\"status\":\"").Append(pass ? "PASS" : "FAIL").Append("\",\"open_codes\":{");
            foreach (var code in codes)
                result.Append('"').Append(code.Key).Append("\":").Append(code.Value).Append(',');
            result.Length--;
            Console.WriteLine(result.Append("}}"));
            return pass ? 0 : 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("FIXTURE_CHECK_ERROR " + error.GetType().Name);
            return 3;
        }
    }
}
