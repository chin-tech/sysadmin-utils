using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;

public class JitBrokerService : ServiceBase
{
    private CancellationTokenSource _cts;
    private const string PipeName = "LocalElevationBroker";
    private const string ConfigPath = @"C:\ProgramData\JitBroker\allowed_users.txt";
    private const int ElevationMinutes = 15;

    public JitBrokerService()
    {
        this.ServiceName = "JitBrokerService";
        this.CanStop = true;
    }

    static void Main()
    {
        ServiceBase.Run(new JitBrokerService());
    }

    protected override void OnStart(string[] args)
    {
        _cts = new CancellationTokenSource();
        Task.Run(() => ListenForRequestsAsync(_cts.Token));
    }

    protected override void OnStop()
    {
        _cts.Cancel();
    }

    private async Task ListenForRequestsAsync(CancellationToken token)
    {
        // 1. Pipe Access Control: Restrict who can connect
        // Only grant access to specific accounts or groups (e.g., Authenticated Users or a specific group)
        PipeSecurity pipeSecurity = new PipeSecurity();

        // Allow SYSTEM full control
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow
        ));

        // Allow Authenticated Users (or replace with a specific user SID/NTAccount) Read/Write access
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow
        ));

        while (!token.IsCancellationRequested)
        {
            using (var server = new NamedPipeServerStream(
                PipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                1024,
                1024,
                pipeSecurity))
            {
                try
                {
                    await server.WaitForConnectionAsync(token);

                    // 2. Identify the caller via Windows Token (cannot be spoofed by text)
                    string callingIdentity = null;
                    server.RunAsClient(() =>
                    {
                        callingIdentity = WindowsIdentity.GetCurrent().Name;
                    });

                    using (var reader = new StreamReader(server))
                    using (var writer = new StreamWriter(server) { AutoFlush = true })
                    {
                        string request = await reader.ReadLineAsync();

                        if (string.IsNullOrWhiteSpace(request))
                        {
                            writer.WriteLine("ERR: Empty request");
                            continue;
                        }

                        // Expecting input format: "ELEVATE <username>"
                        string[] parts = request.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 2 || !parts[0].Equals("ELEVATE", StringComparison.OrdinalIgnoreCase))
                        {
                            writer.WriteLine("ERR: Invalid command syntax. Use: ELEVATE <username>");
                            continue;
                        }

                        string requestedUser = parts[1];

                        // 3. Verify against allowed_users.txt
                        if (!IsUserAuthorized(callingIdentity, requestedUser))
                        {
                            writer.WriteLine("ERR: Authorization failed or user not permitted.");
                            continue;
                        }

                        // 4. Perform elevation
                        bool elevated = SetAdminGroupMembership(requestedUser, add: true);
                        if (!elevated)
                        {
                            writer.WriteLine("ERR: Failed to add user to Administrators group.");
                            continue;
                        }

                        writer.WriteLine($"OK: {requestedUser} elevated for {ElevationMinutes} minutes.");

                        // 5. Asynchronous auto-revocation timer
                        _ = Task.Run(async () =>
                        {
                            await Task.Delay(TimeSpan.FromMinutes(ElevationMinutes));
                            SetAdminGroupMembership(requestedUser, add: false);
                        });
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception) { /* Log to Event Log or local diagnostics */ }
            }
        }
    }

    private bool IsUserAuthorized(string callingIdentity, string requestedUser)
    {
        if (!File.Exists(ConfigPath)) return false;

        try
        {
            // Read lines from the authorization text document
            var allowedEntries = File.ReadAllLines(ConfigPath)
                                     .Select(l => l.Trim())
                                     .Where(l => !string.IsNullOrEmpty(l) && !l.StartsWith("#"));

            // Check if calling process matches the requested target or is authorized
            // Entries in allowed_users.txt can be formatted as: DOMAIN\Username or Username
            bool isListed = allowedEntries.Any(entry =>
                entry.Equals(requestedUser, StringComparison.OrdinalIgnoreCase) ||
                entry.Equals(callingIdentity, StringComparison.OrdinalIgnoreCase));

            return isListed;
        }
        catch
        {
            return false;
        }
    }

    private bool SetAdminGroupMembership(string username, bool add)
    {
        try
        {
            // Connect to local machine SAM database
            using (var ctx = new PrincipalContext(ContextType.Machine))
            {
                using (var group = GroupPrincipal.FindByIdentity(ctx, "Administrators"))
                using (var user = UserPrincipal.FindByIdentity(ctx, username))
                {
                    if (group == null || user == null) return false;

                    if (add)
                    {
                        if (!group.Members.Contains(user))
                        {
                            group.Members.Add(user);
                            group.Save();
                        }
                    }
                    else
                    {
                        if (group.Members.Contains(user))
                        {
                            group.Members.Remove(user);
                            group.Save();
                        }
                    }
                    return true;
                }
            }
        }
        catch
        {
            return false;
        }
    }
}
