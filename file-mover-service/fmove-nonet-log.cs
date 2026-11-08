using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;

public class FileMoverService : ServiceBase
{
    private const string IncomingDir = @"C:\Incoming";
    private const string ParentShare = @"\\server\share\destination";
    private const string LogPath = @"C:\ProgramData\FileMover\service.log";

    // Base destination: \\server\share\destination\COMPUTERNAME
    private static readonly string TargetDir = Path.Combine(ParentShare, Environment.MachineName);

    // Extension routing table: .ext -> relative subfolder under TargetDir
    private static readonly Dictionary<string, string> ExtensionRoutes =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { ".pdl", "pdl" },
            { ".txt", "logs" }
        };

    private static bool _debugEnabled = false;
    private static readonly object _logLock = new object();

    private FileSystemWatcher _watcher;
    private Thread _worker;
    private readonly ManualResetEvent _stop = new ManualResetEvent(false);
    private readonly AutoResetEvent _wake = new AutoResetEvent(false);

    #region Win32 SCM Description Interop
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ChangeServiceConfig2(IntPtr hService, uint dwInfoLevel, ref SERVICE_DESCRIPTION lpInfo);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ChangeServiceConfig(
        IntPtr hService, uint dwServiceType, uint dwStartType, uint dwErrorControl,
        string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId,
        string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_DESCRIPTION
    {
        public string lpDescription;
    }

    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_CHANGE_CONFIG = 0x0002;
    private const uint SERVICE_CONFIG_DESCRIPTION = 1;
    private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
    #endregion

    public FileMoverService()
    {
        ServiceName = "FileMoverService";
        CanShutdown = true;
    }

    static void Main(string[] args)
    {
        EvaluateDebugFlag(args);
        ServiceBase.Run(new FileMoverService());
    }

    private static void EvaluateDebugFlag(string[] args)
    {
        if (args != null)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].IndexOf("debug", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    _debugEnabled = true;
                    return;
                }
            }
        }

        string env = Environment.GetEnvironmentVariable("FILEMOVER_DEBUG", EnvironmentVariableTarget.Machine);
        if (!string.IsNullOrEmpty(env) && (env == "1" || env.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            _debugEnabled = true;
        }
    }

    private static void Log(string message)
    {
        if (!_debugEnabled) return;

        try
        {
            string dir = Path.GetDirectoryName(LogPath);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

            string line = string.Format("[{0:yyyy-MM-dd HH:mm:ss.fff}] {1}", DateTime.Now, message);
            lock (_logLock)
            {
                File.AppendAllText(LogPath, line + Environment.NewLine);
            }
        }
        catch
        {
        }
    }

    protected override void OnStart(string[] args)
    {
        EvaluateDebugFlag(args);
        UpdateScmMetadata();

        Log("=== Service OnStart initiated ===");
        Log(string.Format("Host: {0} | Running As: {1}", Environment.MachineName, WindowsIdentity.GetCurrent().Name));
        Log(string.Format("Target Base: {0}", TargetDir));

        try
        {
            if (!Directory.Exists(IncomingDir))
            {
                Directory.CreateDirectory(IncomingDir);
                Log(string.Format("Created Incoming directory: {0}", IncomingDir));
            }

            _watcher = new FileSystemWatcher(IncomingDir)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            _watcher.Created += (s, e) => _wake.Set();
            _watcher.Renamed += (s, e) => _wake.Set();

            _worker = new Thread(WorkerLoop)
            {
                IsBackground = true,
                Name = "FileMover"
            };
            _worker.Start();

            Log("Service OnStart completed successfully.");
        }
        catch (Exception ex)
        {
            Log(string.Format("FATAL in OnStart: {0}", ex));
            throw;
        }
    }

    protected override void OnStop()
    {
        Log("=== Service OnStop initiated ===");
        _stop.Set();

        if (_watcher != null)
        {
            _watcher.EnableRaisingEvents = false;
            _watcher.Dispose();
        }

        if (_worker != null)
        {
            _worker.Join(3000);
        }

        Log("Service stopped cleanly.");
    }

    private void WorkerLoop()
    {
        WaitHandle[] handles = new WaitHandle[] { _stop, _wake };

        while (true)
        {
            if (_stop.WaitOne(0)) return;

            bool parentReachable = false;
            try
            {
                parentReachable = Directory.Exists(ParentShare);
            }
            catch (Exception ex)
            {
                Log(string.Format("Exception probing ParentShare: {0}", ex.Message));
            }

            if (!parentReachable)
            {
                Log(string.Format("ParentShare '{0}' unreachable or access denied.", ParentShare));
            }
            else
            {
                string[] files = Directory.GetFiles(IncomingDir);
                if (files.Length > 0)
                {
                    Log(string.Format("Processing {0} file(s) in incoming directory.", files.Length));
                }

                foreach (string path in files)
                {
                    if (_stop.WaitOne(0)) return;

                    TransferResult result = TryTransfer(path);
                    Log(string.Format("File: '{0}' -> Result: {1}", Path.GetFileName(path), result));

                    if (result == TransferResult.ShareOffline)
                    {
                        Log("Target share dropped during transfer.");
                        break;
                    }
                }
            }

            int waitIndex = WaitHandle.WaitAny(handles, 15000);
            if (waitIndex == 0) return;
        }
    }

    private enum TransferResult { Success, Locked, ShareOffline, Ignored, Failed }

    private static TransferResult TryTransfer(string path)
    {
        string ext = Path.GetExtension(path);
        string subFolder;

        // Check routing map; if extension is not monitored, skip
        if (string.IsNullOrEmpty(ext) || !ExtensionRoutes.TryGetValue(ext, out subFolder))
        {
            return TransferResult.Ignored;
        }

        // 1. In-flight write-lock check
        try
        {
            using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
            }
        }
        catch (IOException ex)
        {
            Log(string.Format("File locked: '{0}' ({1})", Path.GetFileName(path), ex.Message));
            return TransferResult.Locked;
        }
        catch (UnauthorizedAccessException ex)
        {
            Log(string.Format("Access denied to local file: '{0}' ({1})", Path.GetFileName(path), ex.Message));
            return TransferResult.Failed;
        }

        // 2. Prepare destination path: \\server\share\destination\COMPUTERNAME\<subfolder>\<filename>
        string finalTargetFolder = Path.Combine(TargetDir, subFolder);
        string name = Path.GetFileName(path);
        string dest = Path.Combine(finalTargetFolder, name);
        string temp = dest + ".part";

        try
        {
            // Ensure destination subfolder exists
            if (!Directory.Exists(finalTargetFolder))
            {
                Directory.CreateDirectory(finalTargetFolder);
                Log(string.Format("Created destination subfolder: {0}", finalTargetFolder));
            }

            File.Copy(path, temp, true);

            if (File.Exists(dest))
            {
                File.Delete(dest);
            }

            File.Move(temp, dest);
            File.Delete(path);

            return TransferResult.Success;
        }
        catch (Exception ex)
        {
            Log(string.Format("Transfer error on '{0}': [{1}] {2}", name, ex.GetType().Name, ex.Message));

            try { if (File.Exists(temp)) File.Delete(temp); } catch { }

            if (ex is IOException && !Directory.Exists(ParentShare))
            {
                return TransferResult.ShareOffline;
            }

            return TransferResult.Failed;
        }
    }

    private void UpdateScmMetadata()
    {
        IntPtr hScManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (hScManager == IntPtr.Zero) return;

        try
        {
            IntPtr hService = OpenService(hScManager, ServiceName, SERVICE_CHANGE_CONFIG);
            if (hService == IntPtr.Zero) return;

            try
            {
                string displayName = string.Format("FileMover [{0} -> {1}\\{{pdl|logs}}]", IncomingDir, TargetDir);
                ChangeServiceConfig(
                    hService, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                    null, null, IntPtr.Zero, null, null, null, displayName);

                SERVICE_DESCRIPTION desc = new SERVICE_DESCRIPTION
                {
                    lpDescription = string.Format("Routes .pdl and .txt files from '{0}' to '{1}\\pdl' and '{1}\\logs'.", IncomingDir, TargetDir)
                };
                ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, ref desc);
            }
            finally
            {
                CloseServiceHandle(hService);
            }
        }
        finally
        {
            CloseServiceHandle(hScManager);
        }
    }
}

// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /optimize+ /out:C:\FileMover\FileMoverService.exe /r:System.dll,System.ServiceProcess.dll C:\FileMover\FileMoverService.cs

// :: Enable debug logging
// sc.exe config FileMoverService binPath= "\"C:\FileMover\FileMoverService.exe\" --debug"
// sc.exe stop FileMoverService
// sc.exe start FileMoverService

// :: Disable debug logging (revert to clean binary path)
// sc.exe config FileMoverService binPath= "\"C:\FileMover\FileMoverService.exe\""
// sc.exe stop FileMoverService
// sc.exe start FileMoverService
