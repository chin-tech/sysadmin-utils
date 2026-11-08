using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;

public class FileMoverService : ServiceBase
{
    private const string IncomingDir = @"C:\Incoming";
    private const string TargetShare = @"\\cw1\WindowsPenTools";
    private const string LogPath = @"C:\ProgramData\FileMover\service.log";

    private static readonly object _logLock = new object();

    private FileSystemWatcher _watcher;
    private Thread _worker;
    private readonly ManualResetEvent _stop = new ManualResetEvent(false);
    private readonly AutoResetEvent _wake = new AutoResetEvent(false);

    public FileMoverService()
    {
        ServiceName = "FileMoverService";
        CanShutdown = true;
    }

    static void Main()
    {
        ServiceBase.Run(new FileMoverService());
    }

    private static void Log(string message)
    {
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
            // Suppress logging failures to prevent crashing the service loop
        }
    }

    protected override void OnStart(string[] args)
    {
        Log("=== Service OnStart initiated ===");
        Log(string.Format("Running under Windows Identity: {0}", WindowsIdentity.GetCurrent().Name));

        try
        {
            if (!Directory.Exists(IncomingDir))
            {
                Directory.CreateDirectory(IncomingDir);
                Log(string.Format("Created Incoming directory: {0}", IncomingDir));
            }

            NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;

            _watcher = new FileSystemWatcher(IncomingDir)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            _watcher.Created += (s, e) =>
            {
                Log(string.Format("Watcher detected Created: {0}", e.FullPath));
                _wake.Set();
            };
            _watcher.Renamed += (s, e) =>
            {
                Log(string.Format("Watcher detected Renamed: {0}", e.FullPath));
                _wake.Set();
            };

            _worker = new Thread(WorkerLoop) { IsBackground = true, Name = "FileMover" };
            _worker.Start();

            Log("Service OnStart completed successfully.");
        }
        catch (Exception ex)
        {
            Log(string.Format("FATAL in OnStart: {0}", ex));
            throw; // Rethrow to inform SCM of failure
        }
    }

    protected override void OnStop()
    {
        Log("=== Service OnStop initiated ===");
        _stop.Set();
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        if (_watcher != null) _watcher.Dispose();
        if (_worker != null) _worker.Join(3000);
        Log("Service stopped cleanly.");
    }

    private void OnNetworkChanged(object sender, NetworkAvailabilityEventArgs e)
    {
        Log(string.Format("Network availability changed. IsAvailable: {0}", e.IsAvailable));
        if (e.IsAvailable) _wake.Set();
    }

    private void WorkerLoop()
    {
        WaitHandle[] handles = new WaitHandle[] { _stop, _wake };

        while (true)
        {
            if (_stop.WaitOne(0)) return;

            bool targetReachable = false;
            try
            {
                targetReachable = Directory.Exists(TargetShare);
            }
            catch (Exception ex)
            {
                Log(string.Format("Exception probing TargetShare: {0}", ex.Message));
            }

            if (!targetReachable)
            {
                Log(string.Format("TargetShare '{0}' is NOT accessible to identity {1}. Sleeping.", TargetShare, WindowsIdentity.GetCurrent().Name));
            }
            else
            {
                string[] files = Directory.GetFiles(IncomingDir);
                if (files.Length > 0)
                {
                    Log(string.Format("Found {0} files in incoming queue.", files.Length));
                }

                foreach (string path in files)
                {
                    if (_stop.WaitOne(0)) return;

                    TransferResult result = TryTransfer(path);
                    Log(string.Format("File: '{0}' -> Result: {1}", Path.GetFileName(path), result));

                    if (result == TransferResult.NetworkDown)
                    {
                        Log("Network dropped mid-transfer. Breaking batch loop.");
                        break;
                    }
                }
            }

            // Sleep 30s or until triggered
            int waitIndex = WaitHandle.WaitAny(handles, 30000);
            if (waitIndex == 0) return; // _stop signaled
        }
    }

    private enum TransferResult { Success, Locked, NetworkDown, Failed }

    private static TransferResult TryTransfer(string path)
    {
        // 1. Lock check
        try
        {
            using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
            }
        }
        catch (IOException ex)
        {
            Log(string.Format("Lock check: File '{0}' is locked by another process ({1})", Path.GetFileName(path), ex.Message));
            return TransferResult.Locked;
        }
        catch (UnauthorizedAccessException ex)
        {
            Log(string.Format("Lock check: Access Denied to source file '{0}' ({1})", Path.GetFileName(path), ex.Message));
            return TransferResult.Failed;
        }

        string name = Path.GetFileName(path);
        string dest = Path.Combine(TargetShare, name);
        string temp = dest + ".part";

        try
        {
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

            try
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
            catch { }

            if (ex is IOException && !Directory.Exists(TargetShare))
            {
                return TransferResult.NetworkDown;
            }

            return TransferResult.Failed;
        }
    }
}