using System;
using System.Collections.Generic;
using System.IO;
using System.ServiceProcess;
using System.Threading;

public class FileMoverService : ServiceBase
{
    private const string Incoming = @"C:\Incoming";
    private const string Parent = @"\\server\share\destination";
    private static readonly string Target = Path.Combine(Parent, Environment.MachineName);

    private static readonly Dictionary<string, string> Routes =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { ".pdl", "pdl" },
            { ".txt", "logs" }
        };

    private FileSystemWatcher _watcher;
    private Thread _worker;
    private readonly ManualResetEvent _stop = new ManualResetEvent(false);
    private readonly AutoResetEvent _wake = new AutoResetEvent(false);

    public FileMoverService() { ServiceName = "FileMoverService"; CanShutdown = true; }

    static void Main() { ServiceBase.Run(new FileMoverService()); }

    protected override void OnStart(string[] args)
    {
        Directory.CreateDirectory(Incoming);

        _watcher = new FileSystemWatcher(Incoming) { EnableRaisingEvents = true };
        _watcher.Created += (s, e) => _wake.Set();
        _watcher.Renamed += (s, e) => _wake.Set();

        _worker = new Thread(WorkerLoop) { IsBackground = true };
        _worker.Start();
    }

    protected override void OnStop()
    {
        _stop.Set();
        if (_watcher != null) _watcher.Dispose();
        if (_worker != null) _worker.Join(3000);
    }

    private void WorkerLoop()
    {
        WaitHandle[] handles = new WaitHandle[] { _stop, _wake };

        while (true)
        {
            if (_stop.WaitOne(0)) return;

            if (Directory.Exists(Parent))
            {
                foreach (string path in Directory.GetFiles(Incoming))
                {
                    if (_stop.WaitOne(0)) return;
                    if (Transfer(path) == 2) break; // 2 = share offline
                }
            }

            if (WaitHandle.WaitAny(handles, 15000) == 0) return;
        }
    }

    private static int Transfer(string path) // 0=ok, 1=skip/lock, 2=offline
    {
        string ext = Path.GetExtension(path);
        string sub;
        if (string.IsNullOrEmpty(ext) || !Routes.TryGetValue(ext, out sub)) return 1;

        try
        {
            using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
        }
        catch { return 1; }

        string dir = Path.Combine(Target, sub);
        string name = Path.GetFileName(path);
        string dest = Path.Combine(dir, name);
        string temp = dest + ".part";

        try
        {
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.Copy(path, temp, true);
            if (File.Exists(dest)) File.Delete(dest);
            File.Move(temp, dest);
            File.Delete(path);
            return 0;
        }
        catch (Exception ex)
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
            return (ex is IOException && !Directory.Exists(Parent)) ? 2 : 1;
        }
    }
}

// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /optimize+ /out:C:\FileMover\FileMoverService.exe /r:System.dll,System.ServiceProcess.dll C:\FileMover\FileMoverService.cs
//
// :: Enable debug logging
// sc.exe create FileMoverService binPath= "C:\FileMover\FileMoverService.exe" start= auto DisplayName= "FileMover [C:\Incoming -> \\server\share\dest\%COMPUTERNAME%]"
// sc.exe description FileMoverService "Routes .pdl and .txt files to hostname shares."
