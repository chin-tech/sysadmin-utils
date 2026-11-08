
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using System.Security.Cryptography;
using System.Diagnostics;

public class FileMoverService : ServiceBase
{
    private const string Incoming = @"C:\Incoming";
    private const string Parent = @"\\server\share\destination";
    private static readonly string Target =
        Path.Combine(Parent, Environment.MachineName);

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

    public FileMoverService()
    {
        ServiceName = "FileMoverService";
        CanShutdown = true;
    }

    static void Main()
    {
        ServiceBase.Run(new FileMoverService());
    }

    protected override void OnStart(string[] args)
    {
        Directory.CreateDirectory(Incoming);

        _watcher = new FileSystemWatcher(Incoming);
        _watcher.Created += (s, e) => _wake.Set();
        _watcher.Renamed += (s, e) => _wake.Set();
        _watcher.Error += (s, e) => _wake.Set();
        _watcher.EnableRaisingEvents = true;

        _worker = new Thread(WorkerLoop) { IsBackground = true };
        _worker.Start();
    }

    protected override void OnStop()
    {
        _stop.Set();
        _wake.Set();

        if (_watcher != null) _watcher.Dispose();
        if (_worker != null) _worker.Join(3000);
    }

    private void WorkerLoop()
    {
        WaitHandle[] handles = { _stop, _wake };

        while (!_stop.WaitOne(0))
        {
            try
            {
                if (Directory.Exists(Parent))
                {
                    foreach (string path in Directory.GetFiles(Incoming))
                    {
                        if (_stop.WaitOne(0)) return;
                        if (Transfer(path) == 2) break;
                    }
                }
            }
            catch (Exception ex)
            {
                Log(ex);
            }

            if (WaitHandle.WaitAny(handles, 15000) == 0)
                return;
        }
    }

    private static void Log(Exception ex)
    {
        try
        {
            EventLog.WriteEntry("FileMoverService",
                ex.ToString(), EventLogEntryType.Error);
        }
        catch { }
    }

    private static bool HashesMatch(Stream source, string dest)
    {
        using (var sha = SHA256.Create())
        using (var file = File.OpenRead(dest))
        {
            source.Position = 0;
            byte[] a = sha.ComputeHash(source);
            byte[] b = sha.ComputeHash(file);

            return StructuralComparisons
                .StructuralEqualityComparer.Equals(a, b);
        }
    }

    // 0 = success, 1 = skip/failure, 2 = offline
    private static int Transfer(string path)
    {
        string sub;
        if (!Routes.TryGetValue(Path.GetExtension(path), out sub))
            return 1;

        string dir = Path.Combine(Target, sub);
        string dest = Path.Combine(dir, Path.GetFileName(path));
        string temp = dest + ".part";

        try
        {
            using (var src = File.Open(path, FileMode.Open,
                       FileAccess.Read, FileShare.None))
            {
                Directory.CreateDirectory(dir);

                if (File.Exists(dest))
                {
                    if (!HashesMatch(src, dest))
                        return 1;
                }
                else
                {
                    using (var dst = File.Create(temp))
                    {
                        src.CopyTo(dst);
                        dst.Flush(true);
                    }

                    if (!HashesMatch(src, temp))
                        return 1;

                    File.Move(temp, dest);
                }
            }

            File.Delete(path);
            return 0;
        }
        catch (Exception ex)
        {
            Log(ex);
            return Directory.Exists(Parent) ? 1 : 2;
        }
    }
}

// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /optimize+ /out:C:\FileMover\FileMoverService.exe /r:System.dll,System.ServiceProcess.dll C:\FileMover\FileMoverService.cs
//
// :: Enable debug logging
//# Register event source (elevated, once)
// New-EventLog -LogName Application -Source FileMoverService
// sc.exe create FileMoverService binPath= "C:\FileMover\FileMoverService.exe" start= auto DisplayName= "FileMover [C:\Incoming -> \\server\share\dest\%COMPUTERNAME%]"
// sc.exe description FileMoverService "Routes .pdl and .txt files to hostname shares."
//sc.exe failure FileMoverService reset= 86400 actions= restart/5000/restart/15000/restart/30000
