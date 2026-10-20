using System;
using System.IO;
using System.IO.Pipes;
using System.Text;

class PipeSend
{
    private const string DefaultPipe = "LocalElevationBroker";
    private const int TimeoutMs = 4000;

    static int Main(string[] args)
    {
        string pipeName = DefaultPipe;
        string payload = null;

        // 1. Parse arguments or read standard input
        if (args.Length > 0)
        {
            // Optional syntax: PipeSend.exe -p <PipeName> <Payload...>
            if (args[0].Equals("-p", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
            {
                pipeName = args[1];
                payload = string.Join(" ", args, 2, args.Length - 2);
            }
            else
            {
                payload = string.Join(" ", args);
            }
        }
        else if (Console.IsInputRedirected)
        {
            // Allows reading from stdin: echo ELEVATE Alice | PipeSend.exe
            using (var reader = new StreamReader(Console.OpenStandardInput()))
            {
                payload = reader.ReadToEnd()?.Trim();
            }
        }

        if (string.IsNullOrWhiteSpace(payload))
        {
            Console.Error.WriteLine("Usage: PipeSend.exe [-p PipeName] <Message>");
            return 1;
        }

        // 2. Connect and transmit
        try
        {
            using (var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut))
            {
                client.Connect(TimeoutMs);

                using (var writer = new StreamWriter(client, Encoding.UTF8) { AutoFlush = true })
                using (var reader = new StreamReader(client, Encoding.UTF8))
                {
                    // Transmit request
                    writer.WriteLine(payload);

                    // Read broker response
                    string response = reader.ReadLine();
                    if (!string.IsNullOrEmpty(response))
                    {
                        Console.WriteLine(response);
                        if (response.StartsWith("ERR", StringComparison.OrdinalIgnoreCase))
                        {
                            return 2;
                        }
                    }
                }
            }
            return 0;
        }
        catch (TimeoutException)
        {
            Console.Error.WriteLine($"Error: Connection timed out after {TimeoutMs}ms. Is the broker service running?");
            return 3;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            return 4;
        }
    }
}
