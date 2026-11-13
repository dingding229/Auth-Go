using AuthGo;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

var guard = Bootstrap.Current;
using var stopping = new CancellationTokenSource();
using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; stopping.Cancel(); });
using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, context => { context.Cancel = true; stopping.Cancel(); });
string listen = "0.0.0.0:8080";
for (int i = 0; i + 1 < args.Length; i++) if (args[i] == "-listen") listen = args[i + 1];
var address = listen.Split(':');
var server = new TcpListener(address[0].Length == 0 ? IPAddress.Any : IPAddress.Parse(address[0]), int.Parse(address[1]));
server.Start();
Console.WriteLine("HTTP已启动");
try {
    while (!stopping.IsCancellationRequested && !guard.Done.IsCompleted) {
        using var socket = await server.AcceptTcpClientAsync(stopping.Token);
        socket.ReceiveTimeout = 200; socket.SendTimeout = 200;
        try {
            var stream = socket.GetStream();
            var request = new byte[1024]; stream.Read(request);
            guard.Require();
            var body = JsonSerializer.Serialize(new { marker = "AUTHGO_payload_PROTECTED_CORE", language = "csharp",
                unique = "AUTHGO_payload_CSHARP_CORE", features = guard.Result.Features });
            var bytes = Encoding.UTF8.GetBytes(body);
            var headers = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
            stream.Write(headers); stream.Write(bytes);
        } catch (IOException) { }
    }
} catch (OperationCanceledException) when (stopping.IsCancellationRequested) {
} finally {
    server.Stop();
}
// Bootstrap's ProcessExit handler releases the same Guard, including SIGTERM.
return stopping.IsCancellationRequested ? 0 : Guard.ExitLicense;
