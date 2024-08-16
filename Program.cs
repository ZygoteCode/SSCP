using System.Text;

class Program
{
    private static SscpClient _sscpClient;
    private static SscpServer _sscpServer;

    public static async Task Main(string[] args)
    {
        _sscpClient = new SscpClient("127.0.0.1", 9987);
        _sscpClient.ConnectionOpened += _sscpClient_ConnectionOpened;
        _sscpClient.ConnectionClosed += _sscpClient_ConnectionClosed;
        _sscpClient.MessageReceived += _sscpClient_MessageReceived;

        _sscpServer = new SscpServer(9987);
        _sscpServer.UserConnected += _sscpServer_UserConnected;
        _sscpServer.UserDisconnected += _sscpServer_UserDisconnected;
        _sscpServer.MessageReceived += _sscpServer_MessageReceived;

        new Thread(() =>
        {
            _sscpServer.StartAsync().GetAwaiter().GetResult();
        }).Start();

        await _sscpClient.ConnectAsync();

        while (true)
        {
            await _sscpClient.SendAsync(Encoding.UTF8.GetBytes(Console.ReadLine()!));
        }
    }

    private static void _sscpServer_UserConnected(SscpServerUser obj)
    {
        Console.WriteLine($"[SERVER] A new User has been connected (IP: {obj.ConnectionIpAddress}, Port: {obj.ConnectionPort}).");
    }

    private static void _sscpServer_UserDisconnected(SscpServerUser obj)
    {
        Console.WriteLine("[SERVER] A connected User has been disconnected.");
    }

    private static void _sscpServer_MessageReceived(SscpServerUser arg1, byte[] arg2)
    {
        Console.WriteLine($"[SERVER] A new message from a User has been received => {Encoding.UTF8.GetString(arg2)}");
    }

    private static void _sscpClient_ConnectionOpened()
    {
        Console.WriteLine("[CLIENT] The connection to the Server has been opened.");
    }

    private static void _sscpClient_ConnectionClosed()
    {
        Console.WriteLine("[CLIENT] The connection to the Server is now closed.");
    }

    private static void _sscpClient_MessageReceived(byte[] obj)
    {
        Console.WriteLine($"[CLIENT] A new message from the Server has been received => {Encoding.UTF8.GetString(obj)}");
    }
}