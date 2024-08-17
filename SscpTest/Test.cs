using SSCP;
using System.Text;

public class Test
{
    private static SscpServer _sscpServer;
    private static SscpClient _sscpClient;

    public static void Main()
    {
        _sscpServer = new SscpServer(9987);
        _sscpClient = new SscpClient("127.0.0.1", 9987);

        new Thread(() =>
        {
            _sscpServer.UserConnected += SscpServer_UserConnected;
            _sscpServer.UserDisconnected += SscpServer_UserDisconnected;
            _sscpServer.MessageReceived += SscpServer_MessageReceived;
            _sscpServer.Start();
        }).Start();

        _sscpClient.ConnectionOpened += SscpClient_ConnectionOpened;
        _sscpClient.ConnectionClosed += SscpClient_ConnectionClosed;
        _sscpClient.MessageReceived += SscpClient_MessageReceived;
        _sscpClient.Connect();

        while (true)
        {
            _sscpClient.Send(Console.ReadLine()!);
        }
    }

    private static void SscpClient_MessageReceived(byte[] obj)
    {
        Console.WriteLine($"[CLIENT] A new message has been received from the Server => {Encoding.UTF8.GetString(obj)}");
    }

    private static void SscpClient_ConnectionClosed()
    {
        Console.WriteLine($"[CLIENT] The client has closed the connection with the Server.");
    }

    private static void SscpClient_ConnectionOpened()
    {
        Console.WriteLine($"[CLIENT] The client is now connected to the Server. Connection IP Address: {_sscpClient.IpAddress}, connection port: {_sscpClient.Port}, unique ID: {_sscpClient.ID}.");
    }

    private static void SscpServer_UserDisconnected(SscpServerUser obj)
    {
        Console.WriteLine($"[SERVER] A connected User is now disconnected. Connection IP address: {obj.ConnectionIpAddress}, connection port: {obj.ConnectionPort}, unique ID: {obj.ID}.");
    }

    private static void SscpServer_UserConnected(SscpServerUser obj)
    {
        Console.WriteLine($"[SERVER] A new User has been connected to the Server. Connection IP address: {obj.ConnectionIpAddress}, connection port: {obj.ConnectionPort}, unique ID: {obj.ID}.");
    }

    private static void SscpServer_MessageReceived(SscpServerUser arg1, byte[] arg2)
    {
        Console.WriteLine($"[SERVER] A User ({arg1.ID}) has sent a new message to the Server => {Encoding.UTF8.GetString(arg2)}");
    }
}