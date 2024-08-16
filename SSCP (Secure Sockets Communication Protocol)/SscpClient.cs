using System.Net.WebSockets;
using System.Text;

namespace SSCP
{
    public class SscpClient
    {
        public event Action? ConnectionOpened, ConnectionClosed;
        public event Action<byte[]>? MessageReceived;

        private ClientWebSocket _client;
        private string _uri;

        public SscpClient(string host, ushort port = 9987)
        {
            _uri = $"ws://{host}:{port}/SSCP/";
        }

        public async Task ConnectAsync()
        {
            _client = new ClientWebSocket();
            await _client.ConnectAsync(new Uri(_uri), CancellationToken.None);
            ConnectionOpened?.Invoke();
            Task.Run(async () =>
            {
                await ReceiveMessages();
            });
        }

        public void Connect()
        {
            ConnectAsync().GetAwaiter().GetResult();
        }

        public async Task DisconnectAsync()
        {
            await _client.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
            _client.Dispose();
        }

        public void Disconnect()
        {
            DisconnectAsync().GetAwaiter().GetResult();
        }

        public async Task SendAsync(byte[] data)
        {
            await _client.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, CancellationToken.None);
        }

        public async Task SendAsync(string data)
        {
            await SendAsync(Encoding.UTF8.GetBytes(data));
        }

        public void Send(byte[] data)
        {
            SendAsync(data).GetAwaiter().GetResult();
        }

        public void Send(string data)
        {
            SendAsync(data).GetAwaiter().GetResult();
        }

        private async Task ReceiveMessages()
        {
            byte[] buffer = new byte[1024 * 4];
            List<byte> receivedData = new List<byte>();

            while (_client.State == WebSocketState.Open)
            {
                WebSocketReceiveResult result;

                do
                {
                    result = await _client.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                    receivedData.AddRange(buffer.Take(result.Count));
                }
                while (!result.EndOfMessage);

                MessageReceived?.Invoke(receivedData.ToArray());
                receivedData.Clear();
            }
        }
    }
}