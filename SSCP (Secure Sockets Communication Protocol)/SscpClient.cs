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
        private double _packetNumber, _serverPacketNumber;

        public SscpClient(string host, ushort port = 9987)
        {
            _uri = $"ws://{host}:{port}/SSCP/";
        }

        public async Task ConnectAsync()
        {
            _client = new ClientWebSocket();
            _packetNumber = _serverPacketNumber = 0.0;
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
            data = SscpUtils.Combine(BitConverter.GetBytes(_packetNumber), data);
            await _client.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, CancellationToken.None);
            _packetNumber += 0.0001;

            if (_packetNumber >= 1000000000000)
            {
                _packetNumber = 0.0;
            }
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

                byte[] data = receivedData.ToArray();
                receivedData.Clear();

                double packetNumber = BitConverter.ToDouble(data.Take(8).ToArray(), 0);

                if (packetNumber != _serverPacketNumber)
                {
                    await DisconnectAsync();
                    return;
                }

                data = data.Skip(8).ToArray();
                _serverPacketNumber = _serverPacketNumber + 0.0001;

                if (_serverPacketNumber >= 1000000000000)
                {
                    _serverPacketNumber = 0.0;
                }

                MessageReceived?.Invoke(data);
            }
        }
    }
}