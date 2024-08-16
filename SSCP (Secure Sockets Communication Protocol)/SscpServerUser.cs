using System.Net;
using System.Net.WebSockets;
using System.Text;

namespace SSCP
{
    public class SscpServerUser
    {
        private SscpServer _server;
        private WebSocket _webSocket;
        private IPEndPoint _ipEndPoint;
        private string _id;
        private double _packetNumber, _serverPacketNumber;

        public bool Connected
        {
            get
            {
                return _webSocket.State == WebSocketState.Open;
            }
        }

        public IPEndPoint ConnectionIpEndPoint
        {
            get
            {
                return _ipEndPoint;
            }
        }

        public string ConnectionIpAddress
        {
            get
            {
                return _ipEndPoint.Address.ToString();
            }
        }

        public int ConnectionPort
        {
            get
            {
                return _ipEndPoint.Port;
            }
        }

        public string ID { get; set; }

        public double PacketNumber { get; set; }

        public double ServerPacketNumber { get; set; }

        public List<byte[]> PacketIds { get; set; }

        public SscpServerUser(SscpServer server, WebSocket webSocket, IPEndPoint ipEndPoint, string id)
        {
            _server = server;
            _webSocket = webSocket;
            _ipEndPoint = ipEndPoint;
            ID = id;
            PacketNumber = 0.0;
            ServerPacketNumber = 0.0;
            PacketIds = new List<byte[]>();
        }

        public void Dispose()
        {
            _webSocket.Dispose();
        }

        public async Task KickAsync()
        {
            await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
        }

        public void Kick()
        {
            KickAsync().GetAwaiter().GetResult();
        }

        public async Task SendAsync(byte[] data)
        {
            data = SscpUtils.Combine(BitConverter.GetBytes(_serverPacketNumber), data);
            await _webSocket.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, CancellationToken.None);
            _serverPacketNumber += 0.0001;

            if (_serverPacketNumber >= 1000000000000)
            {
                _serverPacketNumber = 0.0;
            }
        }

        public void Send(byte[] data)
        {
            SendAsync(data).GetAwaiter().GetResult();
        }

        public async Task SendAsync(string data)
        {
            await SendAsync(Encoding.UTF8.GetBytes(data));
        }

        public void Send(string data)
        {
            SendAsync(data).GetAwaiter().GetResult();
        }

        public async Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer)
        {
            return await _webSocket.ReceiveAsync(buffer, CancellationToken.None);
        }
    }
}