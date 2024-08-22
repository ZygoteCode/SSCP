using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using SSCP.Utils;

namespace SSCP
{
    public class SscpServerUser
    {
        private SscpServer _server;
        private WebSocket _webSocket;
        private IPEndPoint _ipEndPoint;
        private string _id;

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
        public List<byte[]> ServerPacketIds { get; set; }
        public byte HandshakeStep { get; set; }
        public RSACryptoServiceProvider ToClientRSA { get; set; }
        public RSACryptoServiceProvider FromClientRSA { get; set; }
        public byte[]? AesTempKey { get; set; }
        public byte[] AesKey { get; set; }
        public bool HandshakeCompleted { get; set; }
        public DateTime ConnectedSince { get; set; }
        public byte[] SecretWebSocketKey { get; set; }

        public SscpServerUser(SscpServer server, WebSocket webSocket, IPEndPoint ipEndPoint, string id, byte[] secretWebSocketKey)
        {
            _server = server;
            _webSocket = webSocket;
            _ipEndPoint = ipEndPoint;
            ID = id;
            PacketNumber = 0.0;
            ServerPacketNumber = 0.0;
            PacketIds = new List<byte[]>();
            ServerPacketIds = new List<byte[]>();
            HandshakeStep = 0;
            SecretWebSocketKey = secretWebSocketKey;
        }

        public void Dispose()
        {
            _webSocket.Dispose();
        }

        public async Task KickAsync()
        {
            while (!HandshakeCompleted)
            {
                await Task.Delay(1);
            }

            await KickAsyncPrivate();
        }

        private async Task KickAsyncPrivate()
        {
            await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
        }

        public void Kick()
        {
            KickAsync().GetAwaiter().GetResult();
        }

        public async Task SendAsync(byte[] data)
        {
            byte[] packetId = SscpUtils.GeneratePacketID();

            data = SscpUtils.Combine(BitConverter.GetBytes(ServerPacketNumber), packetId, BitConverter.GetBytes(SscpUtils.GetTimestamp()), data);
            byte[] hash = SscpUtils.HashKeccak256(data);
            data = SscpUtils.Combine(hash, data);

            if (AesKey != null)
            {
                data = SscpUtils.ProcessAES256(data, AesKey, HandshakeStep == 4 ? SecretWebSocketKey : SscpGlobal.EMPTY_IV, true);
                byte[] theHash = SscpUtils.HashKeccak256(data);
                data = SscpUtils.Combine(theHash, data);
            }

            await _webSocket.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, CancellationToken.None);
            ServerPacketNumber += SscpGlobal.PACKET_NUMBER_INCREMENTAL;

            if (ServerPacketNumber >= SscpGlobal.MAX_PACKET_NUMBER)
            {
                ServerPacketNumber = 0.0;
            }

            ServerPacketIds.Add(packetId);

            if (ServerPacketIds.Count > SscpGlobal.PACKET_ID_MAX_COUNT)
            {
                ServerPacketIds.Clear();
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