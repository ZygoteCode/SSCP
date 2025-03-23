using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using SSCP.Utils;

namespace SSCP
{
    public class SscpServerUser
    {
        private readonly SscpServer _server;
        private readonly WebSocket _webSocket;
        private readonly IPEndPoint _ipEndPoint;
        private readonly SscpCompressionContext _sscpCompressionContext = new();
        private readonly SscpCompressionContext _otherSscpCompressionContext = new();
        private readonly SemaphoreSlim _sendLock = new(1, 1);

        public bool Connected => _webSocket.State == WebSocketState.Open;
        public IPEndPoint ConnectionIpEndPoint => _ipEndPoint;
        public string ConnectionIpAddress => _ipEndPoint.Address.ToString();
        public int ConnectionPort => _ipEndPoint.Port;
        public SscpServer Server => _server;
        public string ID { get; set; }
        public double PacketNumber { get; set; }
        public double ServerPacketNumber { get; set; }
        public List<byte[]> PacketIds { get; set; } = new();
        public HashSet<byte[]> ServerPacketIds { get; set; } = new();
        public byte HandshakeStep { get; set; }
        public RSACryptoServiceProvider ToClientRSA { get; set; }
        public RSACryptoServiceProvider FromClientRSA { get; set; }
        public byte[]? AesTempKey { get; set; }
        public byte[] AesKey { get; set; }
        public bool HandshakeCompleted { get; set; }
        public DateTime ConnectedSince { get; set; }
        public byte[] SecretWebSocketKey { get; }
        public long LastKeepAliveTimestamp { get; set; }
        public Dictionary<object, object> Properties { get; set;  } = new();

        public SscpServerUser(SscpServer server, WebSocket webSocket, IPEndPoint ipEndPoint, string id, byte[] secretWebSocketKey)
        {
            LastKeepAliveTimestamp = SscpUtils.GetTimestamp();
            _server = server;
            _webSocket = webSocket;
            _ipEndPoint = ipEndPoint;
            ID = id;
            PacketNumber = 0.0;
            ServerPacketNumber = 0.0;
            HandshakeStep = 0;
            SecretWebSocketKey = secretWebSocketKey;
        }

        public byte[] Decompress(byte[] data)
        {
            return _sscpCompressionContext.Decompress(data);
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

        public async Task SendAsync(byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA, CancellationToken cancellationToken = default)
        {
            await _sendLock.WaitAsync(cancellationToken);

            try
            {
                byte[] generatedKeyPart = SscpUtils.GetRandomByteArray(SscpGlobal.PACKET_GENERATED_KEY_LENGTH);
                byte[] packetId = SscpUtils.GeneratePacketID();

                data = SscpUtils.Combine(BitConverter.GetBytes(ServerPacketNumber), packetId, BitConverter.GetBytes(SscpUtils.GetTimestamp()), data);
                byte[] hash = SscpUtils.HashWithKeccak256(data);
                data = SscpUtils.Combine(hash, data);

                if (AesKey != null)
                {
                    data = SscpUtils.ProcessAES256(data, SscpUtils.Combine(AesKey.Skip(SscpGlobal.PACKET_GENERATED_KEY_LENGTH).ToArray(), generatedKeyPart), HandshakeStep == 4 ? SecretWebSocketKey : SscpGlobal.EMPTY_IV, true);
                    byte[] theHash = SscpUtils.HashWithKeccak256(data);
                    data = SscpUtils.Combine(theHash, data);
                }

                data = _otherSscpCompressionContext.Compress(data);
                data = SscpUtils.Combine(generatedKeyPart, BitConverter.GetBytes((int)sscpPacketType), SscpUtils.HashWithKeccak256(data), data);

                await _webSocket.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, CancellationToken.None);
                ServerPacketNumber = (ServerPacketNumber + SscpGlobal.PACKET_NUMBER_INCREMENTAL) % SscpGlobal.MAX_PACKET_NUMBER;
                ServerPacketIds.Add(packetId);

                if (ServerPacketIds.Count > SscpGlobal.PACKET_ID_MAX_COUNT)
                {
                    ServerPacketIds.Clear();
                }
            }
            finally
            {
                _sendLock.Release();
            }
        }

        public void Send(byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(data, sscpPacketType).GetAwaiter().GetResult();
        }

        public async Task SendAsync(string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            await SendAsync(Encoding.UTF8.GetBytes(data), sscpPacketType);
        }

        public void Send(string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(data, sscpPacketType).GetAwaiter().GetResult();
        }

        public async Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer)
        {
            return await _webSocket.ReceiveAsync(buffer, CancellationToken.None);
        }
    }
}