using System.Buffers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using SSCP.Utils;

namespace SSCP
{
    internal class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y))
                return true;
            if (x == null || y == null || x.Length != y.Length)
                return false;
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] != y[i])
                    return false;
            }
            return true;
        }

        public int GetHashCode(byte[] obj)
        {
            unchecked
            {
                int hash = 17;
                // Usa alcuni byte per il calcolo dell'hash (dato che la lunghezza è fissa)
                for (int i = 0; i < Math.Min(obj.Length, 8); i++)
                {
                    hash = hash * 31 + obj[i];
                }
                return hash;
            }
        }
    }

    public class SscpClient
    {
        public event Action? ConnectionOpened, ConnectionClosed;
        public event Action<SscpPacket>? PacketReceived;

        private ClientWebSocket _client;
        private readonly string _uri;
        private double _packetNumber, _serverPacketNumber;
        private byte _handshakeStep;
        private RSACryptoServiceProvider _fromServerRSA, _toServerRSA;

        private HashSet<byte[]> _serverPacketIds = new HashSet<byte[]>(new ByteArrayComparer());

        private byte[] _aesKey;
        private string _currentId, _currentIpAddress;
        private int _currentPort;
        private DateTime _connectedSince;
        private byte[] _secretWebSocketKey;
        private SscpCompressionContext _sscpCompressionContext, _otherSscpCompressionContext;
        private long _lastKeepAliveTimestamp;

        private TaskCompletionSource<bool> _handshakeTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private Timer _keepAliveTimer;

        public string ID => _currentId;
        public string IpAddress => _currentIpAddress;
        public int Port => _currentPort;
        public bool Connected => _client.State == WebSocketState.Open;
        public DateTime ConnectedSince => _connectedSince;

        public SscpClient(string host, bool secure = false, ushort port = SscpGlobal.DEFAULT_PORT)
        {
            _uri = $"ws{(secure ? "s" : "")}://{host}{(!secure ? (":" + port) : "")}{SscpGlobal.DEFAULT_URL_SLUG}";
        }

        public async Task ConnectAsync()
        {
            _lastKeepAliveTimestamp = SscpUtils.GetTimestamp();
            _client = new ClientWebSocket();
            _client.Options.AddSubProtocol("SSCP");
            _sscpCompressionContext = new SscpCompressionContext();
            _otherSscpCompressionContext = new SscpCompressionContext();
            _packetNumber = _serverPacketNumber = 0.0;
            _secretWebSocketKey = SscpGlobal.EMPTY_IV;
            _handshakeStep = 0;
            _serverPacketIds.Clear();

            await _client.ConnectAsync(new Uri(_uri), CancellationToken.None);
            _handshakeStep = 1;

            if (_client.SubProtocol != "SSCP")
            {
                Disconnect();
                return;
            }

            _ = Task.Run(ReceiveMessages);

            await _handshakeTcs.Task;

            _keepAliveTimer = new Timer(state =>
            {
                if (!Connected)
                {
                    _keepAliveTimer?.Dispose();
                    return;
                }
                long now = SscpUtils.GetTimestamp();
                if (now - _lastKeepAliveTimestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                {
                    Disconnect();
                    return;
                }
            }, null, 3000, 3000);
        }

        public void Connect()
        {
            ConnectAsync().GetAwaiter().GetResult();
        }

        public async Task DisconnectAsync()
        {
            try
            {
                if (_client != null && _client.State == WebSocketState.Open)
                {
                    await _client.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                }
            }
            finally
            {
                _client?.Dispose();
                _keepAliveTimer?.Dispose();
                ConnectionClosed?.Invoke();
            }
        }

        public void Disconnect()
        {
            DisconnectAsync().GetAwaiter().GetResult();
        }

        public async Task SendAsync(byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            await _handshakeTcs.Task;
            await SendAsyncPrivate(data, sscpPacketType);
        }

        private async Task SendAsyncPrivate(byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            byte[] generatedKeyPart = SscpUtils.GetRandomByteArray(SscpGlobal.PACKET_GENERATED_KEY_LENGTH);
            byte[] packetId = SscpUtils.GeneratePacketID();

            data = SscpUtils.Combine(BitConverter.GetBytes(_packetNumber), packetId, BitConverter.GetBytes(SscpUtils.GetTimestamp()), data);
            byte[] hash = SscpUtils.HashWithKeccak256(data);
            data = SscpUtils.Combine(hash, data);

            if (_aesKey != null)
            {
                data = SscpUtils.ProcessAES256(data,
                    SscpUtils.Combine(_aesKey.Skip(SscpGlobal.PACKET_GENERATED_KEY_LENGTH).ToArray(), generatedKeyPart),
                    _secretWebSocketKey, true);
                byte[] theHash = SscpUtils.HashWithKeccak256(data);
                data = SscpUtils.Combine(theHash, data);
            }

            data = _sscpCompressionContext.Compress(data);
            byte[] compressedDataHash = SscpUtils.HashWithKeccak256(data);
            data = SscpUtils.Combine(generatedKeyPart, BitConverter.GetBytes((int)sscpPacketType), compressedDataHash, data);

            await _client.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, CancellationToken.None);
            _packetNumber += SscpGlobal.PACKET_NUMBER_INCREMENTAL;
            if (_packetNumber >= SscpGlobal.MAX_PACKET_NUMBER)
            {
                _packetNumber = 0.0;
            }
        }

        public async Task SendAsync(string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            await SendAsync(Encoding.UTF8.GetBytes(data), sscpPacketType);
        }

        public void Send(byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(data, sscpPacketType).GetAwaiter().GetResult();
        }

        public void Send(string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(data, sscpPacketType).GetAwaiter().GetResult();
        }

        private async Task ReceiveMessages()
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(SscpGlobal.DEFAULT_BUFFER_SIZE);
            try
            {
                while (_client.State == WebSocketState.Open)
                {
                    int totalBytes = 0;
                    using (var ms = new MemoryStream())
                    {
                        WebSocketReceiveResult result;
                        do
                        {
                            result = await _client.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                            ms.Write(buffer, 0, result.Count);
                        }
                        while (!result.EndOfMessage);

                        byte[] data = ms.ToArray();

                        byte[] generatedKeyPart = data.Take(SscpGlobal.PACKET_GENERATED_KEY_LENGTH).ToArray();
                        data = data.Skip(SscpGlobal.PACKET_GENERATED_KEY_LENGTH).ToArray();

                        SscpPacketType sscpPacketType = (SscpPacketType)BitConverter.ToInt32(data.Take(SscpGlobal.INTEGER_SIZE).ToArray());
                        data = data.Skip(SscpGlobal.INTEGER_SIZE).ToArray();

                        byte[] compressedDataHash = data.Take(SscpGlobal.HASH_SIZE).ToArray();
                        data = data.Skip(SscpGlobal.HASH_SIZE).ToArray();
                        byte[] currentCompressedDataHash = SscpUtils.HashWithKeccak256(data);
                        if (!SscpUtils.CompareByteArrays(compressedDataHash, currentCompressedDataHash))
                        {
                            await DisconnectAsync();
                            return;
                        }

                        data = _otherSscpCompressionContext.Decompress(data);

                        if (_aesKey != null)
                        {
                            byte[] theHash = data.Take(SscpGlobal.HASH_SIZE).ToArray();
                            data = data.Skip(SscpGlobal.HASH_SIZE).ToArray();
                            byte[] theNewHash = SscpUtils.HashWithKeccak256(data);
                            if (!SscpUtils.CompareByteArrays(theHash, theNewHash))
                            {
                                await DisconnectAsync();
                                return;
                            }
                            data = SscpUtils.ProcessAES256(data,
                                SscpUtils.Combine(_aesKey.Skip(5).ToArray(), generatedKeyPart),
                                _secretWebSocketKey, false);
                        }

                        byte[] hash = data.Take(SscpGlobal.HASH_SIZE).ToArray();
                        data = data.Skip(SscpGlobal.HASH_SIZE).ToArray();
                        byte[] newHash = SscpUtils.HashWithKeccak256(data);
                        if (!SscpUtils.CompareByteArrays(hash, newHash))
                        {
                            await DisconnectAsync();
                            return;
                        }

                        double packetNumber = BitConverter.ToDouble(data.Take(SscpGlobal.DOUBLE_SIZE).ToArray(), 0);
                        if (packetNumber != _serverPacketNumber)
                        {
                            await DisconnectAsync();
                            return;
                        }
                        data = data.Skip(SscpGlobal.DOUBLE_SIZE).ToArray();

                        byte[] packetId = data.Take(SscpGlobal.HASH_SIZE).ToArray();
                        if (_serverPacketIds.Contains(packetId))
                        {
                            await DisconnectAsync();
                            return;
                        }
                        data = data.Skip(SscpGlobal.HASH_SIZE).ToArray();

                        long timestamp = BitConverter.ToInt64(data.Take(SscpGlobal.LONG_SIZE).ToArray());
                        if (SscpUtils.GetTimestamp() - timestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                        {
                            await DisconnectAsync();
                            return;
                        }
                        data = data.Skip(SscpGlobal.LONG_SIZE).ToArray();

                        _serverPacketNumber += SscpGlobal.PACKET_NUMBER_INCREMENTAL;
                        if (_serverPacketNumber >= SscpGlobal.MAX_PACKET_NUMBER)
                        {
                            _serverPacketNumber = 0.0;
                        }

                        _serverPacketIds.Add(packetId);
                        if (_serverPacketIds.Count > SscpGlobal.PACKET_ID_MAX_COUNT)
                        {
                            _serverPacketIds.Clear();
                        }

                        switch (_handshakeStep)
                        {
                            case 1:
                                _fromServerRSA = new RSACryptoServiceProvider();
                                _fromServerRSA.FromXmlString(Encoding.UTF8.GetString(data));
                                _toServerRSA = new RSACryptoServiceProvider(SscpGlobal.RSA_KEY_LENGTH);
                                await SendAsyncPrivate(Encoding.UTF8.GetBytes(_toServerRSA.ToXmlString(false)));
                                _handshakeStep = 2;
                                break;
                            case 2:
                                byte[] aesKey = SscpUtils.GetRandomByteArray(SscpGlobal.MID_HASH_SIZE);
                                await SendAsyncPrivate(_fromServerRSA.Encrypt(aesKey, false));
                                _aesKey = SscpUtils.Combine(_toServerRSA.Decrypt(data, false), aesKey);
                                _handshakeStep = 3;
                                break;
                            case 3:
                                _currentId = Encoding.UTF8.GetString(data.Take(SscpGlobal.STRING_HASH_SIZE).ToArray());
                                data = data.Skip(SscpGlobal.STRING_HASH_SIZE).ToArray();
                                int ipLength = BitConverter.ToInt32(data.Take(SscpGlobal.INTEGER_SIZE).ToArray());
                                data = data.Skip(SscpGlobal.INTEGER_SIZE).ToArray();
                                _currentIpAddress = Encoding.UTF8.GetString(data.Take(ipLength).ToArray());
                                data = data.Skip(ipLength).ToArray();
                                _currentPort = BitConverter.ToInt32(data.Take(SscpGlobal.INTEGER_SIZE).ToArray());
                                data = data.Skip(SscpGlobal.INTEGER_SIZE).ToArray();
                                _secretWebSocketKey = data.Take(SscpGlobal.MID_HASH_SIZE).ToArray();

                                _handshakeStep = 4;
                                _connectedSince = DateTime.UtcNow;
                                ConnectionOpened?.Invoke();
                                _handshakeTcs.TrySetResult(true);
                                break;
                            case 4:
                                PacketReceived?.Invoke(new SscpPacket(sscpPacketType, data));
                                if (sscpPacketType.Equals(SscpPacketType.KEEP_ALIVE))
                                {
                                    long keepAliveTimestamp = BitConverter.ToInt64(data),
                                         currentKeepAliveTimestamp = SscpUtils.GetTimestamp();
                                    if (currentKeepAliveTimestamp - keepAliveTimestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                                    {
                                        await DisconnectAsync();
                                        return;
                                    }
                                    Send(BitConverter.GetBytes(currentKeepAliveTimestamp), SscpPacketType.KEEP_ALIVE);
                                    _lastKeepAliveTimestamp = keepAliveTimestamp;
                                }
                                break;
                        }
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }
}