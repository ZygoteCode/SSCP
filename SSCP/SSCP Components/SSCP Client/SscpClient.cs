﻿using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using SSCP.Utils;

namespace SSCP
{
    public class SscpClient
    {
        public event Action? ConnectionOpened, ConnectionClosed;
        public event Action<SscpPacket>? PacketReceived;

        private ClientWebSocket _client;
        private string _uri;
        private double _packetNumber, _serverPacketNumber;
        private byte _handshakeStep;
        private RSACryptoServiceProvider _fromServerRSA, _toServerRSA;

        private List<byte[]> _serverPacketIds = new List<byte[]>();

        private byte[] _aesKey;

        private string _currentId, _currentIpAddress;
        private int _currentPort;
        private bool _handshakeCompleted;
        private DateTime _connectedSince;
        private byte[] _secretWebSocketKey;
        private SscpCompressionContext _sscpCompressionContext, _otherSscpCompressionContext;
        private long _lastKeepAliveTimestamp;

        public string ID
        {
            get
            {
                return _currentId;
            }
        }

        public string IpAddress
        {
            get
            {
                return _currentIpAddress;
            }
        }

        public int Port
        {
            get
            {
                return _currentPort;
            }
        }

        public bool Connected
        {
            get
            {
                return _client.State.Equals(WebSocketState.Open);
            }
        }

        public DateTime ConnectedSince
        {
            get
            {
                return _connectedSince;
            }
        }

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

            Task.Run(async () =>
            {
                await ReceiveMessages();
            });

            while (!_handshakeCompleted)
            {
                await Task.Delay(1);
            }
            
            new Thread(() =>
            {
                while (Connected)
                {
                    Thread.Sleep(3000);

                    if (SscpUtils.GetTimestamp() - _lastKeepAliveTimestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                    {
                        Disconnect();
                        return;
                    }
                }
            }).Start();
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

        public async Task SendAsync(byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            while (!_handshakeCompleted)
            {
                await Task.Delay(1);
            }

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
                data = SscpUtils.ProcessAES256(data, SscpUtils.Combine(_aesKey.Skip(SscpGlobal.PACKET_GENERATED_KEY_LENGTH).ToArray(), generatedKeyPart), _secretWebSocketKey, true);
                byte[] theHash = SscpUtils.HashWithKeccak256(data);
                data = SscpUtils.Combine(theHash, data);
            }

            data = _sscpCompressionContext.Compress(data);
            byte[] compressedDataHash = SscpUtils.HashWithKeccak256(data);
            data = SscpUtils.Combine(generatedKeyPart, BitConverter.GetBytes((int) sscpPacketType), compressedDataHash, data);

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
            byte[] buffer = new byte[SscpGlobal.DEFAULT_BUFFER_SIZE];
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

                    data = SscpUtils.ProcessAES256(data, SscpUtils.Combine(_aesKey.Skip(5).ToArray(), generatedKeyPart), _secretWebSocketKey, false);
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

                if (_serverPacketIds.ContainsByteArray(packetId))
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
                _serverPacketNumber = _serverPacketNumber + SscpGlobal.PACKET_NUMBER_INCREMENTAL;

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
                        _handshakeCompleted = true;
                        _connectedSince = DateTime.UtcNow;
                        ConnectionOpened?.Invoke();
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
}