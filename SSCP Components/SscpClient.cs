using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using SSCP.Utils;

namespace SSCP
{
    public class SscpClient
    {
        public event Action? ConnectionOpened, ConnectionClosed;
        public event Action<byte[]>? MessageReceived;

        private ClientWebSocket _client;
        private string _uri;
        private double _packetNumber, _serverPacketNumber;
        private byte _handshakeStep;
        private RSACryptoServiceProvider _fromServerRSA, _toServerRSA;

        private List<byte[]> _lastPacketIds = new List<byte[]>();
        private List<byte[]> _serverPacketIds = new List<byte[]>();

        private byte[] _aesKey1, _aesKey2, _aesCompleteKey;

        private string _currentId, _currentIpAddress;
        private int _currentPort;
        private bool _handshakeCompleted;

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

        public SscpClient(string host, ushort port = 9987)
        {
            _uri = $"ws://{host}:{port}/SSCP/";
        }

        public async Task ConnectAsync()
        {
            _client = new ClientWebSocket();
            _packetNumber = _serverPacketNumber = 0.0;
            _handshakeStep = 0;
            _lastPacketIds.Clear();
            _serverPacketIds.Clear();
            await _client.ConnectAsync(new Uri(_uri), CancellationToken.None);
            _handshakeStep = 1;
            ConnectionOpened?.Invoke();

            Task.Run(async () =>
            {
                await ReceiveMessages();
            });
            
            while (!_handshakeCompleted)
            {
                await Task.Delay(1);
            }
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
            byte[] packetId = SscpGlobal.SscpRandom.GetRandomByteArray(SscpGlobal.PacketIdSize);

            while (_lastPacketIds.Contains(packetId))
            {
                packetId = SscpGlobal.SscpRandom.GetRandomByteArray(SscpGlobal.PacketIdSize);
            }

            _lastPacketIds.Add(packetId);

            if (_lastPacketIds.Count > SscpGlobal.PacketIdsMaxCount)
            {
                _lastPacketIds.Clear();
            }

            data = SscpUtils.Combine(BitConverter.GetBytes(_packetNumber), packetId, BitConverter.GetBytes(SscpUtils.GetTimestamp()), data);
            byte[] hash = SscpUtils.HashMD5(data);
            data = SscpUtils.Combine(hash, data);

            if (_aesCompleteKey != null)
            {
                data = SscpUtils.ProcessAES256(data, _aesCompleteKey, new byte[16], true);
            }

            await _client.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, CancellationToken.None);
            _packetNumber += SscpGlobal.PacketNumberIncremental;

            if (_packetNumber >= SscpGlobal.MaxPacketNumber)
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

                if (_aesCompleteKey != null)
                {
                    data = SscpUtils.ProcessAES256(data, _aesCompleteKey, new byte[16], false);
                }

                byte[] hash = data.Take(16).ToArray();
                data = data.Skip(16).ToArray();
                byte[] newHash = SscpUtils.HashMD5(data);

                if (!SscpUtils.CompareByteArrays(hash, newHash))
                {
                    await DisconnectAsync();
                    return;
                }

                double packetNumber = BitConverter.ToDouble(data.Take(8).ToArray(), 0);

                if (packetNumber != _serverPacketNumber)
                {
                    await DisconnectAsync();
                    return;
                }

                data = data.Skip(8).ToArray();
                byte[] packetId = data.Take(SscpGlobal.PacketIdSize).ToArray();

                if (_serverPacketIds.Contains(packetId))
                {
                    await DisconnectAsync();
                    return;
                }

                data = data.Skip(SscpGlobal.PacketIdSize).ToArray();
                long timestamp = BitConverter.ToInt64(data.Take(8).ToArray());

                if (SscpUtils.GetTimestamp() - timestamp > SscpGlobal.MaxTimestampDelay)
                {
                    await DisconnectAsync();
                    return;
                }

                data = data.Skip(8).ToArray();
                _serverPacketNumber = _serverPacketNumber + SscpGlobal.PacketNumberIncremental;

                if (_serverPacketNumber >= SscpGlobal.MaxPacketNumber)
                {
                    _serverPacketNumber = 0.0;
                }

                _serverPacketIds.Add(packetId);

                if (_serverPacketIds.Count > SscpGlobal.PacketIdsMaxCount)
                {
                    _serverPacketIds.Clear();
                }

                switch (_handshakeStep)
                {
                    case 1:
                        _fromServerRSA = new RSACryptoServiceProvider();
                        _fromServerRSA.FromXmlString(Encoding.UTF8.GetString(data));

                        _toServerRSA = new RSACryptoServiceProvider(SscpGlobal.RsaKeyLength);
                        Send(Encoding.UTF8.GetBytes(_toServerRSA.ToXmlString(false)));

                        _handshakeStep = 2;
                        break;
                    case 2:
                        _aesKey1 = _toServerRSA.Decrypt(data, false);
                        _aesKey2 = SscpGlobal.SscpRandom.GetRandomBytes(16);

                        Send(_fromServerRSA.Encrypt(_aesKey2, false));
                        _aesCompleteKey = SscpUtils.Combine(_aesKey1, _aesKey2);

                        _handshakeStep = 3;
                        break;
                    case 3:
                        _currentId = Encoding.UTF8.GetString(data.Take(32).ToArray());
                        data = data.Skip(32).ToArray();

                        int ipLength = BitConverter.ToInt32(data.Take(4).ToArray());
                        data = data.Skip(4).ToArray();

                        _currentIpAddress = Encoding.UTF8.GetString(data.Take(ipLength).ToArray());
                        data = data.Skip(ipLength).ToArray();

                        _currentPort = BitConverter.ToInt32(data.Take(4).ToArray());

                        _handshakeStep = 4;
                        _handshakeCompleted = true;
                        ConnectionOpened?.Invoke();
                        break;
                    case 4:
                        MessageReceived?.Invoke(data);
                        break;
                }
            }
        }
    }
}