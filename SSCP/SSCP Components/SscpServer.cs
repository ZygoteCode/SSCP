using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Net;
using System.Text;
using SSCP.Utils;

namespace SSCP
{
    public class SscpServer
    {
        public event Action<SscpServerUser, byte[]>? MessageReceived;
        public event Action<SscpServerUser>? UserConnected, UserDisconnected, UserKicked;

        private ConcurrentDictionary<SscpServerUser, Task> _users = new ConcurrentDictionary<SscpServerUser, Task>();
        private HttpListener _httpListener;

        private char[] _characters = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();
        private DateTime _startedSince;

        public DateTime StartedSince
        {
            get
            {
                return _startedSince;
            }
        }

        public List<SscpServerUser> ListConnectedUsers
        {
            get
            {
                return _users.Keys.ToList();
            }
        }

        public SscpServerUser[] ArrayConnectedUsers
        {
            get
            {
                return _users.Keys.ToArray();
            }
        }

        public int CountConnectedUsers
        {
            get
            {
                return _users.Keys.Count;
            }
        }

        public int MaxUsers { get; set; }

        public SscpServer(ushort port = SscpGlobal.DEFAULT_PORT, int maxUsers = -1)
        {
            MaxUsers = maxUsers;
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add($"http://{SscpGlobal.DEFAULT_SERVER_IP}:{port}{SscpGlobal.DEFAULT_URL_SLUG}");
        }

        public async Task StartAsync()
        {
            _httpListener.Start();

            while (_httpListener.IsListening)
            {
                try
                {
                    HttpListenerContext context = await _httpListener.GetContextAsync();

                    if (context.Request.IsWebSocketRequest)
                    {
                        if (MaxUsers != -1)
                        {
                            if (CountConnectedUsers >= MaxUsers)
                            {
                                continue;
                            }
                        }

                        string secWebSocketKey = "";

                        try
                        {
                            secWebSocketKey = context.Request.Headers[0]!;
                            string secWebSocketVersion = context.Request.Headers[1]!,
                                connection = context.Request.Headers[2]!,
                                upgrade = context.Request.Headers[3]!;

                            if (secWebSocketVersion != "13" || connection != "Upgrade" || upgrade != "websocket" || secWebSocketKey.Length != 24)
                            {
                                context.Response.StatusCode = 400;
                                context.Response.Close();
                                continue;
                            }
                        }
                        catch
                        {
                            context.Response.StatusCode = 400;
                            context.Response.Close();
                            continue;
                        }

                        HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync(null);
                        WebSocket webSocket = webSocketContext.WebSocket;
                        SscpServerUser sscpServerUser = new SscpServerUser(this, webSocket, context.Request.RemoteEndPoint, GenerateID(), SscpUtils.GetKeyFromSecretWebSocketKey(secWebSocketKey));
                        Task userTask = Task.Run(() => HandleWebSocketCommunication(sscpServerUser));
                        _users.TryAdd(sscpServerUser, userTask);
                        sscpServerUser.HandshakeStep = 1;
                        await SendRSAKey(sscpServerUser);
                    }
                    else
                    {
                        context.Response.StatusCode = 400;
                        context.Response.Close();
                    }
                }
                catch
                {

                }
            }
        }

        public async Task BroadcastAsync(byte[] data)
        {
            foreach (SscpServerUser sscpServerUser in _users.Keys)
            {
                if (!sscpServerUser.HandshakeCompleted)
                {
                    continue;
                }

                await SendAsyncPrivate(sscpServerUser, data);
            }
        }

        public async Task BroadcastAsync(string data)
        {
            await BroadcastAsync(Encoding.UTF8.GetBytes(data));
        }

        public void Broadcast(byte[] data)
        {
            BroadcastAsync(data).GetAwaiter().GetResult();
        }

        public void Broadcast(string data)
        {
            BroadcastAsync(data).GetAwaiter().GetResult();
        }

        private async Task SendRSAKey(SscpServerUser sscpServerUser)
        {
            sscpServerUser.ToClientRSA = new System.Security.Cryptography.RSACryptoServiceProvider(SscpGlobal.RSA_KEY_LENGTH);
            await SendAsyncPrivate(sscpServerUser, Encoding.UTF8.GetBytes(sscpServerUser.ToClientRSA.ToXmlString(false)));
            sscpServerUser.HandshakeStep = 2;
        }

        public void Start()
        {
            StartAsync().GetAwaiter().GetResult();
        }

        public async Task StopAsync()
        {
            if (_httpListener != null && _httpListener.IsListening)
            {
                _httpListener.Stop();
                _httpListener.Close();
            }

            foreach (SscpServerUser sscpServerUser in _users.Keys)
            {
                try
                {
                    await sscpServerUser.KickAsync();
                    sscpServerUser.Dispose();
                }
                catch
                {

                }
            }

            _users.Clear();
        }

        public void Stop()
        {
            StopAsync().GetAwaiter().GetResult();
        }

        private async Task SendAsyncPrivate(SscpServerUser sscpServerUser, byte[] data)
        {
            await sscpServerUser.SendAsync(data);
        }

        public async Task SendAsync(SscpServerUser sscpServerUser, byte[] data)
        {
            while (!sscpServerUser.HandshakeCompleted)
            {
                await Task.Delay(1);
            }

            await SendAsyncPrivate(sscpServerUser, data);
        }

        public async Task SendAsync(SscpServerUser sscpServerUser, string data)
        {
            await SendAsync(sscpServerUser, Encoding.UTF8.GetBytes(data));
        }

        public void Send(SscpServerUser sscpServerUser, byte[] data)
        {
            SendAsync(sscpServerUser, data).GetAwaiter().GetResult();
        }

        public void Send(SscpServerUser sscpServerUser, string data)
        {
            SendAsync(sscpServerUser, data).GetAwaiter().GetResult();
        }

        private async Task KickAsyncPrivate(SscpServerUser sscpServerUser)
        {
            _users.TryRemove(sscpServerUser, out _);
            UserDisconnected?.Invoke(sscpServerUser);
            await sscpServerUser.KickAsync();
            sscpServerUser.Dispose();
            UserKicked?.Invoke(sscpServerUser);
        }

        public async Task KickAsync(SscpServerUser sscpServerUser)
        {
            while (!sscpServerUser.HandshakeCompleted)
            {
                await Task.Delay(1);
            }

            await KickAsyncPrivate(sscpServerUser);
        }

        public void Kick(SscpServerUser sscpServerUser)
        {
            KickAsync(sscpServerUser).GetAwaiter().GetResult();
        }

        public SscpServerUser? GetUserByID(string id)
        {
            foreach (SscpServerUser sscpServerUser in _users.Keys)
            {
                if (sscpServerUser.ID.Equals(id))
                {
                    return sscpServerUser;
                }
            }

            return null;
        }

        public async Task KickAsync(string id)
        {
            await KickAsync(GetUserByID(id)!);
        }

        public void Kick(string id)
        {
            KickAsync(id).GetAwaiter().GetResult();
        }

        public async Task SendAsync(string id, byte[] data)
        {
            await SendAsync(GetUserByID(id)!, data);
        }

        public void Send(string id, byte[] data)
        {
            SendAsync(id, data).GetAwaiter().GetResult();
        }

        public async Task SendAsync(string id, string data)
        {
            await SendAsync(GetUserByID(id)!, data);
        }

        public void Send(string id, string data)
        {
            SendAsync(id, data).GetAwaiter().GetResult();
        }

        private string GenerateID()
        {
            string generated = SscpGlobal.SscpRandom.GetRandomString(_characters, 32);

            while (GetUserByID(generated) != null)
            {
                generated = SscpGlobal.SscpRandom.GetRandomString(_characters, 32);
            }

            return generated;
        }

        private async Task HandleWebSocketCommunication(SscpServerUser sscpServerUser)
        {
            byte[] buffer = new byte[1024 * 4];
            List<byte> receivedData = new List<byte>();

            while (sscpServerUser.Connected)
            {
                WebSocketReceiveResult result;

                do
                {
                    result = await sscpServerUser.ReceiveAsync(new ArraySegment<byte>(buffer));

                    if (result.MessageType.Equals(WebSocketMessageType.Close))
                    {
                        goto close;
                    }

                    receivedData.AddRange(buffer.Take(result.Count));
                }
                while (!result.EndOfMessage);

                byte[] data = receivedData.ToArray();
                receivedData.Clear();

                if (sscpServerUser.AesKey != null)
                {
                    byte[] theHash = data.Take(16).ToArray();
                    data = data.Skip(16).ToArray();
                    byte[] theNewHash = SscpUtils.HashMD5(data);

                    if (!SscpUtils.CompareByteArrays(theHash, theNewHash))
                    {
                        goto close;
                    }

                    data = SscpUtils.ProcessAES256(data, sscpServerUser.AesKey, sscpServerUser.HandshakeStep == 4 ? sscpServerUser.SecretWebSocketKey : new byte[16], false);
                }

                byte[] hash = data.Take(16).ToArray();
                data = data.Skip(16).ToArray();
                byte[] newHash = SscpUtils.HashMD5(data);

                if (!SscpUtils.CompareByteArrays(hash, newHash))
                {
                    goto close;
                }

                double packetNumber = BitConverter.ToDouble(data.Take(8).ToArray(), 0);

                if (packetNumber != sscpServerUser.PacketNumber)
                {
                    goto close;
                }

                data = data.Skip(8).ToArray();

                byte[] packetId = data.Take(SscpGlobal.PACKET_ID_SIZE).ToArray();
                data = data.Skip(SscpGlobal.PACKET_ID_SIZE).ToArray();

                if (sscpServerUser.PacketIds.Contains(packetId))
                {
                    goto close;
                }

                long timestamp = BitConverter.ToInt64(data.Take(8).ToArray());

                if (SscpUtils.GetTimestamp() - timestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                {
                    goto close;
                }

                data = data.Skip(8).ToArray();

                sscpServerUser.PacketNumber = sscpServerUser.PacketNumber + SscpGlobal.PACKET_NUMBER_INCREMENTAL;

                if (sscpServerUser.PacketNumber >= SscpGlobal.MAX_PACKET_NUMBER)
                {
                    sscpServerUser.PacketNumber = 0.0;
                }

                sscpServerUser.PacketIds.Add(packetId);

                if (sscpServerUser.PacketIds.Count > SscpGlobal.PACKET_ID_MAX_COUNT)
                {
                    sscpServerUser.PacketIds.Clear();
                }

                switch (sscpServerUser.HandshakeStep)
                {
                    case 2:
                        sscpServerUser.FromClientRSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                        sscpServerUser.FromClientRSA.FromXmlString(Encoding.UTF8.GetString(data));
                        sscpServerUser.AesTempKey = SscpGlobal.SscpRandom.GetRandomBytes(16);

                        await SendAsyncPrivate(sscpServerUser, sscpServerUser.FromClientRSA.Encrypt(sscpServerUser.AesTempKey, false));
                        sscpServerUser.HandshakeStep = 3;
                        break;
                    case 3:
                        sscpServerUser.AesKey = SscpUtils.Combine(sscpServerUser.AesTempKey!, sscpServerUser.ToClientRSA.Decrypt(data, false));
                        Array.Clear(sscpServerUser.AesTempKey!);
                        sscpServerUser.AesTempKey = null;

                        byte[] ipBytes = Encoding.UTF8.GetBytes(sscpServerUser.ConnectionIpAddress);
                        byte[] toSend = SscpUtils.Combine(Encoding.UTF8.GetBytes(sscpServerUser.ID), BitConverter.GetBytes(ipBytes.Length), ipBytes, BitConverter.GetBytes(sscpServerUser.ConnectionPort), sscpServerUser.SecretWebSocketKey);
                        await SendAsyncPrivate(sscpServerUser, toSend);

                        sscpServerUser.HandshakeStep = 4;
                        sscpServerUser.HandshakeCompleted = true;
                        sscpServerUser.ConnectedSince = DateTime.UtcNow;
                        UserConnected?.Invoke(sscpServerUser);
                        break;
                    case 4:
                        MessageReceived?.Invoke(sscpServerUser, data);
                        break;
                }
            }

        close: await KickAsyncPrivate(sscpServerUser);
        }
    }
}