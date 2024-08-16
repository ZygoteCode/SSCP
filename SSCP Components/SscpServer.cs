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
        public event Action<SscpServerUser>? UserConnected, UserDisconnected;

        private ConcurrentDictionary<SscpServerUser, Task> _users = new ConcurrentDictionary<SscpServerUser, Task>();
        private HttpListener _httpListener;

        private char[] _characters = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();

        public SscpServer(ushort port = 9987)
        {
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add($"http://127.0.0.1:{port}/SSCP/");
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
                        HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync(null);
                        WebSocket webSocket = webSocketContext.WebSocket;
                        SscpServerUser sscpServerUser = new SscpServerUser(this, webSocket, context.Request.RemoteEndPoint, GenerateID());
                        Task userTask = Task.Run(() => HandleWebSocketCommunication(sscpServerUser));
                        _users.TryAdd(sscpServerUser, userTask);
                        UserConnected?.Invoke(sscpServerUser);
                        sscpServerUser.HandshakeStep = 1;
                        SendRSAKey(sscpServerUser);
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

        private void SendRSAKey(SscpServerUser sscpServerUser)
        {
            sscpServerUser.ToClientRSA = new System.Security.Cryptography.RSACryptoServiceProvider(SscpGlobal.RsaKeyLength);
            Send(sscpServerUser, Encoding.UTF8.GetBytes(sscpServerUser.ToClientRSA.ToXmlString(false)));
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

        public async Task SendAsync(SscpServerUser sscpServerUser, byte[] data)
        {
            await sscpServerUser.SendAsync(data);
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

        public async Task KickAsync(SscpServerUser sscpServerUser)
        {
            _users.TryRemove(sscpServerUser, out _);
            UserDisconnected?.Invoke(sscpServerUser);
            await sscpServerUser.KickAsync();
            sscpServerUser.Dispose();
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

                if (sscpServerUser.AesCompleteKey != null)
                {
                    data = SscpUtils.ProcessAES256(data, sscpServerUser.AesCompleteKey, new byte[16], false);
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

                byte[] packetId = data.Take(SscpGlobal.PacketIdSize).ToArray();
                data = data.Skip(SscpGlobal.PacketIdSize).ToArray();

                if (sscpServerUser.PacketIds.Contains(packetId))
                {
                    goto close;
                }

                long timestamp = BitConverter.ToInt64(data.Take(8).ToArray());

                if (SscpUtils.GetTimestamp() - timestamp > SscpGlobal.MaxTimestampDelay)
                {
                    goto close;
                }

                data = data.Skip(8).ToArray();

                sscpServerUser.PacketNumber = sscpServerUser.PacketNumber + SscpGlobal.PacketNumberIncremental;

                if (sscpServerUser.PacketNumber >= SscpGlobal.MaxPacketNumber)
                {
                    sscpServerUser.PacketNumber = 0.0;
                }

                sscpServerUser.PacketIds.Add(packetId);

                if (sscpServerUser.PacketIds.Count > SscpGlobal.PacketIdsMaxCount)
                {
                    sscpServerUser.PacketIds.Clear();
                }

                switch (sscpServerUser.HandshakeStep)
                {
                    case 2:
                        sscpServerUser.FromClientRSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                        sscpServerUser.FromClientRSA.FromXmlString(Encoding.UTF8.GetString(data));
                        sscpServerUser.AesKey1 = SscpGlobal.SscpRandom.GetRandomBytes(16);

                        Send(sscpServerUser, sscpServerUser.FromClientRSA.Encrypt(sscpServerUser.AesKey1, false));
                        sscpServerUser.HandshakeStep = 3;
                        break;
                    case 3:
                        sscpServerUser.AesKey2 = sscpServerUser.ToClientRSA.Decrypt(data, false);
                        sscpServerUser.AesCompleteKey = SscpUtils.Combine(sscpServerUser.AesKey1, sscpServerUser.AesKey2);

                        byte[] ipBytes = Encoding.UTF8.GetBytes(sscpServerUser.ConnectionIpAddress);
                        byte[] toSend = SscpUtils.Combine(Encoding.UTF8.GetBytes(sscpServerUser.ID), BitConverter.GetBytes(ipBytes.Length), ipBytes, BitConverter.GetBytes(sscpServerUser.ConnectionPort));
                        Send(sscpServerUser, toSend);

                        sscpServerUser.HandshakeStep = 4;
                        sscpServerUser.HandshakeCompleted = true;
                        UserConnected?.Invoke(sscpServerUser);
                        break;
                    case 4:
                        MessageReceived?.Invoke(sscpServerUser, data);
                        break;
                }
            }

        close: await KickAsync(sscpServerUser);
        }
    }
}