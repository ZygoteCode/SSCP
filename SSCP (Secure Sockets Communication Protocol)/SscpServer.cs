using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Net;
using System.Text;

namespace SSCP
{
    public class SscpServer
    {
        public event Action<SscpServerUser, byte[]>? MessageReceived;
        public event Action<SscpServerUser>? UserConnected, UserDisconnected;

        private ConcurrentDictionary<SscpServerUser, Task> _users = new ConcurrentDictionary<SscpServerUser, Task>();
        private HttpListener _httpListener;

        private SscpRandom _sscpRandom = new SscpRandom(2);
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
            string generated = _sscpRandom.GetRandomString(_characters, 32);

            while (GetUserByID(generated) != null)
            {
                generated = _sscpRandom.GetRandomString(_characters, 32);
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

                double packetNumber = BitConverter.ToDouble(data.Take(8).ToArray(), 0);

                if (packetNumber != sscpServerUser.PacketNumber)
                {
                    goto close;
                }

                data = data.Skip(8).ToArray();

                byte[] packetId = data.Take(6).ToArray();
                data = data.Skip(6).ToArray();

                if (sscpServerUser.PacketIds.Contains(packetId))
                {
                    goto close;
                }

                sscpServerUser.PacketNumber = sscpServerUser.PacketNumber + 0.0001;

                if (sscpServerUser.PacketNumber >= 1000000000000)
                {
                    sscpServerUser.PacketNumber = 0.0;
                }

                sscpServerUser.PacketIds.Add(packetId);

                if (sscpServerUser.PacketIds.Count > 100)
                {
                    sscpServerUser.PacketIds.Clear();
                }

                MessageReceived?.Invoke(sscpServerUser, data);
                Send(sscpServerUser, $"I respond you to the message!");
            }

            close: await KickAsync(sscpServerUser);
        }
    }
}