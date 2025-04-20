using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Net;
using System.Text;
using SSCP.Utils;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Security.Policy;
using System;

namespace SSCP
{
    public class SscpServer
    {
        public event Action<SscpServerUser, SscpPacket>? PacketReceived;
        public event Action<SscpServerUser>? UserConnected, UserDisconnected, UserKicked;

        private ConcurrentDictionary<SscpServerUser, Task> _users = new ConcurrentDictionary<SscpServerUser, Task>();
        private HttpListener _httpListener;
        private DateTime _startedSince;

        public DateTime StartedSince => _startedSince;

        public List<SscpServerUser> ListConnectedUsers => _users.Keys.ToList();

        public SscpServerUser[] ArrayConnectedUsers => _users.Keys.ToArray();

        public int CountConnectedUsers => _users.Count;

        public int MaxUsers { get; set; }
        public HashSet<string> BannedIPs { get; }

        public SscpServer(ushort port = SscpGlobal.DEFAULT_PORT, int maxUsers = -1, bool secure = false)
        {
            MaxUsers = maxUsers;
            BannedIPs = new HashSet<string>();

            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add($"http{(secure ? "s" : "")}://{SscpGlobal.DEFAULT_SERVER_IP}:{(secure ? "443" : port)}{SscpGlobal.DEFAULT_URL_SLUG}");
        }

        public async Task StartAsync()
        {
            _users.Clear();
            _httpListener.Start();

            while (_httpListener.IsListening)
            {
                try
                {
                    HttpListenerContext context = await _httpListener.GetContextAsync();

                    if (context.Request.IsWebSocketRequest)
                    {
                        if (MaxUsers != -1 && CountConnectedUsers >= MaxUsers)
                        {
                            continue;
                        }

                        if (BannedIPs.Contains(context.Request.RemoteEndPoint.Address.ToString()))
                        {
                            context.Response.StatusCode = SscpGlobal.HTTP_401_UNAUTHORIZED;
                            context.Response.Close();
                            continue;
                        }

                        string secWebSocketKey = context.Request.Headers["Sec-WebSocket-Key"];

                        if (secWebSocketKey == null || !ValidateWebSocketHeaders(context))
                        {
                            context.Response.StatusCode = SscpGlobal.HTTP_400_BAD_REQUEST;
                            context.Response.Close();
                            continue;
                        }

                        HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync("SSCP");
                        WebSocket webSocket = webSocketContext.WebSocket;
                        byte[] newSecretWebSocketKey = SscpUtils.GetKeyFromSecretWebSocketKey(secWebSocketKey);

                        var user = new SscpServerUser(this, webSocket, context.Request.RemoteEndPoint, SscpUtils.GenerateUserID(context.Request.RemoteEndPoint.Address.ToString(), context.Request.RemoteEndPoint.Port, newSecretWebSocketKey), newSecretWebSocketKey);

                        var userTask = Task.Run(() => HandleWebSocketCommunication(user));
                        _users.TryAdd(user, userTask);

                        user.HandshakeStep = 1;
                        await SendRSAKey(user);
                    }
                    else
                    {
                        context.Response.StatusCode = SscpGlobal.HTTP_400_BAD_REQUEST;
                        context.Response.Close();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        private bool ValidateWebSocketHeaders(HttpListenerContext context)
        {
            var headers = context.Request.Headers;
            return headers.AllKeys.Length == 6 &&
                   headers["Sec-WebSocket-Key"] != null &&
                   headers["Sec-WebSocket-Version"] == "13" &&
                   headers["Sec-WebSocket-Protocol"] == "SSCP" &&
                   headers["Connection"] == "Upgrade" &&
                   headers["Upgrade"] == "websocket";
        }

        public async Task BanAsync(string ip)
        {
            BannedIPs.Add(ip);

            foreach (SscpServerUser sscpServerUser in _users.Keys)
            {
                if (!sscpServerUser.HandshakeCompleted) continue;

                if (sscpServerUser.ConnectionIpAddress.Equals(ip))
                {
                    _users.TryRemove(sscpServerUser, out _);

                    if (sscpServerUser.HandshakeCompleted)
                    {
                        UserDisconnected?.Invoke(sscpServerUser);
                    }

                    await sscpServerUser.KickAsync();
                    sscpServerUser.Dispose();

                    if (sscpServerUser.HandshakeCompleted)
                    {
                        UserKicked?.Invoke(sscpServerUser);
                    }
                }
            }
        }

        public void Ban(string ip)
        {
            BanAsync(ip).GetAwaiter().GetResult();
        }

        public async Task BanAsync(SscpServerUser sscpServerUser)
        {
            await BanAsync(sscpServerUser.ConnectionIpAddress);
        }

        public void Ban(SscpServerUser sscpServerUser)
        {
            BanAsync(sscpServerUser).GetAwaiter().GetResult();
        }

        public async Task BroadcastAsync(byte[] data)
        {
            var tasks = _users.Keys.Where(u => u.HandshakeCompleted).Select(user => SendAsyncPrivate(user, data));
            await Task.WhenAll(tasks);
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

        public async Task SendRSAKey(SscpServerUser sscpServerUser)
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
            _httpListener?.Stop();
            _httpListener?.Close();

            foreach (var user in _users.Keys.ToList())
            {
                await KickAsync(user);
            }

            _users.Clear();
        }

        public void Stop()
        {
            StopAsync().GetAwaiter().GetResult();
        }

        private async Task SendAsyncPrivate(SscpServerUser sscpServerUser, byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            await sscpServerUser.SendAsync(data, sscpPacketType);
        }

        public async Task SendAsync(SscpServerUser sscpServerUser, byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            while (!sscpServerUser.HandshakeCompleted)
            {
                await Task.Delay(1);
            }

            await SendAsyncPrivate(sscpServerUser, data, sscpPacketType);
        }

        public async Task SendAsync(SscpServerUser sscpServerUser, string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            await SendAsync(sscpServerUser, Encoding.UTF8.GetBytes(data), sscpPacketType);
        }

        public void Send(SscpServerUser sscpServerUser, byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(sscpServerUser, data, sscpPacketType).GetAwaiter().GetResult();
        }

        public void Send(SscpServerUser sscpServerUser, string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(sscpServerUser, data, sscpPacketType).GetAwaiter().GetResult();
        }

        private async Task KickAsyncPrivate(SscpServerUser sscpServerUser)
        {
            _users.TryRemove(sscpServerUser, out _);
            
            if (sscpServerUser.HandshakeCompleted)
            {
                UserDisconnected?.Invoke(sscpServerUser);
            }

            await sscpServerUser.KickAsync();
            sscpServerUser.Dispose();
            
            if (sscpServerUser.HandshakeCompleted)
            {
                UserKicked?.Invoke(sscpServerUser);
            }
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

        public async Task SendAsync(string id, byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            await SendAsync(GetUserByID(id)!, data, sscpPacketType);
        }

        public void Send(string id, byte[] data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(id, data, sscpPacketType).GetAwaiter().GetResult();
        }

        public async Task SendAsync(string id, string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            await SendAsync(GetUserByID(id)!, data, sscpPacketType);
        }

        public void Send(string id, string data, SscpPacketType sscpPacketType = SscpPacketType.DATA)
        {
            SendAsync(id, data, sscpPacketType).GetAwaiter().GetResult();
        }

        private async Task HandleWebSocketCommunication(SscpServerUser sscpServerUser)
        {
            byte[] buffer = new byte[SscpGlobal.DEFAULT_BUFFER_SIZE];
            MemoryStream receivedDataStream = new MemoryStream();
            CancellationTokenSource keepAliveCts = new CancellationTokenSource();

            var keepAliveTask = Task.Run(async () =>
            {
                try
                {
                    while (!keepAliveCts.Token.IsCancellationRequested && sscpServerUser.Connected)
                    {
                        await Task.Delay(3000, keepAliveCts.Token);
                        if (!sscpServerUser.Connected) break;

                        try
                        {
                            Send(sscpServerUser, BitConverter.GetBytes(SscpUtils.GetTimestamp()), SscpPacketType.KEEP_ALIVE);
                        }
                        catch (WebSocketException)
                        {
                            break;
                        }
                        catch (ObjectDisposedException)
                        {
                            break;
                        }

                        if (SscpUtils.GetTimestamp() - sscpServerUser.LastKeepAliveTimestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                        {
                            await KickAsyncPrivate(sscpServerUser);
                            return;
                        }
                    }
                }
                catch (TaskCanceledException)
                {

                }
                finally
                {
                    if (sscpServerUser.Connected)
                    {
                        await KickAsyncPrivate(sscpServerUser);
                    }
                }
            });

            try
            {
                while (sscpServerUser.Connected)
                {
                    WebSocketReceiveResult result;

                    do
                    {
                        try
                        {
                            result = await sscpServerUser.ReceiveAsync(new ArraySegment<byte>(buffer));
                        }
                        catch (WebSocketException ex) when (ex.WebSocketErrorCode == WebSocketError.ConnectionClosedPrematurely || ex.WebSocketErrorCode == WebSocketError.InvalidState)
                        {
                            goto close;
                        }
                        catch (OperationCanceledException)
                        {
                            goto close;
                        }

                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            goto close;
                        }

                        await receivedDataStream.WriteAsync(buffer, 0, result.Count);
                    }
                    while (!result.EndOfMessage);

                    byte[] data = receivedDataStream.ToArray();
                    receivedDataStream.SetLength(0);

                    int offset = 0;

                    if (data.Length < SscpGlobal.PACKET_GENERATED_KEY_LENGTH) goto close;
                    byte[] generatedKeyPart = new byte[SscpGlobal.PACKET_GENERATED_KEY_LENGTH];
                    Buffer.BlockCopy(data, offset, generatedKeyPart, 0, SscpGlobal.PACKET_GENERATED_KEY_LENGTH);
                    offset += SscpGlobal.PACKET_GENERATED_KEY_LENGTH;

                    if (data.Length < offset + SscpGlobal.INTEGER_SIZE) goto close;
                    SscpPacketType sscpPacketType = (SscpPacketType)BitConverter.ToInt32(data, offset);
                    offset += SscpGlobal.INTEGER_SIZE;

                    if (data.Length < offset + SscpGlobal.HASH_SIZE) goto close;
                    byte[] compressedDataHash = new byte[SscpGlobal.HASH_SIZE];
                    Buffer.BlockCopy(data, offset, compressedDataHash, 0, SscpGlobal.HASH_SIZE);
                    offset += SscpGlobal.HASH_SIZE;

                    byte[] currentCompressedData = new byte[data.Length - offset];
                    Buffer.BlockCopy(data, offset, currentCompressedData, 0, currentCompressedData.Length);
                    byte[] currentCompressedDataHash = SscpUtils.HashWithKeccak256(currentCompressedData);

                    if (!SscpUtils.CompareByteArrays(compressedDataHash, currentCompressedDataHash))
                    {
                        goto close;
                    }

                    byte[] decompressedData = sscpServerUser.Decompress(currentCompressedData);
                    int decompressedOffset = 0;

                    if (sscpServerUser.AesKey != null)
                    {
                        if (decompressedData.Length < SscpGlobal.HASH_SIZE) goto close;
                        byte[] theHash = new byte[SscpGlobal.HASH_SIZE];
                        Buffer.BlockCopy(decompressedData, decompressedOffset, theHash, 0, SscpGlobal.HASH_SIZE);
                        decompressedOffset += SscpGlobal.HASH_SIZE;

                        byte[] theNewData = new byte[decompressedData.Length - decompressedOffset];
                        Buffer.BlockCopy(decompressedData, decompressedOffset, theNewData, 0, theNewData.Length);
                        byte[] theNewHash = SscpUtils.HashWithKeccak256(theNewData);
                        if (!SscpUtils.CompareByteArrays(theHash, theNewHash))
                        {
                            goto close;
                        }

                        decompressedData = SscpUtils.ProcessAES256(theNewData, SscpUtils.Combine(sscpServerUser.AesKey.Skip(5).ToArray(), generatedKeyPart), sscpServerUser.HandshakeStep == 4 ? sscpServerUser.SecretWebSocketKey : SscpGlobal.EMPTY_IV, false);
                        decompressedOffset = 0;
                    }

                    if (decompressedData.Length < SscpGlobal.HASH_SIZE) goto close;
                    byte[] hash = new byte[SscpGlobal.HASH_SIZE];
                    Buffer.BlockCopy(decompressedData, decompressedOffset, hash, 0, SscpGlobal.HASH_SIZE);
                    decompressedOffset += SscpGlobal.HASH_SIZE;

                    byte[] finalData = new byte[decompressedData.Length - decompressedOffset];
                    Buffer.BlockCopy(decompressedData, decompressedOffset, finalData, 0, finalData.Length);
                    byte[] newHash = SscpUtils.HashWithKeccak256(finalData);

                    if (!SscpUtils.CompareByteArrays(hash, newHash))
                    {
                        goto close;
                    }

                    if (finalData.Length < SscpGlobal.DOUBLE_SIZE) goto close;
                    double packetNumber = BitConverter.ToDouble(finalData, 0);

                    if (packetNumber != sscpServerUser.PacketNumber)
                    {
                        goto close;
                    }

                    int finalOffset = SscpGlobal.DOUBLE_SIZE;

                    if (finalData.Length < finalOffset + SscpGlobal.HASH_SIZE) goto close;
                    byte[] packetId = new byte[SscpGlobal.HASH_SIZE];
                    Buffer.BlockCopy(finalData, finalOffset, packetId, 0, SscpGlobal.HASH_SIZE);
                    finalOffset += SscpGlobal.HASH_SIZE;

                    if (sscpServerUser.PacketIds.ContainsByteArray(packetId))
                    {
                        goto close;
                    }

                    if (finalData.Length < finalOffset + SscpGlobal.LONG_SIZE) goto close;
                    long timestamp = BitConverter.ToInt64(finalData, finalOffset);

                    if (SscpUtils.GetTimestamp() - timestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                    {
                        goto close;
                    }

                    finalOffset += SscpGlobal.LONG_SIZE;

                    sscpServerUser.PacketNumber += SscpGlobal.PACKET_NUMBER_INCREMENTAL;
                    if (sscpServerUser.PacketNumber >= SscpGlobal.MAX_PACKET_NUMBER)
                    {
                        sscpServerUser.PacketNumber = 0.0;
                    }
                    sscpServerUser.PacketIds.Add(packetId);
                    if (sscpServerUser.PacketIds.Count > SscpGlobal.PACKET_ID_MAX_COUNT)
                    {
                        sscpServerUser.PacketIds.Clear();
                    }

                    byte[] actualData = new byte[finalData.Length - finalOffset];
                    if (actualData.Length > 0)
                    {
                        Buffer.BlockCopy(finalData, finalOffset, actualData, 0, actualData.Length);
                    }

                    switch (sscpServerUser.HandshakeStep)
                    {
                        case 2:
                            sscpServerUser.FromClientRSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                            sscpServerUser.FromClientRSA.FromXmlString(Encoding.UTF8.GetString(actualData));
                            sscpServerUser.AesTempKey = SscpUtils.GetRandomByteArray(SscpGlobal.MID_HASH_SIZE);

                            await SendAsyncPrivate(sscpServerUser, sscpServerUser.FromClientRSA.Encrypt(sscpServerUser.AesTempKey, false));
                            sscpServerUser.HandshakeStep = 3;
                            break;
                        case 3:
                            sscpServerUser.AesKey = SscpUtils.Combine(sscpServerUser.AesTempKey!, sscpServerUser.ToClientRSA.Decrypt(actualData, false));
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
                            PacketReceived?.Invoke(sscpServerUser, new SscpPacket(sscpPacketType, actualData));

                            if (sscpPacketType == SscpPacketType.DATA)
                            {
                                Send(sscpServerUser, Encoding.UTF8.GetBytes($"Hello! I received your message: => \"{Encoding.UTF8.GetString(actualData)}\"."));
                            }
                            else if (sscpPacketType == SscpPacketType.KEEP_ALIVE)
                            {
                                long keepAliveTimestamp = BitConverter.ToInt64(actualData);
                                long currentKeepAliveTimestamp = SscpUtils.GetTimestamp();

                                if (currentKeepAliveTimestamp - keepAliveTimestamp > SscpGlobal.MAX_TIMESTAMP_DELAY)
                                {
                                    goto close;
                                }

                                sscpServerUser.LastKeepAliveTimestamp = keepAliveTimestamp;
                            }
                            break;
                    }
                }
            }
            finally
            {
                keepAliveCts.Cancel();
                await keepAliveTask;
            }

            close:
            if (sscpServerUser.Connected)
            {
                await KickAsyncPrivate(sscpServerUser);
            }
            else
            {
                _users.TryRemove(sscpServerUser, out _);
                sscpServerUser.Dispose();
            }
        }
    }
}