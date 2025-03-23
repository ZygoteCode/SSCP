# SSCP (Secure Sockets Communication Protocol)

## How to use

```c#
﻿using SSCP;
using System.Text;

public class Test
{
    private static SscpServer _sscpServer; // Define the instance of the server
    private static SscpClient _sscpClient; // Define the instance of the client

    public static void Main()
    {
        _sscpServer = new SscpServer(9987, -1, false); // Initialize the server with port, max number of connected clients, and if it uses a secure connection
        _sscpClient = new SscpClient("127.0.0.1", false, 9987); // Initialize the server with the IP address of the server, if it uses a secure connection, and the connection port

        new Thread(() =>
        {
            // Bind the standard server events
            _sscpServer.UserConnected += SscpServer_UserConnected; 
            _sscpServer.UserDisconnected += SscpServer_UserDisconnected;
            _sscpServer.PacketReceived += _sscpServer_PacketReceived;
            _sscpServer.Start(); // Start the server
        }).Start(); // In a thread, so we can work on the main

        // Bind the standard client events
        _sscpClient.ConnectionOpened += SscpClient_ConnectionOpened;
        _sscpClient.ConnectionClosed += SscpClient_ConnectionClosed;
        _sscpClient.PacketReceived += _sscpClient_PacketReceived;
        _sscpClient.Connect(); // Connect the client to the server

        while (true)
        {
            _sscpClient.Send(Console.ReadLine()!); // Infinitely, send a packet to the server with the content of the console readline (every line is a new packet)
        }
    }

    private static void _sscpClient_PacketReceived(SscpPacket obj)
    {
        // Display the content of the packet received by the Server

        if (obj.SscpPacketType.Equals(SscpPacketType.DATA))
        {
            Console.WriteLine($"[CLIENT] A new message has been received from the Server => {obj}");
        }
    }

    private static void _sscpServer_PacketReceived(SscpServerUser arg1, SscpPacket arg2)
    {
        // Display the content of the packet received by the Client

        if (arg2.SscpPacketType.Equals(SscpPacketType.DATA))
        {
            Console.WriteLine($"[SERVER] A User ({arg1.ID}) has sent a new message to the Server => {arg2}");
        }
    }

    private static void SscpClient_ConnectionClosed()
    {
        // When the connection between Client -> Server is closed
        Console.WriteLine($"[CLIENT] The client has closed the connection with the Server.");
    }

    private static void SscpClient_ConnectionOpened()
    {
        // When the connection between Client -> Server is established
        Console.WriteLine($"[CLIENT] The client is now connected to the Server. Connection IP Address: {_sscpClient.IpAddress}, connection port: {_sscpClient.Port}, unique ID: {_sscpClient.ID}.");
    }

    private static void SscpServer_UserDisconnected(SscpServerUser obj)
    {
        // When connection between Server -> Client (also called User, more specifically "SscpServerUser"), is lose
        Console.WriteLine($"[SERVER] A connected User is now disconnected. Connection IP address: {obj.ConnectionIpAddress}, connection port: {obj.ConnectionPort}, unique ID: {obj.ID}.");
    }

    private static void SscpServer_UserConnected(SscpServerUser obj)
    {
        // When connection between Server -> Client (also called User, more specifically "SscpServerUser"), is established
        Console.WriteLine($"[SERVER] A new User has been connected to the Server. Connection IP address: {obj.ConnectionIpAddress}, connection port: {obj.ConnectionPort}, unique ID: {obj.ID}.");
    }
}
```

## Todo List

- [ ] **High Priority:**

  - [ ] Implement all SscpClient's features in JavaScript client-side for browsers
  - [ ] Documentation
  - [ ] User guide
  - [ ] Complete tests
  - [ ] Official explanation of the protocol
  
- [ ] **Features (release V7 possibly?):**
  - [ ] Allow better chunking for big datas (like images, videos, ...) - this can allow upload/download of files
  - [ ] Anti DDoS feature (max packets in seconds/milliseconds, data patterns, strange IP addresses ranges in a span of time, anti HTTP requests spam, ...)

## Discarded Ideas
  - [ ] ~~Implement a new step in the Handshake, similar to the Sec-WebSocket-Key (https://stackoverflow.com/questions/18265128/what-is-sec-websocket-key-for)~~
  - [ ] ~~(Teoric) HWID (hashed) authentication system~~ - We can't go through into specific dynamics, this can be managed by servers' creators.
  - [ ] ~~Introduce a new layer with UDP, for transfering less-useful informations (media content for example)~~ - With this, we will reduce the security layering of the protocol, and the information transfering speed. However, UDP is untrustable and not precise in sending informations, so it's better to send chunked big datas with SSCP.

## Probably Discarded Ideas
  - [ ] Introduce packets (handshake, update AES key, first-second part of AES key update, re-handshake, disconnect, normal message with data, ...)
  - [ ] Periodic exchange of new AES keys (complete and partial)
  - [ ] Custom reason (in bytes / string) on disconnect (client) and kick (server)
  - [ ] Establishing rules between Server and Client (max packet size, max users dynamically, max delay, ...)
