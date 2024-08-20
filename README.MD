# SSCP (Secure Sockets Communication Protocol)

## Todo List

- [ ] **High Priority:**

  - [ ] Implement all SscpClient's features in JavaScript client-side for browsers
  - [ ] Documentation
  - [ ] User guide
  - [ ] Complete tests
  - [ ] Official explanation of the protocol

- [ ] **Features (V4?):**
  - [ ] Implement (optional or forced?) compression of packets with following one(s) algorithms: GZip, Deflate, Brotli, LZMA, Zlib, Zip, BZip2, LZip - we can choose one of them based on the compression speed and the ratio - https://github.com/GabryB03/SimpleCompression/blob/main/SimpleCompression.cs - (Zlib or Brotli?)
  - [ ] Error handling to prevent lose data, lose connections, or temporary downtimes
  - [ ] Periodic exchange of new AES keys (complete and partial)
  - [ ] Establishing rules between Server and Client (max packet size, max users dynamically, max delay, ...)
  - [ ] Introduce custom packets with a custom "Protocol" (handshake, keep-alive, update AES key, first-second part of AES key update, re-handshake, disconnect, normal message with data, ...)
  - [ ] Better security with HTTPS (SSL & TLS), support of certificates
  - [ ] Custom reason (in bytes / string) on disconnect (client) and kick (server)
  - [ ] Reduce Server and Client load by optimizing the code (code size, number of instructions, use of correct collections, ...)
  - [ ] Allow better chunking for big datas (like images, videos, ...) - this can allow upload/download of files
  - [ ] Introduce a new layer with UDP, for transfering less-useful informations (media content for example)
  - [ ] Anti DDoS feature (max packets in seconds/milliseconds, data patterns, strange IP addresses ranges in a span of time, ...)

## Discarded Ideas
  - [ ] ~~(Teoric) Custom Headers in HTTP request for WebSocket, by the Client and the Server, for validation~~
  - [ ] ~~Implement a new step in the Handshake, similar to the Sec-WebSocket-Key (https://stackoverflow.com/questions/18265128/what-is-sec-websocket-key-for)~~
  - [ ] ~~(Teoric) HWID (hashed) authentication system~~ - We can't go through into specific dynamics, this can be managed by servers' creators.
