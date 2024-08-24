# SSCP (Secure Sockets Communication Protocol)

## Todo List

- [ ] **High Priority:**

  - [ ] Implement all SscpClient's features in JavaScript client-side for browsers
  - [ ] Documentation
  - [ ] User guide
  - [ ] Complete tests
  - [ ] Official explanation of the protocol

- [ ] **Features (release V4):**
  - [x] The constant "new byte[16]" for the Sec-WebSocket-Key must be put into "SscpGlobal"
  - [x] The lengths of hashes, extracted data, etc, must be as constants into "SscpGlobal"
  - [x] Replace MD5 with Keccak128
  - [x] Implement (optional or forced?) compression of packets with following one(s) algorithms: GZip, Deflate, Brotli, LZMA, Zlib, Zip, BZip2, LZip - we can choose one of them based on the compression speed and the ratio - https://github.com/GabryB03/SimpleCompression/blob/main/SimpleCompression.cs - (Zlib or Brotli?)
  - [x] Implement integrity check with Keccak256 for compressed data (in encrypted message or out of it? or both?)
  - [x] Introduce custom packets with a custom "Protocol" (keep-alive)

- [ ] **Features (in the near future):**
  - [ ] Error handling to prevent lose data, lose connections, or temporary downtimes
  - [ ] Better security with HTTPS (SSL & TLS), support of certificates
  - [ ] Reduce Server and Client load by optimizing the code (code size, number of instructions, use of correct collections, ...)
  - [ ] Allow better chunking for big datas (like images, videos, ...) - this can allow upload/download of files
  - [ ] Introduce a new layer with UDP, for transfering less-useful informations (media content for example)
  - [ ] Anti DDoS feature (max packets in seconds/milliseconds, data patterns, strange IP addresses ranges in a span of time, anti HTTP requests spam, ...)

## Discarded Ideas
  - [ ] ~~(Teoric) Custom Headers in HTTP request for WebSocket, by the Client and the Server, for validation~~
  - [ ] ~~Implement a new step in the Handshake, similar to the Sec-WebSocket-Key (https://stackoverflow.com/questions/18265128/what-is-sec-websocket-key-for)~~
  - [ ] ~~(Teoric) HWID (hashed) authentication system~~ - We can't go through into specific dynamics, this can be managed by servers' creators.

## Probably Discarded Ideas
  - [ ] Introduce packets (handshake, update AES key, first-second part of AES key update, re-handshake, disconnect, normal message with data, ...)
  - [ ] Periodic exchange of new AES keys (complete and partial)
  - [ ] Custom reason (in bytes / string) on disconnect (client) and kick (server)
  - [ ] Establishing rules between Server and Client (max packet size, max users dynamically, max delay, ...)