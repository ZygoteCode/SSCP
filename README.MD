# SSCP (Secure Sockets Communication Protocol)

## Todo List

- [ ] **High Priority:**

  - [ ] Documentation
  - [ ] User guide
  - [ ] Complete tests
  - [ ] Official explanation of the protocol

- [ ] **Features:**
  - [ ] Error handling to prevent lose data, lose connections, or temporary downtimes
  - [ ] Periodic exchange of new AES keys (complete and partial)
  - [ ] Better use of hashing algorithms (like SHA-512 or Keccak)
  - [ ] Establishing rules between Server and Client (max packet size, max users dynamically, max delay, ...)
  - [ ] Introduce custom packets with a custom "Protocol" (handshake, keep-alive, update AES key, first-second part of AES key update, ...)
  - [ ] Better security with HTTPS (SSL & TLS), support of certificates
  - [ ] Custom reason (in bytes / string) on disconnect (client) and kick (server)
  - [ ] Reduce Server and Client load by optimizing the code (code size, number of instructions, use of correct collections, ...)
  - [ ] Allow better chunking for big datas (like images, videos, ...) - this can allow upload/download of files
  - [x] Add a feature for broadcasting message to all connected users
  - [ ] (Teoric) HWID (hashed) authentication system
  - [ ] (Teoric) WebSocket-HTTP request analyzer & filter, anti-spam for them
  - [ ] (Teoric) Introduce a new layer with UDP, for transfering less-useful informations (media content for example)
  - [ ] (Teoric) Anti DDoS feature (max packets in seconds/milliseconds, data patterns, strange IP addresses ranges in a span of time, ...)
