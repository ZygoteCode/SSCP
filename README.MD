# SSCP (Secure Sockets Communication Protocol)

## Todo List

- [ ] **High Priority:**

  - [ ] Documentation
  - [ ] User guide
  - [ ] Complete tests
  - [ ] Official explanation of the protocol

- [ ] **Features:**
  - [x] Update the Unique ID generation system: concatenate the randomly generated unique ID, and the Secret WebSocket Key hash obtained in the Server, and get the MD5 hash of this concatenation. Also, the current timestamp can be concatenated for security reasons
  - [x] A new method for generating Packet IDs: concatenate the random generated string, and the current timestamp, and hash all with MD5
  - [ ] Implement a new step in the Handshake, similar to the Sec-WebSocket-Key (https://stackoverflow.com/questions/18265128/what-is-sec-websocket-key-for)
  - [ ] Error handling to prevent lose data, lose connections, or temporary downtimes
  - [ ] Periodic exchange of new AES keys (complete and partial)
  - [ ] Better use of hashing algorithms (like SHA-512 or Keccak)
  - [ ] Establishing rules between Server and Client (max packet size, max users dynamically, max delay, ...)
  - [ ] Introduce custom packets with a custom "Protocol" (handshake, keep-alive, update AES key, first-second part of AES key update, re-handshake, ...)
  - [ ] Better security with HTTPS (SSL & TLS), support of certificates
  - [ ] Custom reason (in bytes / string) on disconnect (client) and kick (server)
  - [ ] Reduce Server and Client load by optimizing the code (code size, number of instructions, use of correct collections, ...)
  - [ ] Allow better chunking for big datas (like images, videos, ...) - this can allow upload/download of files
  - [x] Implement a feature to ban IP addresses from the Server, by a list of IP addresses
  - [x] Add a feature for broadcasting message to all connected users
  - [x] WebSocket-HTTP request analyzer & filter (headers analysis)
  - [x] Use Secret WebSocket Key for better encryption
  - [ ] (Teoric) HWID (hashed) authentication system
  - [ ] (Teoric) Introduce a new layer with UDP, for transfering less-useful informations (media content for example)
  - [ ] (Teoric) Anti DDoS feature (max packets in seconds/milliseconds, data patterns, strange IP addresses ranges in a span of time, ...)
  - [ ] ~~(Teoric) Custom Headers in HTTP request for WebSocket, by the Client and the Server, for validation~~
