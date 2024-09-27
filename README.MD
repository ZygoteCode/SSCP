# SSCP (Secure Sockets Communication Protocol)

## Todo List

- [ ] **High Priority:**

  - [ ] Implement all SscpClient's features in JavaScript client-side for browsers
  - [ ] Documentation
  - [ ] User guide
  - [ ] Complete tests
  - [ ] Official explanation of the protocol
  
- [ ] **Features (release V6?):**
  - [ ] Allow better chunking for big datas (like images, videos, ...) - this can allow upload/download of files
  - [ ] Anti DDoS feature (max packets in seconds/milliseconds, data patterns, strange IP addresses ranges in a span of time, anti HTTP requests spam, ...)
  - [ ] Error handling to prevent lose data, lose connections, or temporary downtimes
  - [ ] Reduce Server and Client load by optimizing the code (code size, number of instructions, use of correct collections, ...)

## Discarded Ideas
  - [ ] ~~Implement a new step in the Handshake, similar to the Sec-WebSocket-Key (https://stackoverflow.com/questions/18265128/what-is-sec-websocket-key-for)~~
  - [ ] ~~(Teoric) HWID (hashed) authentication system~~ - We can't go through into specific dynamics, this can be managed by servers' creators.
  - [ ] ~~Introduce a new layer with UDP, for transfering less-useful informations (media content for example)~~ - With this, we will reduce the security layering of the protocol, and the information transfering speed. However, UDP is untrustable and not precise in sending informations, so it's better to send chunked big datas with SSCP.

## Probably Discarded Ideas
  - [ ] Introduce packets (handshake, update AES key, first-second part of AES key update, re-handshake, disconnect, normal message with data, ...)
  - [ ] Periodic exchange of new AES keys (complete and partial)
  - [ ] Custom reason (in bytes / string) on disconnect (client) and kick (server)
  - [ ] Establishing rules between Server and Client (max packet size, max users dynamically, max delay, ...)