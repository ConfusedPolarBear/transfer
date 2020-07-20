# Transfer
Simple end to end encrypted cross platform data transfer

## Features
- Modern cryptography provided by the excellent [Noise framework](https://noiseprotocol.org/):
  - Curve25519 key exchange
  - ChaCha20Poly1305 data encryption
  - BLAKE2s hashing
- No intermediary servers - your data never leaves your network
  - NAT traversal is not (and will not) be supported
- Automatically generated transfer password
- Limit the number of times a file can be downloaded
- Integrity checking at source and destination
- Progress bars on client and server
- Can transfer to web browsers (**no encryption is currently used in this case**)

## What is encrypted in transit?
Everything - which includes:
- File contents
- File name
- SHA256 checksum

The file size is not currently padded or otherwise obscured, so someone monitoring the network will be able to determine the size of the file that is transferred.

## Example (server side)
```
$ ./transfer -f transfer
2020/07/20 01:52:01 Listening on port 1832 on: 192.168.1.1, fe80::1234:5678:8765:4321
2020/07/20 01:52:01 Sending file transfer (8831105 bytes)
2020/07/20 01:52:01 Encryption: Noise_NN_25519_ChaChaPoly_BLAKE2s
2020/07/20 01:52:01 Transfer password: 95daily-unplug
2020/07/20 01:52:03 Securely connected to client 6f24ec63f6b99483dabfe278daf821dc8d9e5e2b7e80cc2be833c25c6033f228
 8.42 MiB / 8.42 MiB [==================================================================] 100.00% 0s
2020/07/20 01:52:05 Transfer complete
2020/07/20 01:52:05 Maximum number of transfers reached, exiting
2020/07/20 01:52:05 http: Server closed
```

## Example (client side)
```
$ ./transfer -c localhost
Enter password: 
2020/07/20 02:30:28 Encryption: Noise_NN_25519_ChaChaPoly_BLAKE2s
2020/07/20 02:30:28 Securely connected to server 6f24ec63f6b99483dabfe278daf821dc8d9e5e2b7e80cc2be833c25c6033f228
2020/07/20 02:30:28 Press Enter to confirm transfer of transfer (8831105 bytes)

 8.42 MiB / 8.42 MiB [==================================================================] 100.00% 0s
2020/07/20 02:30:31 Transfer successful, received data checksum matches source
```
