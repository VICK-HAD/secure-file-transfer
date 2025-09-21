# Security Policy

This document outlines the security features and vulnerability reporting policy for the Secure File Transfer System.

## Security Architecture

This project employs a multi-layered security model to ensure the confidentiality, integrity, and authenticity of all data.

### 1. Transport Layer Security (TLS)

All communication channels between the client and the server are encrypted using TLS (HTTPS). This prevents passive eavesdropping and active man-in-the-middle attacks on the network level, ensuring that the initial key exchange and file transfer are secure from external observers.

### 2. End-to-End File Encryption (AES-256)

Files are never stored or transmitted in plaintext. Before a file is uploaded, it is encrypted on the client's machine using the **AES-256** algorithm with a unique, randomly generated session key. The file remains encrypted until it is explicitly decrypted on the server.

### 3. Secure Key Exchange (RSA)

To transmit the AES session key securely, the client first requests the server's **public RSA key**. The client then encrypts the AES session key with this public key. Only the server, which holds the corresponding private RSA key, can decrypt and retrieve the AES key, making the key exchange secure.

### 4. Data Integrity (SHA-256)

To protect against data tampering or corruption, the client generates a **SHA-256 hash** of the original, unencrypted file. This hash is sent to the server along with the encrypted file. After decrypting the file, the server computes its own SHA-256 hash of the received content and compares it to the hash provided by the client. If the hashes do not match, the file is considered compromised and is rejected.

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it to us by emailing `[meatlinkedin26@gmail.com]`.

Please include a detailed description of the vulnerability, including the steps required to reproduce it. We will make every effort to respond to your report in a timely manner and address the issue. We ask that you do not publicly disclose the vulnerability until we have had a chance to resolve it.