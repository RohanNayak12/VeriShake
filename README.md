# VeriShake: Formally Verified IoT Mutual Authentication

VeriShake is a lightweight, UDP-based mutual authentication protocol designed for constrained IoT devices. It strips away the heavy overhead of standard TLS 1.3/DTLS (X.509 certificate parsing, PKI chains, and cipher suite negotiation) while maintaining military-grade security properties, Perfect Forward Secrecy, and hardware-backed key isolation.

The protocol's state machine is mathematically proven secure against active Dolev-Yao (Man-in-the-Middle) attackers using the **ProVerif** formal verification framework.

## The Problem It Solves
1. **Battery & Bandwidth:** Parsing 2KB X.509 certificate chains and negotiating cipher suites requires excessive network round-trips and CPU cycles, draining IoT batteries.
2. **Physical Theft:** IoT devices are deployed in the field. Software-based TLS implementations that load private keys into RAM are vulnerable to extraction when a device is physically stolen.
3. **Downgrade Attacks:** Algorithm negotiation allows attackers to force weaker cipher suites.

## The Solution
* **Zero-PKI:** Uses pinned, pre-shared public keys (Trust on First Use).
* **Hardcoded Cryptography:** Strictly enforces ECDSA (Identity), ECDH (Forward Secrecy), and AES-GCM (Payload).
* **Virtual HSM Boundary:** The client application never touches the private identity key. All cryptographic signatures and key derivations occur inside an isolated `VirtualHSM` class, mirroring physical Secure Enclaves/TPMs.
* **UDP Optimization:** Completes in exactly three datagrams.

## Protocol Architecture

The 3-way handshake integrates asymmetric identity verification with ephemeral key exchange to securely deliver an AES-GCM encrypted payload.

```text
IoT Device (Client)                                Cloud Backend (Server)
[Virtual HSM]                                      [Pinned Keys]
       |                                                    |
       | ------ Step 1: [Client_ID, Nonce_C, Eph_Pub_C] --> |
       |                                                    |
       |                                       [Generate Eph_Pub_S]
       |                                       [Derive AES Session Key]
       |                                                    |
       | <-- Step 2: [Nonce_S, Eph_Pub_S, Signature_S] ---- |
       |                                                    |
[Verify Server Sig]
[Derive AES Session Key]
[Sign Handshake Hash]
[Encrypt Payload via AES]
       |                                                    |
       | --- Step 3: [AES-GCM Encrypted Payload (Sig_C)] -> |
       |                                                    |
                                                 [Decrypt Payload]
                                                 [Verify Client Sig]
                                            === MUTUAL AUTH COMPLETE ===
