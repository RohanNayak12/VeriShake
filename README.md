# VeriShake: Formally Verified IoT Mutual Authentication

VeriShake is a lightweight, UDP-based mutual authentication protocol
designed for constrained IoT devices. It aims to reduce the overhead
associated with standard TLS 1.3/DTLS deployments, such as X.509
certificate parsing, PKI chains, and cipher suite negotiation, while
providing mutual authentication, Perfect Forward Secrecy, and a virtual
hardware-backed key-isolation boundary.

The protocol's state machine is modeled and analyzed against active
Dolev--Yao (Man-in-the-Middle) attackers using the **ProVerif** formal
verification framework.

## The Problem It Solves

1.  **Battery & Bandwidth:** Parsing certificate chains and negotiating
    cipher suites can require additional network traffic and CPU cycles,
    which may be costly for constrained IoT devices.
2.  **Physical Theft:** IoT devices are often deployed in the field.
    Software-based implementations that expose long-term private keys to
    application memory can increase the risk of key extraction if a
    device is physically compromised.
3.  **Downgrade Attacks:** Flexible algorithm negotiation can create
    opportunities for attackers to force weaker cryptographic
    configurations if it is not securely designed.

## The Solution

-   **Zero-PKI:** Uses pinned, pre-provisioned public keys rather than a
    conventional certificate-chain validation process.
-   **Hardcoded Cryptography:** Uses ECDSA for identity signatures, ECDH
    for ephemeral key agreement, and AES-GCM for authenticated payload
    encryption.
-   **Virtual HSM Boundary:** The client application interacts with an
    isolated `VirtualHSM` class for identity-key operations and key
    derivation, mirroring the interface of physical Secure Enclaves or
    TPMs. This is a software abstraction, not a substitute for a
    hardware security module.
-   **UDP Optimization:** The handshake is designed to complete in three
    datagrams.

## Protocol Architecture

The three-way handshake combines identity verification with ephemeral
key exchange to establish an AES-GCM session key and securely deliver an
encrypted payload.

``` text
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
[Verify Server Sig]                                        |
[Derive AES Session Key]                                   |
[Sign Handshake Hash]                                      |
[Encrypt Payload via AES]                                  |
      |                                                    |
      | --- Step 3: [AES-GCM Encrypted Payload (Sig_C)] -> |
      |                                                    |
      |                                                [Decrypt Payload]
      |                                                [Verify Client Sig]
      |                                           === MUTUAL AUTH COMPLETE ===
```

## Formal Verification

The core handshake logic is modeled in **ProVerif** and analyzed against
an active attacker capable of reading, modifying, and dropping network
messages.

-   **Query 1 (Authentication/MitM Resistance):**
    `event(server_authenticates_client) ==> event(client_started_handshake)`
    is intended to establish that server authentication of the client is
    linked to a corresponding client handshake event. The exact result
    depends on the ProVerif model and query definition.
-   **Query 2 (Secrecy):** The secrecy query is intended to verify that
    the protected payload remains confidential under the modeled
    attacker capabilities.

To reproduce these claims, include the ProVerif model, the exact
queries, and the tool output or verification logs in the repository.
Formal verification results apply to the assumptions and abstractions
represented in the model.

## Project Structure

-   `handshake.pv` - The ProVerif model for the cryptographic state
    machine.
-   `setup.py` - Generates the static SECP256R1 ECDSA keypairs used for
    simulated factory provisioning.
-   `hsm.py` - The Virtual Hardware Security Module abstraction.
    Encapsulates client long-term private-key operations and
    ECDH-related functionality.
-   `server_v2.py` - The UDP server backend.
-   `client_v2.py` - The IoT edge client.

## Getting Started

### Prerequisites

-   Python 3.8+
-   `cryptography` library
-   ProVerif (optional, for running the formal verification model)

### Installation & Setup

1.  **Clone the repository and create a virtual environment:**

    ``` bash
    git clone https://github.com/YOUR_USERNAME/VeriShake.git
    cd VeriShake
    python3 -m venv venv
    source venv/bin/activate
    pip install cryptography
    ```

2.  **Generate the factory keys:**

    ``` bash
    python3 setup.py
    ```

    This generates `client_private.pem`, `client_public.pem`,
    `server_private.pem`, and `server_public.pem` in the project
    directory.

### Execution

1.  **Start the server:**

    ``` bash
    python3 server_v2.py
    ```

2.  **Run the client in a separate terminal:**

    ``` bash
    source venv/bin/activate
    python3 client_v2.py
    ```

## Security Notes

-   The `VirtualHSM` class is a software abstraction. It does not
    provide the tamper resistance or key isolation guarantees of a
    physical TPM, Secure Element, or HSM.
-   Pinning public keys requires a secure provisioning and key-rotation
    process. Trust on First Use is not equivalent to authenticated
    factory provisioning.
-   Perfect Forward Secrecy depends on using fresh ephemeral ECDH key
    pairs for each session and securely deleting ephemeral private-key
    material after use.
-   Do not use this prototype to protect production IoT deployments
    without an independent cryptographic design review, implementation
    audit, and security testing.
