# V17: WebRTC

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x26-V17-WebRTC.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

Web Real-Time Communication (WebRTC) enables real-time voice, video, and data exchange in modern applications. As adoption increases, securing WebRTC infrastructure becomes critical. This section provides security requirements for stakeholders who develop, host, or integrate WebRTC systems.

The WebRTC market can be broadly categorized into three segments:

1. Product Developers: Proprietary and open-source vendors that create and supply WebRTC products and solutions. Their focus is on developing robust and secure WebRTC technologies that can be used by others.

2. Communication Platforms as a Service (CPaaS): Providers that offer APIs, SDKs, and the necessary infrastructure or platforms to enable WebRTC functionalities. CPaaS providers may use products from the first category or develop their own WebRTC software to offer these services.

3. Service Providers: Organizations that leverage products from product developers or CPaaS providers, or develop their own WebRTC solutions. They create and implement applications for online conferencing, healthcare, e-learning, and other domains where real-time communication is crucial.

The security requirements outlined here are primarily focused on Product Developers, CPaaS, and Service Providers who:

* Utilize open-source solutions to build their WebRTC applications.
* Use commercial WebRTC products as part of their infrastructure.
* Use internally developed WebRTC solutions or integrate various components into a cohesive service offering.

It is important to note that these security requirements do not apply to developers who exclusively use SDKs and APIs provided by CPaaS vendors. For such developers, the CPaaS providers are typically responsible for most of the underlying security concerns within their platforms, and a generic security standard like ASVS may not fully address their needs.

> **N/A Note:** The entire V17 chapter may be marked N/A if the application under audit does not use WebRTC at all, or if it exclusively relies on a CPaaS vendor's SDKs and APIs for WebRTC functionality (where the CPaaS provider is responsible for the underlying security). When marking N/A, document the rationale.

---

## V17.1: TURN Server

This section defines security requirements for systems that operate their own TURN (Traversal Using Relays around NAT) servers. TURN servers assist in relaying media in restrictive network environments but can pose risks if misconfigured. These controls focus on secure address filtering and protection against resource exhaustion.

| # | Requirement | Level |
|---|-------------|-------|
| **17.1.1** | Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses. | 2 |
| **17.1.2** | Verify that the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server. | 3 |

### Audit Guidance for V17.1

**General approach:** These requirements apply only if the application operates its own TURN server (e.g., coturn, Twilio TURN, custom TURN implementation). If the application does not use a TURN server, or relies entirely on a third-party CPaaS for TURN relay, mark this section N/A.

**17.1.1 -- TURN IP address filtering (reserved/internal addresses):**

What to look for:
- **TURN server configuration files:** Look for coturn configuration (`turnserver.conf`), or equivalent settings in custom TURN implementations. Check for `denied-peer-ip` or `allowed-peer-ip` directives that block relaying to private/reserved IP ranges.
- **Reserved IP ranges that must be blocked:** RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16), broadcast (255.255.255.255), multicast (224.0.0.0/4). For IPv6: ::1/128 (loopback), fe80::/10 (link-local), fc00::/7 (unique local), ff00::/8 (multicast).
- **Red flags:** TURN server configuration with no IP filtering at all, allowing relay to any address including internal network ranges. This enables SSRF-like attacks where an attacker uses the TURN server to reach internal services.
- **Safe patterns:** Explicit deny lists for all RFC 1918, loopback, link-local, and other reserved ranges in both IPv4 and IPv6, or alternatively an explicit allow list of only public IP ranges.
- **Code-level checks:** In custom TURN implementations, look for IP address validation logic that checks relay target addresses against reserved ranges before establishing the relay connection.

Language/framework-specific patterns:
- **coturn:** Check `turnserver.conf` for `denied-peer-ip=10.0.0.0-10.255.255.255`, `denied-peer-ip=172.16.0.0-172.31.255.255`, `denied-peer-ip=192.168.0.0-192.168.255.255`, and similar entries for IPv6 private ranges. The `no-multicast-peers` flag should also be set.
- **Go (pion/turn):** Check for custom `RelayAddressGenerator` implementations or peer address validation in relay allocation handlers.
- **Node.js (custom TURN):** Check for IP validation before relaying, using libraries like `ip` or `ipaddr.js` to detect private ranges.
- **Docker/container deployments:** Check that TURN containers are network-isolated appropriately and cannot reach internal services even if IP filtering is misconfigured.

**17.1.2 -- TURN resource exhaustion protection:**

What to look for:
- **Per-user allocation limits:** Check whether the TURN server limits the number of simultaneous allocations (relayed transport addresses) a single user or IP can create.
- **coturn settings:** Look for `total-quota`, `user-quota`, `max-bps` (bandwidth limit), and `stale-nonce` configuration. Check for `max-allocations` or equivalent settings.
- **Authentication enforcement:** TURN servers should require authentication (long-term or short-term credential mechanisms per RFC 5389/8489). Unauthenticated TURN is a major red flag for resource exhaustion.
- **Red flags:** No per-user quotas on allocations, no bandwidth limits, no authentication required for TURN allocations, no connection timeouts for idle allocations.
- **Safe patterns:** Authenticated TURN with time-limited credentials (e.g., ephemeral credentials with HMAC-based authentication), per-user allocation limits, bandwidth caps, idle timeout configurations, monitoring and alerting on allocation counts.

---

## V17.2: Media

These requirements only apply to systems that host their own WebRTC media servers, such as Selective Forwarding Units (SFUs), Multipoint Control Units (MCUs), recording servers, or gateway servers. Media servers handle and distribute media streams, making their security critical to protect communication between peers. Safeguarding media streams is paramount in WebRTC applications to prevent eavesdropping, tampering, and denial-of-service attacks that could compromise user privacy and communication quality.

In particular, it is necessary to implement protections against flood attacks such as rate limiting, validating timestamps, using synchronized clocks to match real-time intervals, and managing buffers to prevent overflow and maintain proper timing. If packets for a particular media session arrive too quickly, excess packets should be dropped. It is also important to protect the system from malformed packets by implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques.

Systems that rely solely on peer-to-peer media communication between web browsers, without the involvement of intermediate media servers, are excluded from these specific media-related security requirements.

This section refers to the use of Datagram Transport Layer Security (DTLS) in the context of WebRTC. A requirement related to having a documented policy for the management of cryptographic keys can be found in the "Cryptography" chapter. Information on approved cryptographic methods can be found either in the Cryptography Appendix of the ASVS or in documents such as NIST SP 800-52 Rev. 2 or BSI TR-02102-2 (Version 2025-01).

| # | Requirement | Level |
|---|-------------|-------|
| **17.2.1** | Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys. | 2 |
| **17.2.2** | Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP). | 2 |
| **17.2.3** | Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams. | 2 |
| **17.2.4** | Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets. | 2 |
| **17.2.5** | Verify that the media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | 3 |
| **17.2.6** | Verify that the media server is not susceptible to the "ClientHello" Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test. | 3 |
| **17.2.7** | Verify that any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | 3 |
| **17.2.8** | Verify that the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream. | 3 |

### Audit Guidance for V17.2

**General approach:** These requirements apply only when the application operates its own media server (SFU, MCU, recording server, or gateway). If the application uses only peer-to-peer WebRTC between browsers with no media server, or relies entirely on a CPaaS provider for media infrastructure, mark this section N/A.

**17.2.1 -- DTLS certificate key management:**

What to look for:
- **Key storage:** Check how the DTLS private key is stored. It should not be hardcoded in source code, committed to version control, or stored in plaintext configuration files accessible to unauthorized users.
- **Safe patterns:** Key stored in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), loaded from environment variables at runtime, stored with restricted file permissions (e.g., 0600), or managed by a hardware security module (HSM).
- **Key rotation:** Check whether there is a documented procedure or automated mechanism for rotating the DTLS certificate and key. Look for certificate expiration handling.
- **Red flags:** Private key files committed to the repository, private keys in Docker images, shared keys across environments (dev/staging/production using the same key), no documented key management policy, self-signed certificates with no rotation plan.
- **Cross-reference:** This requirement links to the Cryptography chapter's key management policy requirement. Check whether a key management policy document exists.

Language/framework-specific patterns:
- **Janus (C):** Check `janus.jcfg` or command-line flags for `cert_pem` and `cert_key` paths. Verify file permissions on the key file.
- **mediasoup (Node.js):** Check `WebRtcTransport` options for `dtlsCertificateFile` and `dtlsPrivateKeyFile`. Verify the key is not embedded in code.
- **Pion (Go):** Check for `webrtc.Configuration` or `dtls.Config` with certificate settings. Look at how certificates are loaded (from file, generated at runtime, from secrets store).
- **Kurento / OpenVidu (Java):** Check for keystore configuration and how the DTLS certificate is provisioned.
- **Ocelot / Olocatio (Java):** Check certificate loading configuration in SRTP/DTLS setup.

**17.2.2 -- Approved DTLS cipher suites and DTLS-SRTP protection profiles:**

What to look for:
- **DTLS version:** The media server should support DTLS 1.2 at minimum. DTLS 1.0 (based on TLS 1.1) should be disabled.
- **Cipher suites:** Check the configured cipher suites against approved lists. Approved cipher suites for DTLS-SRTP include those using AEAD algorithms (e.g., AES-128-GCM, AES-256-GCM). Weak or deprecated ciphers (RC4, DES, 3DES, NULL ciphers, export ciphers) must not be offered.
- **SRTP protection profiles:** Check which DTLS-SRTP protection profiles are configured. Recommended profiles include `SRTP_AEAD_AES_128_GCM` and `SRTP_AEAD_AES_256_GCM` (RFC 7714). Legacy profiles like `SRTP_AES128_CM_HMAC_SHA1_80` are widely used and acceptable but less preferred than AEAD profiles. `SRTP_AES128_CM_HMAC_SHA1_32` uses truncated authentication and is less secure.
- **Red flags:** DTLS 1.0 only, NULL cipher suites enabled, deprecated ciphers (RC4, DES) in the offered list, no explicit cipher suite configuration (relying on library defaults without verification), SRTP_NULL protection profile enabled.
- **Safe patterns:** Explicit cipher suite allowlist in configuration, DTLS 1.2+ enforced, AEAD SRTP protection profiles preferred.

Language/framework-specific patterns:
- **Janus:** Check `dtls_ciphers` in configuration and SRTP profile settings.
- **mediasoup:** Check `dtlsCiphers` option or OpenSSL cipher string configuration. mediasoup uses OpenSSL/BoringSSL internally.
- **Pion (Go):** Check `dtls.Config` for `CipherSuites` and `SRTPProtectionProfiles` fields.
- **FreeSWITCH:** Check `vars.xml` or SIP profiles for TLS/DTLS cipher configuration.
- **Ocelot / custom C/C++:** Check OpenSSL `SSL_CTX_set_cipher_list()` or `SSL_CTX_set_ciphersuites()` calls and `SSL_CTX_set_tlsext_use_srtp()` profile strings.

**17.2.3 -- SRTP authentication enforcement (RTP injection prevention):**

What to look for:
- **SRTP authentication tag validation:** The media server must verify the SRTP authentication tag on every incoming SRTP packet before processing the media payload. Packets with invalid authentication tags should be silently discarded.
- **Red flags:** SRTP authentication disabled or bypassed (e.g., using `SRTP_NULL` or `UNENCRYPTED_SRTP`), media server accepting and forwarding unauthenticated RTP packets, configuration options to disable SRTP entirely for "debugging" left enabled in production.
- **Safe patterns:** SRTP always enforced with authentication, no fallback to plain RTP, authentication failures logged and packets dropped.
- **Code-level checks:** In custom media server implementations, check that the SRTP decryption/verification function is called before any media processing or forwarding, and that failures result in packet drop (not forwarding the raw packet).

Language/framework-specific patterns:
- **libsrtp (C/C++):** Check for `srtp_unprotect()` calls and that return codes are checked. If `srtp_err_status_ok` is not the result, the packet should be discarded.
- **Pion (Go):** Check for `srtp.SessionSRTP` usage and that decrypted packets are the only ones forwarded. Pion enforces SRTP by default.
- **mediasoup (Node.js/C++):** mediasoup enforces SRTP by default. Check that it has not been patched or configured to accept plain RTP.
- **Janus:** Check for `force-bundle` and `force-rtcp-mux` settings. Janus enforces SRTP; check that no plugins bypass it.

**17.2.4 -- Resilience to malformed SRTP packets:**

What to look for:
- **Error handling:** The media server should gracefully handle malformed packets (truncated, corrupted, oversized, invalid headers, wrong SSRC) without crashing, hanging, or entering an error state that prevents processing of valid packets.
- **Red flags:** Uncaught exceptions or panics on malformed input, missing bounds checks on packet parsing, direct pointer arithmetic on packet buffers without length validation, `unwrap()` or equivalent crash-on-error patterns in packet parsing code (Rust), missing try/catch around packet processing (Java/C#).
- **Safe patterns:** Defensive packet parsing with length checks at each step, try/catch or error-return patterns around packet processing, fuzz testing evidence (fuzz test files in the repo), graceful degradation logging malformed packets and continuing.
- **Testing evidence:** Look for fuzz tests, malformed packet test cases, or chaos/resilience testing configurations that demonstrate the server has been tested against malformed input.

**17.2.5 -- SRTP flood resilience (L3):**

What to look for:
- **Rate limiting at the media layer:** Check whether the media server implements per-session or per-source rate limiting for incoming SRTP packets. Packets arriving faster than expected media rates (based on codec clock rates and typical packet intervals) should be dropped.
- **Buffer management:** Check for bounded buffer/queue sizes for incoming media, with drop policies (e.g., tail-drop, random early detection) when buffers fill.
- **Resource isolation:** Check whether a flood from one session can impact other sessions. Good implementations isolate media processing per session/stream.
- **Red flags:** Unbounded packet queues, no per-session rate limits, single-threaded processing where one flood blocks all sessions, no monitoring of packet rates.
- **Safe patterns:** Per-session packet rate enforcement, bounded buffers with drop policies, multi-threaded or async processing with resource isolation, monitoring and alerting on unusual traffic patterns.

**17.2.6 -- DTLS ClientHello race condition (L3):**

What to look for:
- **Known vulnerability:** This is a specific DoS vulnerability where an attacker sends a DTLS ClientHello to a media server's ICE candidate before the legitimate client, causing the server to establish a DTLS session with the attacker and reject the legitimate client's subsequent ClientHello.
- **Check media server version:** Determine the media server software and version. Check against known affected versions documented at Enable Security's advisory.
- **Known affected servers:** Janus (fixed in version 0.11.4+), Ocelot Olocatio (check version), and others documented in the Enable Security white paper.
- **Mitigation patterns:** Allowing DTLS renegotiation or restart after ICE consent freshness checks, implementing DTLS session reset on ICE connectivity check changes, applying the fixes documented in the Enable Security advisory.
- **Red flags:** Running known-vulnerable versions of media servers without patches, no awareness of this vulnerability in security documentation.
- **Testing:** If feasible, the race condition test described in the Enable Security white paper can be performed. Otherwise, version checking against known-vulnerable releases is the minimum.

**17.2.7 -- Recording mechanism flood resilience (L3):**

What to look for:
- **Recording architecture:** Identify how recording is implemented. Common patterns: recording at the SFU/MCU level, dedicated recording server receiving forked media, client-side recording.
- **Isolation between recording and live media:** Check whether the recording subsystem is decoupled from live media processing, so that recording being overwhelmed does not impact live streams.
- **Red flags:** Recording running in the same thread/process as live media forwarding with shared resources, unbounded recording buffers, no disk I/O throttling, recording failures causing media server crashes.
- **Safe patterns:** Asynchronous/buffered recording pipelines, dedicated recording processes or threads, disk write buffering with overflow handling, graceful degradation (dropping recording frames under load rather than crashing).

**17.2.8 -- DTLS certificate fingerprint verification against SDP (L3):**

What to look for:
- **SDP fingerprint attribute:** During WebRTC session setup, the SDP offer/answer contains an `a=fingerprint` attribute with a hash of the expected DTLS certificate. The media server must verify that the DTLS certificate presented during the DTLS handshake matches this fingerprint.
- **Red flags:** DTLS fingerprint verification disabled or not implemented, media server accepting any DTLS certificate regardless of the SDP fingerprint, SDP fingerprint attribute not being propagated from signaling to the media layer.
- **Safe patterns:** Certificate fingerprint comparison during DTLS handshake, automatic termination of the media stream if the fingerprint does not match, logging of fingerprint mismatches.

Language/framework-specific patterns:
- **Pion (Go):** Check that `DTLSTransport` validates the remote certificate fingerprint against the value received in the SDP. Pion does this by default via `webrtc.PeerConnection`.
- **Janus (C):** Check for fingerprint verification in DTLS setup code. Janus performs this check by default.
- **mediasoup (Node.js/C++):** Check that `dtlsParameters.fingerprints` from the remote SDP are validated during the DTLS handshake. mediasoup handles this internally.
- **Custom implementations:** Look for code that extracts the `a=fingerprint` from SDP and compares it (after hashing the peer certificate with the specified algorithm) during the DTLS handshake callback.

---

## V17.3: Signaling

This section defines requirements for systems that operate their own WebRTC signaling servers. Signaling coordinates peer-to-peer communication and must be resilient against attacks that could disrupt session establishment or control.

To ensure secure signaling, systems must handle malformed inputs gracefully and remain available under load.

| # | Requirement | Level |
|---|-------------|-------|
| **17.3.1** | Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level. | 2 |
| **17.3.2** | Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques. | 2 |

### Audit Guidance for V17.3

**General approach:** These requirements apply when the application operates its own signaling server for WebRTC session establishment. Signaling servers typically handle SDP offer/answer exchange, ICE candidate exchange, and session control messages, often over WebSocket or HTTP. If signaling is handled entirely by a third-party CPaaS provider, mark this section N/A.

**17.3.1 -- Signaling flood resilience (rate limiting):**

What to look for:
- **Rate limiting on signaling endpoints:** Check that WebSocket connections and/or HTTP endpoints used for signaling have rate limiting applied at the signaling message level (not just at the connection level).
- **Per-user/per-session limits:** Rate limiting should be applied per authenticated user or per session, not just per IP (since multiple legitimate users may share an IP).
- **Signaling protocol specifics:** If using SIP for signaling, check for SIP flood protection. If using custom WebSocket-based signaling, check for per-connection message rate limits.

Language/framework-specific patterns:
- **Node.js (Socket.io, ws):** Check for rate limiting middleware on WebSocket message handlers. Look for libraries like `rate-limiter-flexible`, custom message counters per connection, or application-level throttling.
- **Python (aiortc, Django Channels, FastAPI WebSocket):** Check for rate limiting decorators or middleware on signaling endpoints. Look for per-connection message counting.
- **Go (gorilla/websocket, nhooyr/websocket):** Check for rate limiting in WebSocket handler goroutines, per-connection message counters, or middleware.
- **Java (Spring WebSocket, Ocelot):** Check for `HandshakeInterceptor` or `ChannelInterceptor` implementations that enforce rate limits, or application-level throttling in message handlers.
- **Infrastructure level:** Check for WebSocket rate limiting at the reverse proxy level (nginx `limit_req` on WebSocket upgrade endpoints, HAProxy rate limiting, API gateway limits).

Red flags:
- No rate limiting on signaling WebSocket connections.
- Rate limiting only at the HTTP connection level but not at the message level within established WebSocket connections.
- No authentication required before sending signaling messages (allows anonymous flooding).
- Signaling server directly exposed to the internet without a reverse proxy or load balancer providing initial flood protection.

Safe patterns:
- Per-connection message rate limiting with configurable thresholds.
- Authentication required before signaling message processing.
- Reverse proxy or load balancer in front of signaling servers with connection and request rate limiting.
- Separate signaling server instances with auto-scaling under load.

**17.3.2 -- Signaling malformed message resilience:**

What to look for:
- **SDP parsing safety:** SDP (Session Description Protocol) messages are text-based and complex. Check that the SDP parser handles malformed input gracefully without crashing. Look for try/catch or error handling around SDP parsing.
- **Input validation on signaling messages:** Check that signaling messages are validated for expected structure, types, and sizes before processing. JSON schema validation, protocol buffer validation, or manual field validation.
- **Red flags:** Direct parsing of SDP or signaling messages without error handling, unbounded string/buffer allocations based on attacker-controlled length fields, integer overflow possibilities in session ID or media line count parsing, `JSON.parse()` without try/catch, missing length limits on incoming message sizes.
- **Safe patterns:** Schema validation on incoming signaling messages, bounded message sizes (rejecting oversized messages), try/catch around all parsing operations, SDP parsing using well-tested libraries rather than custom regex-based parsing, fuzz testing evidence for the signaling parser.

Language/framework-specific patterns:
- **Node.js:** Check for `try/catch` around `JSON.parse()` and SDP parsing. Check for `maxPayload` or `maxLength` settings on WebSocket server configuration. Look for use of established SDP libraries (`sdp-transform`, `sdptransform`).
- **Python:** Check for exception handling around SDP parsing (`aiortc`'s SDP parser, `python-sdp`). Check for `max_size` on WebSocket connections (`websockets` library).
- **Go:** Check for error return value handling on SDP parsing (`pion/sdp`). Go's `pion/sdp` library returns errors for malformed SDP; ensure these errors are handled and do not cause panics.
- **Java:** Check for try/catch around SDP parsing. Check for maximum message size configuration on WebSocket endpoints. Look for use of established SDP libraries (SRTP, Ocelot, or OWASP-adjacent SDP parsing).
- **C/C++:** Check for buffer overflow protections in SDP parsing, bounds checking on all buffer operations, safe string handling functions, and integer overflow checks. This is especially critical in C/C++ signaling server implementations.

---

## References

For more information, see also:

* The WebRTC DTLS ClientHello DoS is best documented at [Enable Security's blog post aimed at security professionals](https://www.enablesecurity.com/blog/novel-dos-vulnerability-affecting-webrtc-media-servers/) and the associated [white paper aimed at WebRTC developers](https://www.enablesecurity.com/blog/webrtc-hello-race-conditions-paper/)
* [RFC 3550 - RTP: A Transport Protocol for Real-Time Applications](https://www.rfc-editor.org/rfc/rfc3550)
* [RFC 3711 - The Secure Real-time Transport Protocol (SRTP)](https://datatracker.ietf.org/doc/html/rfc3711)
* [RFC 5764 - Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP))](https://datatracker.ietf.org/doc/html/rfc5764)
* [RFC 8825 - Overview: Real-Time Protocols for Browser-Based Applications](https://www.rfc-editor.org/info/rfc8825)
* [RFC 8826 - Security Considerations for WebRTC](https://www.rfc-editor.org/info/rfc8826)
* [RFC 8827 - WebRTC Security Architecture](https://www.rfc-editor.org/info/rfc8827)
* [DTLS-SRTP Protection Profiles](https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml)

---

## V17 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 0 | -- |
| L2 | 7 | 17.1.1, 17.2.1, 17.2.2, 17.2.3, 17.2.4, 17.3.1, 17.3.2 |
| L3 | 5 | 17.1.2, 17.2.5, 17.2.6, 17.2.7, 17.2.8 |
| **Total** | **12** | |
