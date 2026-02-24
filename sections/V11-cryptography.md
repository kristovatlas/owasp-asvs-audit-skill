# V11: Cryptography

**ASVS Version:** 5.0.0
**ASVS Source:** `0x20-V11-Cryptography.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

The objective of this chapter is to define best practices for the general use of cryptography, as well as to instill a fundamental understanding of cryptographic principles and inspire a shift toward more resilient and modern approaches. It encourages the following:

* Implementing robust cryptographic systems that fail securely, adapt to evolving threats, and are future-proof.
* Utilizing cryptographic mechanisms that are both secure and aligned with industry best practices.
* Maintaining a secure cryptographic key management system with appropriate access controls and auditing.
* Regularly evaluating the cryptographic landscape to assess new risks and adapt algorithms accordingly.
* Discovering and managing cryptographic use cases throughout the application's lifecycle to ensure that all cryptographic assets are accounted for and secured.

In addition to outlining general principles and best practices, this document also provides more in-depth technical information about the requirements in Appendix C - Cryptography Standards. This includes algorithms and modes that are considered "approved" for the purposes of the requirements in this chapter.

Requirements that use cryptography to solve a separate problem, such as secrets management or communications security, will be in different parts of the standard.

---

## V11.1: Cryptographic Inventory and Documentation

Applications need to be designed with strong cryptographic architecture to protect data assets according to their classification. Encrypting everything is wasteful; not encrypting anything is legally negligent. A balance must be struck, usually during architectural or high-level design, design sprints, or architectural spikes. Designing cryptography "on the fly" or retrofitting it will inevitably cost much more to implement securely than simply building it in from the start.

It is important to ensure that all cryptographic assets are regularly discovered, inventoried, and assessed. Please see the appendix for more information on how this can be done.

The need to future-proof cryptographic systems against the eventual rise of quantum computing is also critical. Post-Quantum Cryptography (PQC) refers to cryptographic algorithms designed to remain secure against attacks by quantum computers, which are expected to break widely used algorithms such as RSA and elliptic curve cryptography (ECC).

Please see the appendix for current guidance on vetted PQC primitives and standards.

| # | Requirement | Level |
|---|-------------|-------|
| **11.1.1** | Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys). | 2 |
| **11.1.2** | Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys. | 2 |
| **11.1.3** | Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations. | 3 |
| **11.1.4** | Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats. | 3 |

### Audit Guidance for V11.1

**General approach:** These are documentation and governance requirements. The sub-agent should look for evidence of cryptographic policies, inventories, and migration plans in project documentation, architecture docs, ADRs, and configuration management artifacts.

**11.1.1 -- Documented cryptographic key management policy:**

What to look for:
- Dedicated key management policy documents, runbooks, or ADRs that reference standards such as NIST SP 800-57.
- Evidence of key lifecycle management: key generation procedures, rotation schedules, revocation processes, key expiration policies.
- Configuration or infrastructure-as-code referencing key management services (AWS KMS, Azure Key Vault, GCP Cloud KMS, HashiCorp Vault) with documented rotation and access policies.
- Evidence that private keys are restricted to a single entity and shared secrets to at most two entities (e.g., access control policies on key vaults, IAM policies limiting key access).
- Red flags: private keys or shared secrets stored in plain text in repositories, keys shared across many services without documented justification, no rotation schedule.
- N/A conditions: none -- any application using cryptography should have key management documentation.

**11.1.2 -- Cryptographic inventory:**

What to look for:
- A document or spreadsheet listing all cryptographic algorithms, key types, key sizes, certificates, and their purposes.
- Configuration files or infrastructure-as-code that enumerate cryptographic resources (TLS certificates, signing keys, encryption keys).
- Documentation indicating where each key is used and what data it protects.
- Red flags: no inventory document exists, certificates or keys are discovered in the codebase that are not listed in any inventory.
- Mark MANUAL_REVIEW if cryptography is used but no formal inventory exists.

**11.1.3 -- Cryptographic discovery mechanisms:**

What to look for:
- Automated tooling or scripts that scan the codebase and runtime environment for cryptographic usage (e.g., tools like `cryptosense`, `crypto-detector`, custom grep-based scanning for crypto API usage).
- CI/CD pipeline steps that detect or flag new cryptographic usage.
- This is a Level 3 requirement -- many applications will not have automated discovery.

**11.1.4 -- Migration plan for new cryptographic standards (including PQC):**

What to look for:
- Documentation or ADRs that discuss migration to post-quantum cryptography.
- Evidence of crypto-agility planning: abstraction layers around cryptographic operations, pluggable algorithm selection.
- Documented timelines or roadmaps for algorithm migration.
- This is a Level 3 requirement and is forward-looking -- mark MANUAL_REVIEW if no documentation is found.

---

## V11.2: Secure Cryptography Implementation

This section defines the requirements for the selection, implementation, and ongoing management of core cryptographic algorithms for an application. The objective is to ensure that only robust, industry-accepted cryptographic primitives are deployed, in alignment with current standards (e.g., NIST, ISO/IEC) and best practices. Organizations must ensure that each cryptographic component is selected based on peer-reviewed evidence and practical security testing.

| # | Requirement | Level |
|---|-------------|-------|
| **11.2.1** | Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations. | 2 |
| **11.2.2** | Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available. | 2 |
| **11.2.3** | Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security. | 2 |
| **11.2.4** | Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information. | 3 |
| **11.2.5** | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks. | 3 |

### Audit Guidance for V11.2

**11.2.1 -- Industry-validated cryptographic implementations:**

What to look for:
- The application uses well-known, peer-reviewed cryptographic libraries rather than custom implementations.
- **Approved libraries by language:**
  - **Python:** `cryptography`, `PyCryptodome`, `hashlib`, `hmac`, `secrets` (stdlib). Red flag: custom cipher implementations, `pycrypto` (unmaintained).
  - **JavaScript/Node.js:** `node:crypto` (built-in), `@noble/ciphers`, `@noble/hashes`, `tweetnacl`, `libsodium-wrappers`. Red flag: hand-rolled crypto, `crypto-js` for security-critical operations (limited auditing).
  - **Java:** JCA/JCE (built-in), Bouncy Castle, Google Tink, Conscrypt. Red flag: custom implementations of AES, RSA, or hashing.
  - **PHP:** `openssl_*` functions, `sodium_*` functions (libsodium), `hash_hmac()`. Red flag: `mcrypt_*` (removed in PHP 7.2), custom cipher code.
  - **Ruby:** `OpenSSL` module (stdlib), `RbNaCl` (libsodium binding). Red flag: custom implementations.
  - **Go:** `crypto/*` packages (stdlib), `golang.org/x/crypto`. Red flag: custom cipher implementations, non-standard crypto packages.
  - **C#/.NET:** `System.Security.Cryptography` namespace, Bouncy Castle for .NET. Red flag: custom AES/RSA implementations.
  - **Rust:** `ring`, `RustCrypto` crates (`aes-gcm`, `chacha20poly1305`, `sha2`, etc.). Red flag: unsafe blocks implementing crypto primitives.
- Red flags across all languages: any file implementing block cipher rounds, S-boxes, Feistel networks, or modular exponentiation from scratch.

**11.2.2 -- Crypto agility:**

What to look for:
- Abstraction layers or configuration-driven selection of cryptographic algorithms. For example:
  - Algorithm identifiers stored in configuration files or environment variables rather than hardcoded.
  - Wrapper functions or classes that abstract the specific cipher, hash, or MAC used (e.g., an `Encryptor` class where the algorithm can be swapped by changing config).
  - Encrypted data includes a version or algorithm identifier header so old data can be decrypted and re-encrypted with a new algorithm.
- Key rotation mechanisms: ability to generate new keys and re-encrypt existing data.
- Red flags: algorithm names hardcoded throughout the codebase with no central configuration, encrypted data with no version/algorithm metadata, no mechanism to rotate keys without data loss.

**11.2.3 -- Minimum 128-bit security level:**

What to look for:
- **AES:** Key size must be 128, 192, or 256 bits. All provide at least 128-bit security. AES-128 is acceptable.
- **RSA:** Key size must be at least 3072 bits for 128-bit security. Red flag: RSA-1024 or RSA-2048 (RSA-2048 provides approximately 112 bits of security).
- **ECC:** Key size must be at least 256 bits (e.g., P-256, Curve25519). Red flag: P-192 or smaller curves.
- **Diffie-Hellman:** Group size must be at least 3072 bits. Red flag: 1024-bit or 2048-bit DH groups.
- **Hash functions:** Output length must be at least 256 bits for collision resistance (SHA-256, SHA-3-256, BLAKE2b-256). SHA-1 (160 bits) does not meet this threshold.
- **Symmetric ciphers:** DES (56-bit), 3DES (112-bit effective) do not meet the 128-bit minimum. Red flag: any use of DES or 3DES.
- Search for key size parameters in code: look for numeric literals like `1024`, `2048` near RSA key generation, or `DES`, `3DES`, `Blowfish` algorithm names.

**11.2.4 -- Constant-time cryptographic operations:**

What to look for:
- **Safe patterns:** Use of library-provided constant-time comparison functions:
  - Python: `hmac.compare_digest()`, `secrets.compare_digest()`
  - Node.js: `crypto.timingSafeEqual()`
  - Java: `MessageDigest.isEqual()`
  - Go: `crypto/subtle.ConstantTimeCompare()`
  - Ruby: `OpenSSL.secure_compare()`, `Rack::Utils.secure_compare()`
  - C#: `CryptographicOperations.FixedTimeEquals()`
  - PHP: `hash_equals()`
- **Red flags:** Direct `==` or `===` comparison of hashes, MACs, tokens, or signatures. Early-return patterns in custom comparison loops (e.g., `if (a[i] != b[i]) return false`). String comparison operators on cryptographic output.
- This is a Level 3 requirement. Focus on MAC verification, signature verification, and token comparison code paths.

**11.2.5 -- Secure failure of cryptographic modules:**

What to look for:
- Exception/error handling around decryption, signature verification, and MAC validation operations.
- Red flags: different error messages or HTTP status codes for different cryptographic failure modes (e.g., "invalid padding" vs. "invalid MAC" -- this enables Padding Oracle attacks). Decryption errors that expose the type of failure to the caller. Catch blocks that silently ignore cryptographic errors and proceed.
- **Good patterns:** Generic error messages for all cryptographic failures ("decryption failed" regardless of cause), logging the specific error internally but returning a generic response, failing closed (denying access on any cryptographic error).

---

## V11.3: Encryption Algorithms

Authenticated encryption algorithms built on AES and CHACHA20 form the backbone of modern cryptographic practice.

| # | Requirement | Level |
|---|-------------|-------|
| **11.3.1** | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | 1 |
| **11.3.2** | Verify that only approved ciphers and modes such as AES with GCM are used. | 1 |
| **11.3.3** | Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm. | 2 |
| **11.3.4** | Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used. | 3 |
| **11.3.5** | Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode. | 3 |

### Audit Guidance for V11.3

**11.3.1 -- No insecure block modes or weak padding:**

What to look for:
- **ECB mode (FAIL):** Search for `ECB` in cipher mode specifications. ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking patterns.
  - Python: `AES.new(key, AES.MODE_ECB)`, `Cipher(algorithms.AES(key), modes.ECB())`
  - Java: `Cipher.getInstance("AES/ECB/...")`, `Cipher.getInstance("AES")` (defaults to ECB in many JCA providers)
  - Node.js: `crypto.createCipheriv('aes-256-ecb', ...)`
  - PHP: `openssl_encrypt($data, 'aes-256-ecb', ...)`
  - Go: using `cipher.NewECBEncrypter` or raw `aes.NewCipher()` block operations without a mode wrapper
  - C#: `aes.Mode = CipherMode.ECB`
  - Ruby: `OpenSSL::Cipher.new('aes-256-ecb')`
- **PKCS#1 v1.5 padding (FAIL):** Search for RSA encryption using PKCS#1 v1.5 padding (vulnerable to Bleichenbacher attacks).
  - Java: `Cipher.getInstance("RSA/ECB/PKCS1Padding")` or `Cipher.getInstance("RSA")` (defaults to PKCS1 in many providers)
  - Python: `PKCS1_v1_5.new(key).encrypt(...)`, `padding.PKCS1v15()` for encryption
  - C#: `rsa.Encrypt(data, false)` (false = PKCS#1 v1.5)
  - Approved alternative: RSA-OAEP (`RSA/ECB/OAEPWithSHA-256AndMGF1Padding` in Java, `padding.OAEP()` in Python)
- **Other insecure modes:** CBC without authentication is not insecure by itself but is fragile and addressed by 11.3.3 and 11.3.5.

**11.3.2 -- Only approved ciphers and modes:**

What to look for:
- **Approved algorithms and modes:**
  - AES-GCM (AES-128-GCM, AES-256-GCM) -- authenticated encryption
  - AES-CCM -- authenticated encryption
  - ChaCha20-Poly1305 -- authenticated encryption
  - AES-CBC with a separate HMAC (if combined correctly per 11.3.5) -- acceptable but AES-GCM preferred
  - XChaCha20-Poly1305 -- approved extended-nonce variant
- **Disallowed algorithms (FAIL):**
  - DES, 3DES/Triple-DES (`DESede` in Java)
  - RC4 (`ARC4`, `ARCFOUR`)
  - Blowfish (limited block size of 64 bits)
  - RC2
  - IDEA
  - Any custom or proprietary cipher
- Search across all source files for cipher algorithm string constants and enum references.
- In Java, pay special attention to `Cipher.getInstance()` calls. In Python, check `Cipher` and `Fernet` constructors. In Node.js, check `crypto.createCipheriv()` algorithm strings.

**11.3.3 -- Authenticated encryption or encryption + MAC:**

What to look for:
- **Good patterns (PASS):** Use of authenticated encryption modes: AES-GCM, AES-CCM, ChaCha20-Poly1305. These provide both confidentiality and integrity in a single operation.
  - Python: `AESGCM`, `ChaCha20Poly1305` from `cryptography.hazmat.primitives.ciphers.aead`
  - Java: `Cipher.getInstance("AES/GCM/NoPadding")`
  - Node.js: `crypto.createCipheriv('aes-256-gcm', ...)` with `getAuthTag()`
  - Go: `cipher.NewGCM(block)`
  - C#: `AesGcm` class
  - PHP: `openssl_encrypt($data, 'aes-256-gcm', ..., tag: $tag)`
- **Acceptable pattern:** AES-CBC + HMAC-SHA256 (encrypt-then-MAC), but verify the MAC covers both ciphertext and IV, and verify order per 11.3.5.
- **Red flags (FAIL):** AES-CBC or AES-CTR without any MAC or authentication tag. Encrypted data stored or transmitted without integrity protection. Use of `Fernet` in Python is acceptable (it uses AES-CBC + HMAC internally with encrypt-then-MAC).

**11.3.4 -- Nonce/IV uniqueness and proper generation:**

What to look for:
- **AES-GCM:** Nonces must be unique per key. A 96-bit (12-byte) random nonce with AES-GCM is standard but has a birthday-bound collision risk after approximately 2^32 encryptions with the same key. If high-volume encryption is expected, look for nonce counters or key rotation strategies.
  - Red flag: reusing a nonce with the same key in GCM mode is catastrophic -- it reveals the authentication key and allows forgery.
  - Red flag: generating nonces with non-cryptographic random (`Math.random()`, `random.random()`).
- **AES-CBC:** IVs must be unpredictable (random). A counter-based IV is insufficient for CBC mode.
  - Red flag: static IV, zero IV, or predictable IV generation for CBC.
- **ChaCha20-Poly1305:** 96-bit nonce, same uniqueness requirement as GCM. XChaCha20-Poly1305 uses a 192-bit nonce, which makes random generation safe for high-volume use.
- Search for IV/nonce generation code near encryption calls. Verify it uses CSPRNG.
- This is a Level 3 requirement.

**11.3.5 -- Encrypt-then-MAC ordering:**

What to look for:
- When encryption and MAC are applied separately (not using an AEAD mode like GCM), the correct order is:
  1. Encrypt the plaintext.
  2. MAC the ciphertext (and IV/nonce).
  3. Verify the MAC before decrypting.
- **Red flags:**
  - MAC-then-encrypt: computing MAC on plaintext, then encrypting both plaintext and MAC. This is vulnerable to Padding Oracle and related attacks.
  - Encrypt-and-MAC: computing MAC on plaintext independently of encryption.
  - Verifying MAC after decryption rather than before.
- **Good patterns:** If using AES-GCM or ChaCha20-Poly1305, this is inherently handled (mark as PASS for AEAD modes). Only relevant when encryption and MAC are separate operations.
- N/A conditions: if the application exclusively uses AEAD modes (GCM, CCM, ChaCha20-Poly1305), this requirement is automatically satisfied.

---

## V11.4: Hashing and Hash-based Functions

Cryptographic hashes are used in a wide variety of cryptographic protocols, such as digital signatures, HMAC, key derivation functions (KDF), random bit generation, and password storage. The security of the cryptographic system is only as strong as the underlying hash functions used. This section outlines the requirements for using secure hash functions in cryptographic operations.

For password storage, as well as the cryptography appendix, the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#password-hashing-algorithms) will also provide useful context and guidance.

| # | Requirement | Level |
|---|-------------|-------|
| **11.4.1** | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | 1 |
| **11.4.2** | Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security. | 2 |
| **11.4.3** | Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits. | 2 |
| **11.4.4** | Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key. | 2 |

### Audit Guidance for V11.4

**11.4.1 -- Only approved hash functions for cryptographic use:**

What to look for:
- **Approved hash functions:** SHA-256, SHA-384, SHA-512, SHA-3 family (SHA3-256, SHA3-384, SHA3-512), BLAKE2b, BLAKE2s, BLAKE3.
- **Disallowed hash functions (FAIL):**
  - MD5: search for `md5`, `MD5`, `hashlib.md5`, `MessageDigest.getInstance("MD5")`, `crypto.createHash('md5')`, `md5()` (PHP), `Digest::MD5` (Ruby), `crypto/md5` (Go), `MD5.Create()` (C#).
  - SHA-1: search for `sha1`, `SHA1`, `SHA-1`, `hashlib.sha1`, `MessageDigest.getInstance("SHA-1")`, `crypto.createHash('sha1')`, `sha1()` (PHP), `Digest::SHA1` (Ruby), `crypto/sha1` (Go), `SHA1.Create()` (C#).
  - MD4, MD2, RIPEMD-128.
- **Context matters:** MD5 or SHA-1 used for non-cryptographic purposes (e.g., cache keys, checksums for non-security file deduplication) may be acceptable, but any use for digital signatures, HMAC, KDF, integrity verification, or random bit generation is a FAIL.
- Check HMAC constructions: `HMAC-MD5` and `HMAC-SHA1` are disallowed. `HMAC-SHA256` and above are approved.

**11.4.2 -- Password storage with approved password hashing functions:**

What to look for:
- **Approved password hashing algorithms:**
  - Argon2id (preferred): search for `argon2`, `Argon2id`, `argon2-cffi` (Python), `password_hash(PASSWORD_ARGON2ID)` (PHP).
  - bcrypt: search for `bcrypt`, `BCrypt`, `password_hash(PASSWORD_BCRYPT)` (PHP), `BCryptPasswordEncoder` (Spring), `bcrypt.hashpw()` (Python), `bcrypt.hash()` (Node.js).
  - scrypt: search for `scrypt`, `crypto.scrypt` (Node.js), `hashlib.scrypt` (Python).
  - PBKDF2 with high iteration count: search for `PBKDF2`, `pbkdf2`, `PBKDF2WithHmacSHA256` (Java). Minimum recommended iterations: 600,000 for PBKDF2-HMAC-SHA256 (per OWASP 2023 guidance).
- **Disallowed for password storage (FAIL):**
  - Plain SHA-256/SHA-512 (even with salt but without key stretching).
  - MD5 (with or without salt).
  - SHA-1 (with or without salt).
  - Single-iteration hashing of any kind.
  - Reversible encryption of passwords.
  - Storing passwords in plaintext.
- **Parameter checks:**
  - Argon2id: minimum memory 19 MiB, minimum iterations 2, minimum parallelism 1 (OWASP recommendation: 19 MiB memory, 2 iterations, 1 parallelism).
  - bcrypt: cost factor at least 10 (12+ preferred). Search for work factor/round parameters.
  - scrypt: N at least 2^17, r=8, p=1 (minimum).
  - PBKDF2: at least 600,000 iterations with HMAC-SHA256.

**11.4.3 -- Collision-resistant hash functions with appropriate bit-lengths:**

What to look for:
- For digital signatures and data authentication requiring collision resistance: hash output must be at least 256 bits.
  - SHA-256 (256 bits): PASS
  - SHA-384 (384 bits): PASS
  - SHA-512 (512 bits): PASS
  - SHA3-256 (256 bits): PASS
  - SHA-1 (160 bits): FAIL
  - MD5 (128 bits): FAIL
- For scenarios requiring only second pre-image resistance: output must be at least 128 bits.
  - SHA-256: PASS
  - SHA-1 (160 bits): marginally meets the bit-length requirement but is cryptographically broken for collision resistance -- FAIL if used where collision resistance is needed.
- Check digital signature code paths: what hash algorithm is used with RSA, ECDSA, or EdDSA signing?

**11.4.4 -- Approved KDF with key stretching for password-derived keys:**

What to look for:
- This applies to deriving cryptographic keys from passwords (e.g., for file encryption, database encryption, key wrapping), not password storage (which is 11.4.2).
- **Approved KDFs:** PBKDF2, Argon2, scrypt, HKDF (for key derivation from high-entropy input, not passwords).
- **Red flags:** Deriving encryption keys from passwords using a single hash iteration (e.g., `key = SHA256(password)`). Using HKDF directly on passwords (HKDF is designed for high-entropy inputs, not passwords).
- **Good patterns:** `PBKDF2(password, salt, iterations=600000, hash=SHA256)` to derive an AES key. `Argon2id(password, salt, ...)` to derive a key. Using a KDF output as input to HKDF for multiple derived keys.
- Check parameter adequacy: same iteration/memory cost guidance as 11.4.2.

---

## V11.5: Random Values

Cryptographically secure Pseudo-random Number Generation (CSPRNG) is incredibly difficult to get right. Generally, good sources of entropy within a system will be quickly depleted if over-used, but sources with less randomness can lead to predictable keys and secrets.

| # | Requirement | Level |
|---|-------------|-------|
| **11.5.1** | Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition. | 2 |
| **11.5.2** | Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand. | 3 |

### Audit Guidance for V11.5

**11.5.1 -- CSPRNG usage with at least 128 bits of entropy:**

What to look for:
- **Approved CSPRNG sources by language:**
  - Python: `secrets` module (`secrets.token_bytes()`, `secrets.token_hex()`, `secrets.token_urlsafe()`), `os.urandom()`. Red flag: `random` module (`random.random()`, `random.randint()`) for security-sensitive values.
  - Node.js: `crypto.randomBytes()`, `crypto.randomUUID()`, `crypto.randomInt()`. Red flag: `Math.random()` for security-sensitive values.
  - Java: `java.security.SecureRandom`. Red flag: `java.util.Random`, `java.lang.Math.random()`.
  - PHP: `random_bytes()`, `random_int()`. Red flag: `rand()`, `mt_rand()`, `array_rand()` for security-sensitive values.
  - Ruby: `SecureRandom` module. Red flag: `rand()` for security-sensitive values.
  - Go: `crypto/rand` package. Red flag: `math/rand` for security-sensitive values.
  - C#: `RandomNumberGenerator` (or `RNGCryptoServiceProvider` in older .NET). Red flag: `System.Random` for security-sensitive values.
  - Rust: `rand::rngs::OsRng`, `getrandom` crate. Red flag: non-cryptographic RNGs like `rand::rngs::SmallRng` for security-sensitive values.
- **Entropy requirement:** At least 128 bits means at least 16 random bytes from a CSPRNG. Check that tokens, session IDs, API keys, and nonces are at least 16 bytes (32 hex characters, 22 base64 characters).
- **UUID caveat:** UUIDv4 contains only 122 random bits out of 128 total (6 bits are fixed for version/variant). The requirement notes UUIDs do not meet this condition. If UUIDs are used as security tokens, this is a finding.
- Search for token generation, session ID generation, API key generation, and CSRF token generation code paths.

**11.5.2 -- Secure RNG under heavy demand:**

What to look for:
- Whether the CSPRNG can handle concurrent high-volume requests without blocking or degrading entropy quality.
- On Linux, `/dev/urandom` is non-blocking and suitable for high-throughput use. `/dev/random` may block when entropy pool is depleted -- using `/dev/random` in high-demand scenarios is a potential issue (though modern Linux kernels have largely mitigated this).
- **Good patterns:** Using the OS-provided CSPRNG (which handles entropy replenishment internally), using thread-safe CSPRNG instances, connection pooling for hardware RNG devices.
- **Red flags:** Custom entropy pooling, seeding CSPRNG with time-based or PID-based values, using a single-threaded RNG shared across concurrent requests without synchronization.
- This is a Level 3 requirement. In most cases, using standard library CSPRNG functions (as listed in 11.5.1) is sufficient.

---

## V11.6: Public Key Cryptography

Public Key Cryptography will be used where it is not possible or not desirable to share a secret key between multiple parties.

As part of this, there exists a need for approved key exchange mechanisms, such as Diffie-Hellman and Elliptic Curve Diffie-Hellman (ECDH) to ensure that the cryptosystem remains secure against modern threats. The "Secure Communication" chapter provides requirements for TLS so the requirements in this section are intended for situations where Public Key Cryptography is being used in use cases other than TLS.

| # | Requirement | Level |
|---|-------------|-------|
| **11.6.1** | Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization. | 2 |
| **11.6.2** | Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks. | 3 |

### Audit Guidance for V11.6

**11.6.1 -- Approved algorithms for key generation and digital signatures:**

What to look for:
- **Approved signature algorithms:**
  - RSA with PSS padding (RSA-PSS) and key size >= 3072 bits.
  - ECDSA with P-256, P-384, or P-521 curves.
  - EdDSA (Ed25519, Ed448).
- **Approved key generation:**
  - RSA: key size >= 3072 bits, generated using a validated library. Red flag: RSA keys generated with small public exponents or without proper prime generation (Fermat factorization vulnerability occurs when p and q are too close together -- standard libraries prevent this).
  - ECC: using named curves P-256, P-384, P-521, Curve25519, Curve448. Red flag: custom curve parameters.
- **Disallowed (FAIL):**
  - RSA with PKCS#1 v1.5 signature padding in new implementations (SHA256withRSA in Java uses PKCS#1 v1.5 by default -- prefer `SHA256withRSA/PSS` or `RSASSA-PSS`).
  - DSA (deprecated, limited to 1024-bit keys in many implementations).
  - RSA keys < 3072 bits.
- **Language-specific patterns:**
  - Java: `KeyPairGenerator.getInstance("RSA")` -- check `initialize()` key size parameter. `Signature.getInstance("SHA256withRSA")` vs. `Signature.getInstance("SHA256withRSA/PSS")`.
  - Python: `rsa.generate_private_key(public_exponent=65537, key_size=...)` -- check key_size >= 3072. `ec.generate_private_key(ec.SECP256R1())`.
  - Node.js: `crypto.generateKeyPairSync('rsa', { modulusLength: ... })` -- check modulusLength. `crypto.sign()` algorithm parameter.
  - Go: `rsa.GenerateKey(rand, bits)` -- check bits >= 3072. `ecdsa.GenerateKey(elliptic.P256(), rand)`.

**11.6.2 -- Secure key exchange parameters:**

What to look for:
- **Diffie-Hellman (DH):**
  - Group/parameter size must be at least 3072 bits. Red flag: 1024-bit or 2048-bit DH groups.
  - Prefer well-known groups (RFC 3526, RFC 7919) over custom-generated parameters. Custom DH parameters may be weak if not generated properly.
  - Search for `DHParameterSpec` (Java), DH group selection in TLS configuration, `DiffieHellman` (Node.js).
- **Elliptic Curve Diffie-Hellman (ECDH):**
  - Use approved curves: P-256, P-384, P-521, X25519, X448.
  - Red flag: custom curve parameters, small curves.
  - Search for `ECDH`, `X25519`, key agreement/exchange code.
- **Red flags across all languages:**
  - Hardcoded DH parameters with small prime sizes.
  - Static (non-ephemeral) DH key exchange -- prefer ephemeral DH (DHE) or ephemeral ECDH (ECDHE) for forward secrecy.
  - No validation of received public keys (missing public key validation can enable small subgroup attacks).
- N/A conditions: if the application does not perform key exchange operations outside of TLS (key exchange within TLS is covered by the Secure Communication chapter).

---

## V11.7: In-Use Data Cryptography

Protecting data while it is being processed is paramount. Techniques such as full memory encryption, encryption of data in transit, and ensuring data is encrypted as quickly as possible after use is recommended.

| # | Requirement | Level |
|---|-------------|-------|
| **11.7.1** | Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes. | 3 |
| **11.7.2** | Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible. | 3 |

### Audit Guidance for V11.7

**11.7.1 -- Full memory encryption:**

What to look for:
- This is a Level 3 infrastructure-level requirement. It typically requires hardware and OS-level support rather than application-level code.
- **Technologies to look for:**
  - AMD SEV (Secure Encrypted Virtualization) or Intel TME (Total Memory Encryption) / Intel TDX (Trust Domain Extensions).
  - Confidential computing environments: Azure Confidential Computing, AWS Nitro Enclaves, GCP Confidential VMs.
  - SGX enclaves or ARM TrustZone usage.
- **In application code, look for:**
  - Use of secure enclaves or trusted execution environments (TEE) for processing sensitive data.
  - Infrastructure-as-code or deployment configurations that specify confidential computing instances.
  - Documentation referencing memory encryption requirements.
- This requirement is largely outside the scope of static code analysis. Mark MANUAL_REVIEW and note whether the deployment environment is documented to support memory encryption.

**11.7.2 -- Data minimization and immediate encryption after use:**

What to look for:
- **Good patterns:**
  - Sensitive data (decrypted secrets, plaintext credentials, PII) is zeroed or overwritten in memory after use. In languages with manual memory management (C, C++, Rust): explicit `memset_s()`, `SecureZeroMemory()`, or `zeroize` crate usage. In managed languages, this is harder to enforce due to garbage collection.
  - Sensitive variables are scoped as narrowly as possible (e.g., decrypted data exists only within a `try`/`using`/`with` block).
  - Data is re-encrypted or securely erased immediately after processing.
  - Minimize the number of copies of sensitive data in memory (avoid unnecessary string conversions, logging, or caching of decrypted data).
- **Red flags:**
  - Decrypted sensitive data stored in long-lived variables, session state, or global caches.
  - Logging or debug output that includes decrypted sensitive data.
  - Sensitive data persisted in temporary files without encryption.
  - Bulk decryption of data when only a subset is needed for processing.
- This is a Level 3 requirement and is difficult to fully verify through static analysis. Mark MANUAL_REVIEW for runtime and infrastructure verification.

---

## References

For more information, see also:

* [OWASP Web Security Testing Guide: Testing for Weak Cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography)
* [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
* [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

---

## V11 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 3 | 11.3.1, 11.3.2, 11.4.1 |
| L2 | 11 | 11.1.1, 11.1.2, 11.2.1, 11.2.2, 11.2.3, 11.3.3, 11.4.2, 11.4.3, 11.4.4, 11.5.1, 11.6.1 |
| L3 | 10 | 11.1.3, 11.1.4, 11.2.4, 11.2.5, 11.3.4, 11.3.5, 11.5.2, 11.6.2, 11.7.1, 11.7.2 |
| **Total** | **24** | |
