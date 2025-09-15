# RouletteCipher (RC)

RouletteCipher (RC) is a high-security file encryption tool with built-in “Russian Roulette” logic: incorrect password attempts can irreversibly destroy the encrypted file. Designed for maximum resilience against brute-force attacks, RC combines modern cryptography, self-destruct mechanisms, and polymorphic behaviors to protect sensitive data.

Features

AES-256-GCM Encryption: Industry-standard encryption ensures strong confidentiality.

Argon2 Key Derivation: Uses Argon2 for password-based key derivation, resistant to GPU cracking.

Russian Roulette Self-Destruct: Files may be destroyed on incorrect password attempts to prevent brute-force attacks.

Polymorphic Builds: Each compilation can introduce slight variations, making automated attacks or signature-based detection more difficult.

Cross-Platform: Works on Linux (and can be built for other platforms with Rust).

Safe Base64 Metadata: All encryption metadata is safely encoded and stored with the file.

Installation

Clone the repository
