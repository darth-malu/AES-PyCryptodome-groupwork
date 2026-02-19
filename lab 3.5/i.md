Store a Passphrase and a Salt in the environment.

- PBKDF2HMAC is used to "stretch" the passphrase.

- Use HMAC-SHA256 with 100,000 iterations to make brute-forcing computationally expensive for an attacker.