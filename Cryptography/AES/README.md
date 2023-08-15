[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) A.K.A. Rijndael is a **symmetric** cryptographic algorithm. It uses the **same key** for encryption and decryption.

[This tutorial](https://www.davidwong.fr/blockbreakers/index.html) is a good introduction to AES and explain the implementation of the 128-bit version. It also goes through the [Square Attack](https://en.wikipedia.org/wiki/Square_attack) for a 4 round AES.

Different [modes of operations](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) are used to encrypt data larger than 128 bits (16 bytes). Block operation modes are used to encrypt data in one go while stream operation modes are used to encrypt data bit by bit.

The most common block operation modes are:

| Mode | Type | Description |
| ---- | ---- | ----------- |
| ECB | Block | Electronic Codebook |
| CBC | Block | Cipher Block Chaining |
| PCBC | Block | Propagating Cipher Block Chaining |
| CTR | Stream | Counter |
| CFB | Stream | Cipher Feedback |
| OFB | Stream | Output Feedback |

**Stream ciphers** usually only use the encryption block to create an output called **keystream** from pre-defined values. Then, it xors this keystream with the plaintext. Consequenly, when a bit of plaintext is flipped, the corresponding bit of ciphertext is flipped as well. Stream ciphers are often vulnerable to **encryption oracles (CPA)** as their stream of bits is xored to the plaintext. An attacker only have to input null bytes to get this keystream.

* 4-6 round AES

	When a low number of rounds is used, the key can be recovered by using the [Square Attack](https://en.wikipedia.org/wiki/Square_attack). See [this tutorial](https://www.davidwong.fr/blockbreakers/square.html) for an example.