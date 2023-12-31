Cryptography and Cryptanalysis are the art of creating and breaking codes. 

This section will only explain the most common attacks, as there are too many of them (and would require too much time to write). However, tools and resources will be provided to help you learn more about cryptography and understand the well-known attacks.

Platforms with cryptanalysis challenges:
- [Cryptohack](https://cryptohack.org/)
- [CryptoPals](https://cryptopals.com/)

* `SageMath` - [Website](https://www.sagemath.org/)

    Powerful mathematics software, very useful for crypto and number theory.

* `Crypton` - [GitHub](https://github.com/ashutosh1206/Crypton)

    Archive repository of the most common attacks on cryptosystems.

* `Crypto Attacks repository` - [GitHub](https://github.com/jvdsn/crypto-attacks)

    A large collection of cryptography attacks.

* Predictable Pseudo-Random Number Generators

    For performance reasons, most of random number generators are **predictable**. Generating a cryptographic key requires a secure PRNG.
    
    For exemple, python's `random` module uses the Mersenne Twister algorithm, which is not cryptographically secure. [`randcrack`](https://github.com/tna0y/Python-random-module-cracker) is a tool that can predict the next random number generated by the Mersenne Twister algorithm when you know the 624 previously generated integers (4 bytes each).

