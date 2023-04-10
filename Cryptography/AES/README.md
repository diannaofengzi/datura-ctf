[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) A.K.A. Rijndael is a **symmetric** cryptographic algorithm. It uses the **same key** for encryption and decryption.

[This tutorial](https://www.davidwong.fr/blockbreakers/index.html) is a good introduction to AES and explain the implementation of the 128-bit version. It also goes through the [Square Attack](https://en.wikipedia.org/wiki/Square_attack) for a 4 round AES.



* 4-6 round AES

	When a low number of rounds is used, the key can be recovered by using the [Square Attack](https://en.wikipedia.org/wiki/Square_attack). See [this tutorial](https://www.davidwong.fr/blockbreakers/square.html) for an example.