[AES Electronic CodeBook](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) is the most basic mode of operation. Each block is encrypted independently of the others. This means that the same plaintext block will always result in the same ciphertext block. This is considered **unsecure** for most applications.

<!--image -->
![ECB Encryption](./_img/601px-ECB_encryption.png#gh-light-mode-only)
![ECB Encryption](./_img/601px-ECB_encryption-dark.png#gh-dark-mode-only)
![ECB Decryption](./_img/601px-ECB_decryption.png#gh-light-mode-only)
![ECB Decryption](./_img/601px-ECB_decryption-dark.png#gh-dark-mode-only)


* AES ECB

	The "blind SQL" of cryptography... leak the flag out by testing for characters just one byte away from the block length.