[AES Output FeedBack](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)) is an unusual stream cipher. It has no real benefits these days over CTR mode. Indeed CTR can be computed in parallel and allows random access in the ciphertext whereas OFB cannot.

<!--image -->
![CBC Encryption](./_img/CBC_encryption.png#gh-light-mode-only)
![CBC Encryption](./_img/CBC_encryption-dark.png#gh-dark-mode-only)
![CBC Decryption](./_img/CBC_decryption.png#gh-light-mode-only)
![CBC Decryption](./_img/CBC_decryption-dark.png#gh-dark-mode-only)