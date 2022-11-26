[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is an **asymetric** cryptographic algorithm. A **public key** is used to encrypt data and a **private key** is used to decrypt data.

The variables of textbook RSA are:
- **N**: the product of two large primes
- **e**: the public exponent
- **d**: the private exponent

The public key is (N, e) and the private key is (N, d).

### Key generation
1. Choose two large primes **p** and **q**.
2. Compute **N = p * q**.
3. Compute **phi = (p - 1) * (q - 1)**.
4. Choose an integer **e** such that **1 < e < phi** and **gcd(e, phi) = 1** (usually **e = 65537**).
5. Compute **d** such that **d * e = 1 mod phi** i.e. **d = e^-1 mod phi**. (for exemple with the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm))

### Encryption
To encrypt a message **m** with the public key **(N, e)**, compute $c = m^e \mod N$.

c is the ciphertext.

### Decryption
To decrypt a ciphertext **c** with the private key **(N, d)**, compute $m = c^d \mod N$.

m is the deciphered message.

Several attacks exist on RSA depending on the circumstances.

* [RSA CTF Tool](https://github.com/RsaCtfTool/RsaCtfTool)

    Performs several attacks on RSA keys. Very useful for CTFs.


* RSA: Classic RSA

	Variables typically given: `n`, `c`, `e`. _ALWAYS_ try and give to [http://factordb.com](http://factordb.com). If `p` and `q` are able to be determined, use some RSA decryptor; handmade code available here: [https://pastebin.com/ERAMhJ1v](https://pastebin.com/ERAMhJ1v)

__If FactorDB cannot find factors, try [alpertron](https://www.alpertron.com.ar/ECM.HTM)__

* RSA: Multi-prime RSA

	When you see multi-prime RSA, you can use calculate `phi` by still using all the factors.

```
phi = (a - 1) * (b - 1) * (c - 1)    # ... etcetera
```


* RSA: `e` is 3 (or small)

	If `e` is 3, you can try the cubed-root attack. If you the cubed root of `c`, and if that is smaller than the cubed root of `n`, then your plaintext message `m` is just the cubed root of `c`! Here is [Python](https://www.python.org/) code to take the cubed root:

```
def root3rd(x):
    y, y1 = None, 2
    while y!=y1:
        y = y1
        y3 = y**3
        d = (2*y3+x)
        y1 = (y*(y3+2*x)+d//2)//d
    return y
```

* RSA: Wiener's Little D Attack

	The telltale sign for this kind of challenge is an enormously large `e` value. Typically `e` is either 65537 (0x10001) or `3` (like for a Chinese Remainder Theorem challenge). Some stolen code available here: [https://pastebin.com/VKjYsDqD](https://pastebin.com/VKjYsDqD)

* RSA:  Boneh-Durfee Attack
	The tellgate sign for this kind of challenge is also an enormously large `e` value (`e` and `n` have similar size).
Some code for this attack can be found [here](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage)

* RSA: Chinese Remainder Attack

	These challenges can be spotted when given  mutiple `c` cipher texts and multiple `n` moduli. `e` must be the same number of given `c` and `n` pairs. Some handmade code here: [https://pastebin.com/qypwc6wH](https://pastebin.com/qypwc6wH)

* RSA: Fixed Point