[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is an **asymetric** cryptographic algorithm. A **public key** is used to encrypt data and a **private key** is used to decrypt data.

The variables of textbook RSA are:

| Variable | Description |
|----------|-------------|
| $N$ | The product of two large primes |
| $e$ | The public exponent |
| $d$ | The private exponent |

The public key is (N, e) and the private key is (N, d).

## Key generation
1. Choose two large primes $p$ and $q$. Use a cryptographically secure random number generator.
2. Compute the public modulus:
   >$N = p q$.
3. Compute the "private" modulus:
   >$\Phi(N) = (p - 1) (q - 1)$
4. Choose an integer $e$ such that 
   >$1 < e < \Phi(N)$ and $\gcd(e, \Phi(N)) = 1$.<br>
   
   Usually $e = 65537 = 0x10001$.
5. Compute $d$ such that $de = 1 \mod \Phi(N)$ <br>
   >$d = e^-1 \mod \Phi(N)$. 
   
   (for exemple with the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm))

## Encryption
To encrypt a message $m$ with the **public** key $(N, e)$, compute the ciphertext $c$ with:

>$c = m^e \mod N$

## Decryption
To decrypt a ciphertext $c$ with the private key $(N, d)$, compute $m = c^d \mod N$.

m is the deciphered message.

Several attacks exist on RSA depending on the circumstances.

* [RSA CTF Tool](https://github.com/RsaCtfTool/RsaCtfTool) :heart:

    Performs several attacks on RSA keys. Very useful for CTFs.


* Known factors in databases

	Services such as [FactorDB](http://factordb.com) or  [Alpertron's calculator](https://www.alpertron.com.ar/ECM.HTM) provide a database of known factors. If you can find a factor of $N$, you can compute $p$ and $q$ then $d$.


* [Wiener's Attack](https://en.wikipedia.org/wiki/Wiener%27s_attack) with continued fractions

   When $e$ is **very large**, that means $d$ is small and the system can be vulnerable to the Wiener's attack. See [this script](./Tools/wiener.py) for an implementation of the attack.

	This type of attack on small private exponents was improved by Boneh and Durfee. See [this repository](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage) for an implementation of the attack.

* Chinese Remainder Attack

   When there are **multiple moduli** $N_1, N_2, \dots, N_k$ for multiple $c_1, c_2, \dots, c_k$ of the same message and the **same public exponent** $e$, you can use the Chinese Remainder Theorem to compute $m$.

* Multiple Recipients

   When there are **multiple public exponents** $e_1, e_2$ for multiple $c_1, c_2$ and the **same moduli** $N$, you can use Bezout's identity to compute $m$.

   Using Bezout's algorithm, you can find $a$ and $b$ such that $a e_1 + b e_2 = 1$. Then you can compute $m$ with:
   > $c_1^a c_2^b = m^{a e_1} m^{b e_2} = m^{a e_1 + b e_2} = m^1 = m \mod N$

* [RSA Fixed Point](https://crypto.stackexchange.com/questions/81128/fixed-point-in-rsa-encryption)

   These challenges can be spotted when the input is not changed with encrypted/decrypted.

   There are 6 non-trivial fixed points in RSA encryption, caracterized by $m$ mod $p \in \{0, 1, -1\}$ **and** $m$ mod $q \in \{0, 1, -1\}$.

   It is possible to deduce one of the prime factors of $n$ from the fixed point, since $\text{gcd}(m−1,n),\ \text{gcd}(m,n),\ \text{gcd}(m+1,n)$ are $1, p, q$ in a different order depending on the values of $m$ mod $p$ and $m$ mod $q$.
   
* Decipher oracle with blacklist 

   A decipher oracle can not control the message that it decrypts. If it blocks the decryption of cipher $c$, you can pass it $c * r^e \mod n$ where $r$ is any number. It will then return 
   >$(c * r^e)^d = c^d * r = m * r \mod n$
    
   You can then compute $m = c^d$ by dividing by $r$.

* Bleichenbacher's attack on PKCS#1 v1.5

   When the message is padded with **PKCS#1 v1.5** and a **padding oracle** output an error when the decrypted ciphertext is not padded, it is possible to perform a Bleichenbacher attack (BB98). See [this github script](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py) for an implementation of the attack.

   This attack is also known as the million message attack, as it require a lot of oracle queries.


* Coppersmith's attack 
