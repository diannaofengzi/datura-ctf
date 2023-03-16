* [DCode](https://www.dcode.fr)

	Support many crypto algorithms, but also some interesting tools.

* [CyberChef](https://gchq.github.io/CyberChef/) :heart:

	Online tool to encrypt/decrypt, encode/decode, analyse, and perform many other operations on data.


* [Keyboard Shift](https://www.dcode.fr/keyboard-shift-cipher)

	ROT but using the keyboard layout.


* XOR

	Simple logic operation that can be used to encrypt a message with a key.

	Encryption: c = m ^ k
	Decryption: m = c ^ k

* [Caesar Cipher](https://www.dcode.fr/caesar-cipher)

	Shift cipher using the alphabet. Different alphabets can also be used. Vulnerable to **frequency analysis**.


* [Atbash Cipher](https://en.wikipedia.org/wiki/Atbash) 
	
	Shift cipher using the alphabet in reverse order. Vulnerable to frequency analysis.

* [Vigenere Cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) 
	
	Shift cipher using a key. The key is repeated to match the length of the message.

	| Type    | Content     |
    |---------|-------------|
	| Message | HELLO WORLD |
	| Key     | ABCDE FABCD |
	| Cipher (sum)%26  | HFNLP XQEMK |



* [Gronsfeld Cipher](http://rumkin.com/tools/cipher/gronsfeld.php)

	Variant of the Vigenere cipher using a key of numbers instead of letters.

* [Beaufourt Cipher](https://www.dcode.fr/beaufort-cipher)


* [Bacon Cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher)

	A substitution cipher that replaces each character with five characters from a set of two (A and B is used most of the time). If we look at A as 0 and B as 1 it is a special encoding to binary numbers, where the character A has the value of binary `b00000`. Easy to recognize, because the ciphertext only contains two characters (e.g.: A and B) and the length of the ciphertext is divisible by 5. Example: `AAABB AAABA ABBAB AAABB AABAA AAAAB AAAAA AAABA ABBAB ABBAA`.

        [Online tool](http://rumkin.com/tools/cipher/baconian.php)

* [Python random module cracker/predictor](https://github.com/tna0y/Python-random-module-cracker)

	Python's `random` module can be predicted from previous values. This tool can be used to predict the next value from a list of previous results.

* Transposition Cipher


* [LC4](https://www.schneier.com/blog/archives/2018/05/lc4_another_pen.html) 
	This is an adaptation of RC4... just not. There is an implementation available in Python.
	[https://github.com/dstein64/LC4/blob/master/documentation.md](https://github.com/dstein64/LC4/blob/master/documentation.md)

* Elgamal

* Affine Cipher

* Substitution Cipher (use quip quip!)

	[https://quipqiup.com/](https://quipqiup.com/)

* Railfence Cipher

	[http://rumkin.com/tools/cipher/railfence.php](http://rumkin.com/tools/cipher/railfence.php)


* [Playfair Cipher](https://en.wikipedia.org/wiki/Playfair_cipher) 
	racker: [http://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html](http://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html)

* Polybius Square

	[https://www.braingle.com/brainteasers/codes/polybius.php](https://www.braingle.com/brainteasers/codes/polybius.php)

* The Engima

	[http://enigma.louisedade.co.uk/enigma.html](http://enigma.louisedade.co.uk/enigma.html),
	[https://www.dcode.fr/enigma-machine-cipher](https://www.dcode.fr/enigma-machine-cipher)


* Two-Time Pad

* [International Code of Signals Maritime](https://en.wikipedia.org/wiki/International_Code_of_Signals) 
	First drafted by the British Board of Trade in 1855 and adopted as a world-wide standard on 1 January 1901. It is used for communications with ships, but also occasionally used by geocaching mystery caches (puzzle caches), CTFs and various logic puzzles. You may want to give a look at the tool [maritime flags translator].


* Daggers Cipher

The daggers cipher is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/daggers-alphabet](https://www.dcode.fr/daggers-alphabet).

![../_img/dagger_cipher.png](../_img/dagger_cipher.png)

* Hylian Language (Twilight Princess)

The Hylian language is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/hylian-language-twilight-princess](https://www.dcode.fr/hylian-language-twilight-princess).

![../_img/hylian.png](../_img/hylian.png)

* Hylian Language (Breath of the Wild)

The Hylian language is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/hylian-language-breath-of-the-wild](https://www.dcode.fr/hylian-language-breath-of-the-wild).

![../_img/botw.jpg](../_img/botw.jpg)

* Sheikah Language (Breathe of the Wild)

The Sheikah language is another silly text-to-image encoder. This is the key, and you can
find a decoder on [https://www.dcode.fr/sheikah-language](https://www.dcode.fr/sheikah-language).

![../_img/sheikah.png](../_img/sheikah.png)

* Hexahue Alphabet 

The hexhue is an another tex-to-image enocder. you can find a decoder
on [https://www.boxentriq.com/code-breaking/hexahue](https://www.boxentriq.com/code-breaking/hexahue)

![img](../_img/hexahue-alphabet.png)


* References to DICE, or EFF

	If your challenges references "EFF" or includes dice in some way, or showcases numbers 1-6 of length 5, try [https://www.eff.org/dice](https://www.eff.org/dice). This could refer to a passphrase generated by dice rolls available here: [https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)

* `Base64` :heart:, `Base32`, `Base85`, `Base91` ...

	| Name | Charset | Exemple |
	| --- | --- | --- |
	| Base64 | `A-Za-z0-9+/` | `SGVsbG8gV29ybGQh` |
	| Base32 | `A-Z2-7` | `JBSWY3DPEBLW64TMMQ======` |
	| Base85 | `A-Za-z0-9!#$%&()*+-;<=>?@^_` | `9jqo^F*bKt7!8'or``]8%F<+qT*` |
	| Base91 | `A-Za-z0-9!#$%&()*+,./:;<=>?@[]^_` | `fPNKd)T1E8K\*+9MH/@RPE.` |

	Usually decoded with python or the `base64 -d` command.


* [Base65535](https://github.com/qntm/base65536)


	Unicode characters encoding. Includes a lot of seemingly random spaces and chinese characters!


* [Base41](https://github.com/sveljko/base41/blob/master/python/base41.py)


* [Enigma](https://en.wikipedia.org/wiki/Enigma_machine)

	Machine used by the Germans during World War II to encrypt messages. Still takes a lot of time to crack today, but some tricks can be used to speed up the process.

	[404CTF WU](https://remyoudompheng.github.io/ctf/404ctf/enigma.html)


	