
* Magic Hashes

	A common vulnerability in [PHP](https://en.wikipedia.org/wiki/PHP) that fakes hash "collisions..." where the `==` operator falls short in [PHP](https://en.wikipedia.org/wiki/PHP) type comparison, thinking everything that follows `0e` is considered scientific notation (and therefore 0). More valuable info can be found here: [https://github.com/spaze/hashes](https://github.com/spaze/hashes).


* `preg_replace`

	A bug in older versions of [PHP](https://en.wikipedia.org/wiki/PHP) where the user could get remote code execution

	[http://php.net/manual/en/function.preg-replace.php](http://php.net/manual/en/function.preg-replace.php)


* [`phpdc.phpr`](https://github.com/lighttpd/xcache/blob/master/bin/phpdc.phpr)

	A command-line tool to decode [`bcompiler`](http://php.net/manual/en/book.bcompiler.php) compiled [PHP](https://en.wikipedia.org/wiki/PHP) code.


* [`php://filter` for Local File Inclusion](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/)

	A bug in [PHP](https://en.wikipedia.org/wiki/PHP) where if GET HTTP variables in the URL are controlling the navigation of the web page, perhaps the source code is `include`-ing other files to be served to the user. This can be manipulated by using [PHP filters](http://php.net/manual/en/filters.php) to potentially retrieve source code. Example like so:

```
http://xqi.cc/index.php?m=php://filter/convert.base64-encode/resource=index
```


* `data://text/plain;base64`

	A [PHP](https://en.wikipedia.org/wiki/PHP) stream that can be taken advantage of if used and evaluated as an `include` resource or evaluated. Can be used for RCE: check out this writeup: [https://ctftime.org/writeup/8868](https://ctftime.org/writeup/8868) ... TL;DR:

```
http://103.5.112.91:1234/?cmd=whoami&page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4=
```


* [`PHP Generic Gadget Chains`](https://github.com/ambionics/phpggc)

	Payloads for Object injection in `unserialize` on different frameworks.