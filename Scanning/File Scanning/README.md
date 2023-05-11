* `file`

    Deduce the file type from the headers.

* `binwalk` :heart:

    Look for embedded files in other files.

    
    ```bash
    binwalk <file>            # List embedded files
    binwalk -e <file>         # Extract embedded files
    binwalk --dd=".*" <file>  # Extract all embedded files
    ```
    Alternatives: `foremost`, `hachoir-subfile`...

* `strings`

    Extract strings from a file.

* `grep`

    Search for a string, or regex, in a file.

	```bash
	grep <string> <file>          # Search in a file
	grep -r <string> <directory>  # Search recursively in a directory
	```

* `hexdump`

	Display the hexadecimal representation of a file.

	```bash
	hexdump -C <file>  # Dump bytes with adress and ascii representation
	hexdump <file>     # Dump bytes with adress only
	xxd -p <file>      # Dump only bytes
	```


* `yara` - [Website](https://virustotal.github.io/yara/)

    Scan a file with Yara rules to find (malicious) patterns. ules can be found in the [Yara-Rules](https://github.com/Yara-Rules/rules)

* `file signatures` - [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

    File signatures are bytes at the beginning of a file that identify the file type. This header is also called magic numbers.

    Most files can be [found here](https://en.wikipedia.org/wiki/List_of_file_signatures), but the most common ones are :

    | Hex signature | File type | Description |
    | --- | --- | --- |
    | `FF D8 FF` (???) | JPEG | [JPEG](https://en.wikipedia.org/wiki/JPEG) image |
    | `89 50 4E 47 0D 0A 1A 0A` (?PNG) | PNG | [PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) image |
    | `50 4B` (PK) | ZIP | [ZIP](https://en.wikipedia.org/wiki/Zip_(file_format)) archive |