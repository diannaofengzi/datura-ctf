* `file`

    Deduce the file type from the headers.

* `binwalk`

    Look for embedded files in other files.

    
    ```bash
    binwalk <file>            # List embedded files
    binwalk -e <file>         # Extract embedded files
    binwalk --dd=".*" <file>  # Extract all embedded files
    ```

* `strings`

    Extract strings from a file.

* `grep`

    Search for a string in a file.


* `yara`

    Scan a file with Yara rules.

* [`file signatures`](https://en.wikipedia.org/wiki/List_of_file_signatures)

    A list of file signatures. The most common ones are :

    | Hex signature | File type | Description |
    | --- | --- | --- |
    | `FF D8 FF` (???) | JPEG | [JPEG](https://en.wikipedia.org/wiki/JPEG) image |
    | `89 50 4E 47 0D 0A 1A 0A` (?PNG) | PNG | [PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) image |
    | `50 4B` (PK) | ZIP | [ZIP](https://en.wikipedia.org/wiki/Zip_(file_format)) archive |

