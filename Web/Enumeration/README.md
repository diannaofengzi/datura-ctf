

* `robots.txt`

	File to tell search engines not to index certain files or directories.


* Mac / Macintosh / Apple Hidden Files `.DS_Store` [DS_Store_crawler](https://github.com/anantshri/DS_Store_crawler_parser)

	On Mac computers, there is a hidden index file `.DS_Store`. Useful if you have a **LFI** vulnerability.

```bash
python3 dsstore_crawler.py -i <url>
```

* Bazaar `.bzr` directory

	Contains the history of the project. Can be used to find old versions of the project. Can be fetched with [https://github.com/kost/dvcs-ripper](https://github.com/kost/dvcs-ripper)

Download the bzr repository:
```bash
bzr branch <url> <out-dir>
```

* `/.git/`

	Sign of an exposed git repository. Contains the history of the project. Can be used to find old versions of the project and to maybe find credentials in sources.

* [`GitDumper`](https://github.com/arthaud/git-dumper)

	A command-line tool that will automatically scrape and download a [git](https://git-scm.com/) repository hosted online with a given URL.

```bash
gitdumper <url>/.git/ <out-dir>
```

