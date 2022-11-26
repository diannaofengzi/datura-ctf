
* `binwalk`

	A command-line tool to carve files out of another file.

Extract files:
```bash
binwalk -e [filename]
```

* [`yara`](https://virustotal.github.io/yara/)

	Find patterns in files. Rules can be found in the [Yara-Rules](https://github.com/Yara-Rules/rules)

Usage
```bash
yara <rules.yar> <file>
```


* [`dumpzilla`](http://www.dumpzilla.org/)

	A [Python](https://www.python.org/) script to examine a `.mozilla` configuration file, to examine downloads, bookmarks, history or bookmarks and registered passwords. Usage may be as such:

```
python dumpzilla.py .mozilla/firefox/c3a958fk.default/ --Downloads --History --Bookmarks --Passwords
```


* Keepass

	`keepassx` can be installed on Ubuntu to open and explore Keepass databases. Keepass databases master passwords can be cracked with `keepass2john`.

* [Magic Numbers](https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_numbers_in_files) 
	The starting values that identify a file format. These are often crucial for programs to properly read a certain file type, so they must be correct. If some files are acting strangely, try verifying their [magic number] with a [trusted list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

* [`hexed.it`](https://hexed.it/)

	An online tool that allows you to modify the hexadecimal and binary values of an uploaded file. This is a good tool for correcting files with a corrupt [magic number]


* `foremost`

	A command-line tool to carve files out of another file. Usage is `foremost [filename]` and it will create an `output` directory.

```
sudo apt install foremost
```


* [`hachoir-subfile`](https://pypi.python.org/pypi/hachoir-subfile/0.5.3)

	A command-line tool to carve out files of another file. Very similar to the other tools like `binwalk` and `foremost`, but always try everything!


* [TestDisk](https://www.cgsecurity.org/Download_and_donate.php/testdisk-7.1-WIP.linux26.tar.bz2) 
	A command-line tool, used to recover deleted files from a file system image. Handy to use if given a `.dd` and `.img` file etc.

* [photorec](https://www.cgsecurity.org/wiki/PhotoRec) 
	Another command-line utility that comes with `testdisk`. It is file data recovery software designed to recover lost files including video, documents and archives from hard disks, CD-ROMs, and lost pictures (thus the Photo Recovery name) from digital camera memory. PhotoRec ignores the file system and goes after the underlying data, so it will still work even if your media's file system has been severely damaged or reformatted.


