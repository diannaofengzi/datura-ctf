* Missing `ls` or `dir` commands

	If you cannot run `ls` or `dir`, or `find` or `grep`, to list files you can use

	```
	echo *
	echo /any/path/*
	```


* restricted bash (`rbash`) read files

	If you are a restricted shell like `rbash` you can still read any file with some builtin commands like `mapfile`:

	```
	mapfile -t  < /etc/passwd
	printf "$s\n" "${anything[@]}"
	```


* Python 3

    `().__class__.__base__.__subclasses__()` - Gives access to `object` subclasses