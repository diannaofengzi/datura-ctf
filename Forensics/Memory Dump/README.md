Memory dumps are captures of the state of the memory at a given time. It contains all the loaded files, processes and data that was used at this moment.

Memory dumps can be analyzed using the [Volatility Framework](https://www.volatilityfoundation.org/) :heart: .

Two versions of the framework are available:
- [Volatility 2](https://github.com/volatilityfoundation/volatility) (Python 2)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
Volatility 3 have currently less features but is easier to use. Volatility requires profiles which can sometimes be hard to find. Both versions are often used simultaneously.

The documentation can be found [here](https://volatility3.readthedocs.io)

* `Online Cheat Sheet` - [Website](https://blog.onfvp.com/post/volatility-cheatsheet/)

* `Windows Memory Forensics` - [Website](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html#)

* `Linux Memory Forensics` - [Website](https://volatility3.readthedocs.io/en/latest/getting-started-linux-tutorial.html)

* Most useful plugins

    | Plugin | Description |
    | --- | --- |
    | `pslist` | List all processes |
    | `filescan` | List all files |
    | `filedump` | Dump a file from memory |
    | `netscan` | List all network connections |

    Some usefull windows commands:
    ```bash
    # Utility
    export DUMP_NAME=memory.dmp
    mkdir out

    # General information
    sudo vol -f $DUMP_NAME windows.info # Get windows version
    sudo vol -f $DUMP_NAME windows.filescan > out/filescan.txt # List all files
    sudo vol -f $DUMP_NAME windows.pslist > out/pslist.txt # List all running processes
    sudo vol -f $DUMP_NAME windows.pstree > out/pstree.txt # List all running processes as a tree
    sudo vol -f $DUMP_NAME windows.netscan > out/netscan.txt # List all network connections
    sudo vol -f $DUMP_NAME windows.cmdlines > ./out/cmdlines.txt # List all commands executed and their arguments (arguments are usually very interesting)
    
    # Specific information
    sudo vol -f $DUMP_NAME windows.dumpfiles --physaddr <addr> # Dump a file from memory (addr from filescan)
    sudo vol -f $DUMP_NAME windows.handles --pid <pid> # List all handles of a process (files opened, etc...)
    
    # Registry
    sudo vol -f $DUMP_NAME windows.registry.hivescan > out/hivescan.txt # List all registry hives
    sudo vol -f $DUMP_NAME windows.registry.hivelist > out/hivelist.txt # List all registry hives
    sudo vol -f $DUMP_NAME windows.registry.printkey.PrintKey --key 'Software\Microsoft\Windows\CurrentVersion\Run' > out/autoruns.txt # List all autoruns
    ```

    Some usefull linux commands:
    ```bash
    # Utility
    export DUMP_NAME=memory.dmp
    mkdir out

    # General information
    sudo vol -f $DUMP_NAME linux.info # Get linux version
    sudo vol -f $DUMP_NAME linux.filescan > out/filescan.txt # List all files
    sudo vol -f $DUMP_NAME linux.pslist > out/pslist.txt # List all running processes
    sudo vol -f $DUMP_NAME linux.pstree > out/pstree.txt # List all running processes as a tree
    sudo vol -f $DUMP_NAME linux.netscan > out/netscan.txt # List all network connections
    sudo vol -f $DUMP_NAME linux.cmdlines > ./out/cmdlines.txt # List all commands executed and their arguments (arguments are usually very interesting)

    # Specific information
    sudo vol -f $DUMP_NAME linux.dumpfiles --physaddr <addr> # Dump a file from memory (addr from filescan)
    sudo vol -f $DUMP_NAME linux.handles --pid <pid> # List all handles of a process (files opened, etc...)
    ```





* Browser profile

    It is often a good idea to look at the browser profile to find interesting information, such as bookmarks, history, cookies, stored passwords, etc... 
    
    See [Browser Forensics](../Browser%20Forensics/README.md) for more information.



