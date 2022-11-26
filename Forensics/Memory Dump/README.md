Memory dumps are captures of the state of the memory at a given time. It contains all the loaded files, processes and data that was used at this moment.

Memory dumps can be analyzed using the [Volatility Framework](https://www.volatilityfoundation.org/)

I recommand using **volatility 3** so you do not have to bother with profiles (finding it was often a pain in vol2)

The documentation can be found [here](https://volatility3.readthedocs.io)

* [Online Cheat Sheet](https://blog.onfvp.com/post/volatility-cheatsheet/)

* [Windows Memory Forensics](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html#)

* [Linux Memory Forensics](https://volatility3.readthedocs.io/en/latest/getting-started-linux-tutorial.html)

* Most useful plugins

| Plugin | Description |
| --- | --- |
| `pslist` | List all processes |
| `filescan` | List all files |
| `filedump` | Dump a file from memory |
| `netscan` | List all network connections |

* Browser profile

    The browser profile contains a lot of information about the user, such as bookmarks, history, cookies, stored passwords, etc.

In Windows:
| Browser | Location |
| --- | --- |
| Chrome | `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default` |
| [Firefox](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) | `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>` |
| Edge | `C:\Users\<username>\AppData\Local\Microsoft\Edge\User Data\Default` |

In Linux:
| Browser | Location |
| --- | --- |
| Chrome | `~/.config/google-chrome/Default` |
| [Firefox](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) | `~/.mozilla/firefox/<profile>` |



