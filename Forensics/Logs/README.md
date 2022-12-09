Looking at logs takes time but can lead to valuable information.

* [Windows Event Logs](https://en.wikipedia.org/wiki/Event_Viewer)

    Windows logs a *lot* of information. It can be read using `mmc.exe`, under "Windows Logs".

    The categories are:
    | Category | Description |
    | --- | --- |
    | Application | Programs (started, stopped ...) |
    | Security | Security events (login, logout, ...) |
    | System | Changes to system (boot, shutdown, peripherals ...) |
    | Setup | System maintainance (update logs, ...) |

* [Linux logs](https://fr.wikipedia.org/wiki/Syslog)

    Linux logs are stored in `/var/log/`. The most important ones are:
    | File | Description |
    | --- | --- |
    | `auth.log` or `secure` | Authentication events (login, logout, ...) |
    | `syslog` or `messages` | General messages (system wide) |
    | `dpkg.log` | Package managment |
    | `kern.log` | Kernel messages |
    | `btmp` | Failed login attempts |
    | `wtmp` | Login/logout history |
    | `lastlog` | Last login for each user |

    `btmp`, `wtmp` and `lastlog` can be read using `last <file>`

    Other applications can have their own logs in /var/logs.
