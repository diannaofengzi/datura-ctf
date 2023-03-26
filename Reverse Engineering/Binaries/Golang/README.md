[GO](go.dev) is a compiled programming language developped by google as a high level alternative to C. It is statically typed and compiled to machine code.

Function are named after the library they are from. For exemple, function from the standard I/O library are `fmt.<function>`. The main function is called `main.main`.

When the binary is stripped, the function's informations are stored in the `.gopclntab` section. 

