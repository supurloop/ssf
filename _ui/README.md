# User Interface

[SSF](../README.md)

User-facing input parsing and presentation interfaces.

| Module | Description | Source Files | Documentation |
|--------|-------------|--------------|---------------|
| ssfargv | Command line string to gobj parser | ssfargv.c, ssfargv.h | [ssfargv.md](ssfargv.md) |
| ssfcli | CLI framework | ssfcli.c, ssfcli.h | [ssfcli.md](ssfcli.md) |
| ssfvted | ANSI/VT100 terminal line editor | ssfvted.c, ssfvted.h | [ssfvted.md](ssfvted.md) |

## See Also

- [Generic Object](../_codec/ssfgobj.md) — Hierarchical generic object container produced by `ssfargv`
- [Safe Strings](../_codec/ssfstr.md) — Safe C string utilities for working with the buffer produced by `ssfvted`
- [Linked List](../_struct/ssfll.md) — Linked list used internally by `ssfcli` for the command registry
