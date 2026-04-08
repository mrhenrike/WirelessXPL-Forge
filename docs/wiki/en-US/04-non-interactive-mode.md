# Non-interactive (batch) CLI

**Language:** English (en-US). **pt-BR:** [../pt-BR/04-modo-nao-interativo.md](../pt-BR/04-modo-nao-interativo.md)

## Syntax

```bash
wxf -m <module/path> [-s "option value"] ...
# or: python wxf.py …   or: python -m wirelessxpl …
```

- `-m` / `--module`: module path (internal normalization accepts slashes).
- `-s` / `--set`: repeat; each string parsed like interactive `set` (first word = option name).

## Example

```bash
wxf -m creds/generic/ssh_default -s "target 192.168.0.50" -s "port 22" -s "threads 4"
```

Flow: `use` → each `set` → one `run`/`exploit`.

## Help

```bash
wxf -h
```

## Pipelines

Redirect output carefully — it may contain credentials or banners. There is no universal JSON mode.

---

[Wiki hub](../README.md)
