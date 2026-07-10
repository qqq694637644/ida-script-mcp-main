# IDAPython documentation index

Use this skill for IDA Pro automation, IDAPython scripting, Hex-Rays decompilation, function and xref analysis, type work, comments, renaming, patching, and IDB inspection.

## Recommended live-action order

1. `listIdaInstances` to find the active IDA database.
2. `getIdaDatabaseInfo` to confirm architecture, image base, file path, and function counts.
3. `listIdaFunctions`, `decompileIdaFunction`, or `getIdaXrefs` for structured reads.
4. `executeIdapython` when custom IDAPython is the fastest or most direct way to solve the task.

## Common docs

- `docs/idautils.md`: iterating functions, xrefs, strings, segments, and names.
- `docs/ida_funcs.md`: function boundaries, flags, chunks, and metadata.
- `docs/ida_xref.md`: cross-reference APIs and xref type handling.
- `docs/ida_hexrays.md`: decompiler APIs, pseudocode, ctree visitors, and Hex-Rays objects.
- `docs/ida_bytes.md`: reading and patching bytes, flags, comments, and data items.
- `docs/ida_name.md`: symbol lookup and renaming.
- `docs/ida_typeinf.md`: type information, function prototypes, structures, and `tinfo_t`.
- `docs/ida_segment.md`: segments, address ranges, and memory layout.
- `docs/idc.md`: legacy convenience helpers still useful for simple tasks.

## Script generation rules

Prefer modern `ida_*` modules when practical. Mention required imports. When a script can mutate the IDB, make the intended changes explicit in the code and in the explanation. Inspect `executeIdapython` results by checking `status`, `stdout`, `stderr`, `result`, and `error`.
