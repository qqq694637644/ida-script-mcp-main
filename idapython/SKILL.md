---
name: idapython
description: GPT-5.6 Sol guidance for IDAPython tasks through the ida_skill GPT Actions runtime.
---

# IDAPython Skill for GPT-5.6 Sol

Use this skill after `retrieveSkillContext` selects `idapython`. Retrieved skill rules, selected docs, and live IDA Action results are the evidence for the answer.

## Runtime rules

1. `retrieveSkillContext` is the normal entry point. After this skill is selected, do not repeat retrieval unless a concrete documentation gap remains.
2. Use retrieved docs as the source of IDAPython API behavior. Do not invent undocumented APIs.
3. Obtain current IDB facts through live IDA Actions; do not guess database identity, addresses, functions, xrefs, pseudocode, or execution results.
4. Use `listIdaInstances` when the target instance is not unambiguous. Use `getIdaDatabaseInfo` when database identity, architecture, image base, or file details matter.
5. Prefer direct structured reads when they cover the observation: `listIdaFunctions`, `decompileIdaFunction`, and `getIdaXrefs`.
6. Use `executeIdapython` for custom analysis, bulk processing, renaming, comments, patches, type changes, or validation scripts. In this personal workflow, do not add an extra approval step when the user's intent is clear.
7. After `executeIdapython`, inspect `status`, `stdout`, `stderr`, `result`, and `error`. After a mutation, perform a targeted read-back when the response alone does not prove the change.
8. When `allow_skill_chaining=true` returns multiple `selected_skills`, keep each skill scoped to its own `skill_id`. `searchSkillDocs` and `readSkillContent` operate on one explicit `skill_id` at a time.

## IDAPython rules

- Prefer modern `ida_*` modules when practical and include required imports.
- Call `ida_auto.auto_wait()` before relying on auto-analysis results.
- Assume `ea_t` may contain 64-bit addresses.
- Parse user-supplied hex or decimal strings with `int(value, 0)` when needed.
- Handle unavailable Hex-Rays or decompilation failure explicitly.
- Validate hardcoded addresses against the live database before use.

## Module router

| Task | Module | Common APIs |
|---|---|---|
| Bytes and patches | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags` |
| Functions | `ida_funcs` | `get_func`, `get_func_name`, `add_func` |
| Names | `ida_name` | `get_name`, `set_name`, `demangle_name` |
| Types | `ida_typeinf` | `tinfo_t`, `parse_decl`, `apply_tinfo` |
| Decompiler | `ida_hexrays` | `decompile`, `cfunc_t`, ctree visitors |
| Xrefs | `ida_xref`, `idautils` | `xrefblk_t`, `XrefsTo`, `XrefsFrom` |
| Iteration | `idautils` | `Functions`, `FuncItems`, `Strings` |
| Database info | `ida_ida` | `inf_get_*`, `inf_is_64bit` |
| Analysis | `ida_auto` | `auto_wait`, `plan_and_wait` |

## Core patterns

### Functions

```python
import ida_funcs
import idautils

for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)
    name = ida_funcs.get_func_name(ea)
```

### Xrefs

```python
import idautils

for xref in idautils.XrefsTo(ea):
    print(f"{xref.frm:#x} -> {xref.to:#x} type={xref.type}")
```

### Decompile

```python
import ida_hexrays

cfunc = ida_hexrays.decompile(ea)
if cfunc is None:
    raise RuntimeError(f"decompilation failed at {ea:#x}")
print(cfunc)
```

### Read or patch bytes

```python
import ida_bytes

data = ida_bytes.get_bytes(ea, size)
ida_bytes.patch_bytes(ea, b"\x90\x90")
```

### Apply a type

```python
import ida_typeinf

tif = ida_typeinf.tinfo_t()
if ida_typeinf.parse_decl(tif, None, "int (*)(char *, int)", 0):
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
```

## Documentation

Use `INDEX.md` for the shortest Action route and documentation map. Read `docs/<module>.md` for focused API guidance; use `docs/<module>.rst` only when the Markdown summary is insufficient.
