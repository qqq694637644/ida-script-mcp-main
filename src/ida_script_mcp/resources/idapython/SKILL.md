---
name: idapython
description: Use for IDAPython scripting, live IDA database analysis, Hex-Rays decompilation, functions, xrefs, names, types, patches, and IDB automation through the ida_skill GPT Actions runtime.
---

# IDAPython for GPT-5.6 Sol

Use this skill for IDAPython tasks in the `ida_skill` GPT Actions runtime. Treat this file, the task-relevant referenced files, and live IDA Action responses as the evidence for the answer.

## Action workflow

1. `retrieveSkillContext` is the normal entry point. Once this `SKILL.md` has been returned, do not retrieve it again without a concrete reason.
2. Use live IDA Actions for facts about the open database. Do not guess database identity, addresses, functions, xrefs, pseudocode, or execution results.
3. Use `listIdaInstances` when the target instance is unclear. Use `getIdaDatabaseInfo` when database identity, architecture, image base, or input file matters.
4. Prefer direct structured reads when they cover the observation:
   - `listIdaFunctions`
   - `decompileIdaFunction`
   - `getIdaXrefs`
5. Use `executeIdapython` for custom analysis, bulk work, renaming, comments, patches, type changes, and validation not covered by structured Actions. This is a trusted personal workflow; do not add another approval step when the user's intent is clear.
6. After `executeIdapython`, inspect `status`, `stdout`, `stderr`, `result`, and `error`. After a mutation, perform a targeted read-back when the execution response alone does not prove the change.

## Progressive disclosure

Read only the references required by the task. Use `readSkillContent` with this skill's `skill_id` and the exact relative path below. Read a selected reference completely, continuing with `start_line` when the response is truncated. Use `searchSkillDocs` only when this routing table does not identify the required reference.

| Task | Read |
|---|---|
| Function iteration, items, strings, convenience iterators | `docs/idautils.md` |
| Function boundaries, chunks, flags, names | `docs/ida_funcs.md` |
| Incoming or outgoing references | `docs/ida_xref.md` |
| Pseudocode, ctree, local variables, decompiler failures | `docs/ida_hexrays.md` |
| Reading, defining, or patching bytes and data | `docs/ida_bytes.md` |
| Symbol lookup, renaming, demangling | `docs/ida_name.md` |
| Function prototypes, structures, and `tinfo_t` | `docs/ida_typeinf.md` |
| Segments and address ranges | `docs/ida_segment.md` |
| Auto-analysis waiting and planning | `docs/ida_auto.md` |

Use the matching RST file in the docs directory only when the Markdown reference is insufficient. Do not load unrelated references. When multiple `selected_skills` are returned, keep every read scoped to the explicit `skill_id` that owns the resource.

## IDAPython invariants

- Prefer modern `ida_*` modules when practical and include required imports.
- Call `ida_auto.auto_wait()` before relying on auto-analysis results.
- Assume `ea_t` may contain 64-bit addresses.
- Parse user-supplied hexadecimal or decimal strings with `int(value, 0)` when needed.
- Validate hardcoded addresses against the live database before use.
- Handle unavailable Hex-Rays or decompilation failure explicitly.
- Do not invent undocumented IDAPython APIs.

## Completion

Distinguish documentation-based guidance from verified live IDA results. Do not repeat completed skill reads or live IDA calls unless new evidence is required.
