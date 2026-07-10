# IDAPython GPT Action index

Use this skill for IDA Pro automation, IDAPython scripting, Hex-Rays decompilation, function and xref analysis, type work, comments, renaming, patching, and IDB inspection in the `ida_skill` GPT Action runtime.

## GPT Action workflow

1. `retrieveSkillContext` selects this skill and returns the relevant rules and docs.
2. `listIdaInstances` finds available IDA sessions.
3. `getIdaDatabaseInfo` confirms the target IDB.
4. Use structured read Actions when they cover the task:
   - `listIdaFunctions`
   - `decompileIdaFunction`
   - `getIdaXrefs`
5. Use `executeIdapython` for custom analysis, bulk operations, mutations, or validation scripts.
6. Inspect `executeIdapython` result fields before answering: `status`, `stdout`, `stderr`, `result`, and `error`.

## Multi-skill behavior

When `allow_skill_chaining=true` returns multiple `selected_skills`, keep each skill scoped to its own `skill_id`. Use `searchSkillDocs` and `readSkillContent` with the specific `skill_id` being investigated. Do not assume one skill's docs apply to another skill.

## Documentation map

- `docs/idautils.md`: iterating functions, xrefs, strings, segments, and names.
- `docs/ida_funcs.md`: function boundaries, flags, chunks, and metadata.
- `docs/ida_xref.md`: cross-reference APIs and xref type handling.
- `docs/ida_hexrays.md`: decompiler APIs, pseudocode, ctree visitors, and Hex-Rays objects.
- `docs/ida_bytes.md`: reading and patching bytes, flags, comments, and data items.
- `docs/ida_name.md`: symbol lookup and renaming.
- `docs/ida_typeinf.md`: type information, function prototypes, structures, and `tinfo_t`.
- `docs/ida_segment.md`: segments, address ranges, and memory layout.
- `docs/ida_auto.md`: autoanalysis waiting and planning helpers.
- `docs/idc.md`: legacy convenience helpers only when documented and clearly simpler.

## Script generation rules

Prefer modern `ida_*` modules when practical. Mention required imports. Use Python-native parsing such as `int(value, 0)` for hex or decimal strings. When a script can mutate the IDB, make the intended changes explicit in the code and explanation. Inspect `executeIdapython` results before concluding.
