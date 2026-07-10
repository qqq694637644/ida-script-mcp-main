# IDAPython Skill Index for GPT-5.6 Sol

## GPT Action workflow

1. `retrieveSkillContext`
2. `listIdaInstances` when the target instance is not already clear
3. `getIdaDatabaseInfo` when database identity or architecture matters
4. `listIdaFunctions`, `decompileIdaFunction`, or `getIdaXrefs` for direct reads
5. `executeIdapython` for custom analysis, bulk work, mutations, or validation
6. Inspect `status`, `stdout`, `stderr`, `result`, and `error`; perform a targeted read-back after mutations when needed

Do not repeat completed retrieval or live IDA calls without a concrete reason.

## Multi-skill behavior

- `allow_skill_chaining=true` may return multiple `selected_skills`.
- `searchSkillDocs` and `readSkillContent` require one explicit `skill_id`.
- Inspect only the selected skills that contribute to the current task.

## Documentation map

- `docs/idautils.md`
- `docs/ida_funcs.md`
- `docs/ida_xref.md`
- `docs/ida_hexrays.md`
- `docs/ida_bytes.md`
- `docs/ida_name.md`
- `docs/ida_typeinf.md`
- `docs/ida_segment.md`
- `docs/ida_auto.md`
