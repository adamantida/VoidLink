<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it BEFORE grep/find or reading files when you need to understand or locate code:

- **Tool / MCP** (when available): `codegraph_explore` answers most code questions in one call — the relevant symbols' verbatim, line-numbered source plus the call paths between them, including dynamic-dispatch hops grep cannot follow. Name a file or symbol in the query. If it is listed but deferred, load it by name via tool search.
- **Shell** (always works): `codegraph explore "<symbol names or question>"` prints the same output.

No `.codegraph/` in this checkout (fresh clone, git worktree)? The index is per-checkout: run `codegraph init --yes` (≈6 s) — never fall back to grep on that account. Before searching after any edit, run `codegraph sync` (≈1 s); `codegraph status --strict` exits 1 while the index is stale.
<!-- CODEGRAPH_END -->

## Проектные скиллы

В репозитории лежит скилл этого проекта — `.dsh/skills/`; он подхватывается
автоматически, когда задача совпадает по описанию:

- `voidlink-windows` — служба `TunnelDaemon`, пайп и SDDL, Wintun, трей, ACL, MSI.

Маршруты изменений протокола, тестовые гейты и синхронизация документации
описаны в `docs/DEVELOPMENT.md` (§11, «Тестирование», «Документация»).

## Память

Проектная память ведётся в Hindsight (инструменты `hindsight_*`: страницы проекта,
поиск, рефлексия, ingest документов). MCP-заметок basic-memory (`mcp__notes__*`)
больше нет — не ищите и не пишите в них.
