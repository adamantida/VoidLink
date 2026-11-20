<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it BEFORE grep/find or reading files when you need to understand or locate code:

- **MCP tool** (when available): `codegraph_explore` answers most code questions in one call — the relevant symbols' verbatim source plus the call paths between them, including dynamic-dispatch hops grep can't follow. Name a file or symbol in the query to read its current line-numbered source. If it's listed but deferred, load it by name via tool search.
- **Shell** (always works): `codegraph explore "<symbol names or question>"` prints the same output.

If there is no `.codegraph/` directory, skip CodeGraph entirely — indexing is the user's decision.
<!-- CODEGRAPH_END -->

## Проектные скиллы

В репозитории лежат скиллы этого проекта — `.dsh/skills/`; они подхватываются
автоматически, когда задача совпадает по описанию:

- `voidlink-protocol` — изменение проводного формата: protocol → server → client → фаззинг → `PROTOCOL.md`;
- `voidlink-testing` — гейты `fmt`/`clippy`/`test`, счёт для бейджа, e2e, NAT-лаборатория, ограничения Windows;
- `voidlink-docs` — синхронизация 20 документов и инварианты (счёт тестов, версия протокола, лимиты);
- `voidlink-windows` — служба `TunnelDaemon`, пайп и SDDL, Wintun, трей, ACL, MSI.

## Память (MCP)

Инструменты `mcp__notes__*` — basic-memory, проект `voidlink`
(`~/.dsh/memory/basic/voidlink`, заметки Markdown). Перед задачей: `bm_search`
с `project: "voidlink"` (`mode: "text"` для идентификаторов вроде `IpcMode::None`,
`mode: "hybrid"` для смысловых запросов), затем `bm_read`. После принятого решения
или найденной ловушки: `bm_write` (одна заметка на тему, `[[wikilink]]` для связей)
или `bm_edit`. Писать атомарные факты, решения (`decision:`) и ловушки (`gotcha:`);
транскрипты, содержимое файлов и секреты — не писать.
