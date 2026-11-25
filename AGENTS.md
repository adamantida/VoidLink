<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it BEFORE grep/find or reading files when you need to understand or locate code:

- **Shell** (always works): `codegraph explore "<symbol names or question>"` prints the same output.

If there is no `.codegraph/` directory, init the graph, and use
<!-- CODEGRAPH_END -->

## Проектные скиллы

В репозитории лежат скиллы этого проекта — `.dsh/skills/`; они подхватываются
автоматически, когда задача совпадает по описанию:

- `voidlink-protocol` — изменение проводного формата: protocol → server → client → фаззинг → `PROTOCOL.md`;
- `voidlink-testing` — гейты `fmt`/`clippy`/`test`, счёт для бейджа, e2e, NAT-лаборатория, ограничения Windows;
- `voidlink-docs` — синхронизация 20 документов и инварианты (счёт тестов, версия протокола, лимиты);
- `voidlink-windows` — служба `TunnelDaemon`, пайп и SDDL, Wintun, трей, ACL, MSI.
