# FakeTLS для MTProxy — документация

Место разработки: **`D:/RustProjects/grammers`** (git, `origin = git@github.com:alksef/grammers.git`).
Папка `D:/RustProjects/grammers-mtproxy-alksef-master` — это **устаревшая zip-копия** того же репо
без git-истории. Весь код и доки ведём здесь.

> Создано 2026-07-09 при ресерче «почему faketls не заработал и на чём уперлось».

## TL;DR (главное)

- В `master` сейчас **нет** кода faketls (модуль `grammers-mtproto/src/tls/` удалён).
  Вся предыдущая реализация сохранена в истории веток/коммитов — см. [02-root-cause-analysis.md](02-root-cause-analysis.md).
- MTProxy **Simple / DD** режимы работают (текущий рабочий ключ `argeiphontes.ru:13370`
  с 16-байтным секретом — Simple, без префикса).
- FakeTLS **не заработал** в прошлой попытке. Корень проблемы найден точно —
  это **не** баг буферизации `AsyncWrite` (как предполагала заметка `text.txt`),
  а **архитектурное расхождение с эталоном**: прошлая реализация после
  FakeTLS-handshake уходила в «raw mode» (сырые AES-CTR байты без TLS-framing),
  а сервер MTProxy ждёт, что **весь** трафик продолжает идти в TLS-Application-records.
  Сервер рвёт соединение с `incorrect tls version` → клиент ловит
  `EOF while reading TLS record header`.
- Тип прокси **не задаётся явно** — определяется по длине секрета
  (16 = Simple, 17 = DD/Secured, >17 = TLS/faketls). Это совпадает с эталоном gotd/td.

## Структура документов

| Файл | О чём |
|------|-------|
| [01-protocol-and-architecture.md](01-protocol-and-architecture.md) | Эталонная архитектура gotd/td, формат секрета, слои протокола |
| [02-root-cause-analysis.md](02-root-cause-analysis.md) | **Точный диагноз** провала прошлой попытки + опровержение гипотезы `text.txt` |
| [03-references.md](03-references.md) | Три эталонных реализации (gotd/td, tdesktop, Telethon), их ветки/коммиты, что брать |
| [04-implementation-plan.md](04-implementation-plan.md) | План портирования faketls на текущий `master` |
| [05-rounds-progress-and-status.md](05-rounds-progress-and-status.md) | **Промежуточный итог**: статус итераций, что доказано, на чём застряли |

## Текущее состояние веток (2026-07-09)

| Репозиторий | Путь | Ветка | HEAD | FakeTLS |
|-------------|------|-------|------|---------|
| alksef/grammers (этот репо) | `D:/RustProjects/grammers` | `master` | `8519c06` | код удалён, история есть |
| gotd/td | `D:/Projects/td` | `main` | `36ad1b14f` | ✅ **эталон**, `mtproxy/faketls/` |
| telegramdesktop/tdesktop | `D:/Projects/tdesktop` | `dev` | `27f41580d2` | ✅ есть (C++) |
| Telethon | `D:/PycharmProjects/Telethon` | `v1` | `577812be` | ❌ домен обрезается (`tcpmtproxy.py:145`) |

## Рабочие тестовые ключи

| Сервер | Секрет | Режим | Статус |
|--------|--------|-------|--------|
| `argeiphontes.ru:13370` | `4758456789abcdef0123456789abcdef` | Simple (16 байт) | ✅ работает |
| `argeiphontes.ru:13371` | `ee7b184b3f7c1ace06fa2efbbaa851f1a8617267656970686f6e7465732e7275` | FakeTLS (ee+key+домен) | ❌ цель задачи |
