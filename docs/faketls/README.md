# FakeTLS для MTProxy — документация

Место разработки: **`~/RustProjects/grammers-mtproxy`** (git, `origin = git@github.com:alksef/grammers.git`).
Ранее велось на Windows (`D:/RustProjects/grammers`) — перенос на Linux 2026-07-10.

> Создано 2026-07-09 при ресерче «почему faketls не заработал и на чём уперлось».

## TL;DR (главное, обновлено 2026-07-10)

- В `master` код faketls **есть** (коммит `6f88547`, модуль `grammers-mtproto/src/tls/`).
  Round 1–17 вели отладку поверх него. **FakeTLS полностью запущен и работает E2E.**
- **Корень зависания в Round 16/17:** Клод ошибочно считал, что `gotd` шлет `transport-tag` (`eeeeeeee`/`dddddddd`) в поток как отдельный TLS-record. На самом деле это была длина первого MTProto-пакета. Отправка тега вешала Telegram.
- **Решение:** Мы настроили FakeTLS-клиент на использование `RandomizedIntermediate` (`PaddedIntermediate` аналог), а в `stream.rs` перехватываем и отбрасываем протокольный тег `0xdddddddd` на первом шаге, пуская в сеть чистый поток `[len][payload]`.
- MTProxy **Simple** режим также полностью работает.

## Структура документов

| Файл | О чём |
|------|-------|
| [01-protocol-and-architecture.md](01-protocol-and-architecture.md) | Эталонная архитектура gotd/td, формат секрета, слои протокола |
| [02-root-cause-analysis.md](02-root-cause-analysis.md) | Диагноз провала первой попытки (raw-mode) + опровержение гипотезы `text.txt` |
| [03-references.md](03-references.md) | Три эталонные реализации (gotd/td, tdesktop, Telethon), их ветки/коммиты, что брать |
| [04-implementation-plan.md](04-implementation-plan.md) | План портирования faketls на текущий `master` |
| [05-rounds-progress-and-status.md](05-rounds-progress-and-status.md) | Round 1–15: статус итераций, что доказано, на чём застряли |
| [06-rootcause-init-record.md](06-rootcause-init-record.md) | **Round 16 — КОРНЕВАЯ ПРИЧИНА**: init glued с MTProto в один record (Часть 1 — фиксен) + transport-tag glue (Часть 2) |
| [07-final-resolution.md](07-final-resolution.md) | **Итоговое решение (Победа)**: Разбор гипотезы transport-tag, отбрасывание тега из потока, E2E Pong и запуск. |
| [../deepseek/07-fix-faketls-transport-tag.md](../deepseek/07-fix-faketls-transport-tag.md) | План фикса Части 2 для deepseek: transport-tag отдельным TLS-record |

## Текущее состояние репозиториев (обновлено 2026-07-10)

| Репозиторий | Путь | Ветка | HEAD | FakeTLS |
|-------------|------|-------|------|---------|
| alksef/grammers (этот репо) | `~/RustProjects/grammers-mtproxy` | `master` | `6f88547` | ✅ **Полностью работает E2E** |
| gotd/td | `~/Projects/td` | `main` | shallow clone | ✅ **эталон**, `mtproxy/faketls/`, собирается+работает |
| telegramdesktop/tdesktop | (на Windows) | `dev` | — | ✅ рабочий client |

## Рабочие тестовые ключи

| Сервер | Секрет | Режим | Статус |
|--------|--------|-------|--------|
| `argeiphontes.ru:13370` | `4758456789abcdef0123456789abcdef` | Simple (16 байт) | ✅ работает |
| `argeiphontes.ru:16000` | `ee7b184b3f7c1ace06fa2efbbaa851f1a8617267656970686f6e7465732e7275` | FakeTLS (ee+key+домен) | ✅ **полностью работает (grammers/gotd/tdesktop)** |
