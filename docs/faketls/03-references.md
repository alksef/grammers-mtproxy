# Эталонные реализации FakeTLS

Все три локально, обновлены до актуального master 2026-07-09.

## 1. gotd/td (Go) — ГЛАВНЫЙ референс для портирования

- Путь: `D:/Projects/td`
- Remote: `https://github.com/gotd/td.git`, ветка `main`, HEAD `36ad1b14f`
- Чистая pure-Go реализация MTProto + всех режимов MTProxy, включая FakeTLS.
- Это лучший референс: читаемый, без C++, без FFI.

Ключевые файлы:

| Файл | Что даёт |
|------|----------|
| `mtproxy/obfuscator/obfuscator.go` | **Композиция слоёв** — `FakeTLS` оборачивает сокет, `Obfuscated2` пишет в `FakeTLS`. Главный урок: framing не снимается. |
| `mtproxy/secret.go` | Парсинг секрета **по длине** (Simple/Secured/TLS), извлечение cloak-домена. |
| `mtproxy/faketls/faketls.go` | Оркестратор handshake + quirk первого пакета (CCS). |
| `mtproxy/faketls/client_hello.go` | Точный byte-layout ClientHello, вычисление ClientRandom (HMAC + XOR ts). |
| `mtproxy/faketls/server_hello.go` | Чтение 3 records (ServerHello/CCS/Application), проверка ServerRandom. |
| `mtproxy/faketls/record.go` | TLS-record framing (5-байтный заголовок, big-endian length). |
| `mtproxy/faketls/tls.go` | Константы: ContentType, версии TLS. |
| `mtproxy/obfuscated2/keys.go`, `keys_util.go` | Вывод AES-CTR ключей из 64-байтного init + secret, фильтрация запрещённых первых байт. |
| `mtproxy/obfuscated2/obfuscated2.go` | AES-CTR encrypt/decrypt поверх conn (FakeTLS). |

Ссылки внутри кода на TDLib:
- `td/mtproto/TcpTransport.cpp` (CCS-quirk, init-фильтрация)
- `td/mtproto/TlsInit.cpp#L380` (HMAC ClientRandom)

## 2. tdesktop / TDLib (C++) — официальный эталон

- Путь: `D:/Projects/tdesktop`
- Remote: `https://github.com/telegramdesktop/tdesktop.git`, ветка `dev`, HEAD `27f41580d2`
- TDLib (лежит в `tdesktop/lib/td/...` либо upstream `github.com/tdlib/td`) — официальная
  реализация; faketls поддерживается нативно.
- Использовать **только для сверки** алгоритмов, не как основу порта (C++ тяжелее читается).

Соответствие файлов gotd → TDLib:
- `client_hello.go` ↔ `td/mtproto/TlsInit.cpp`
- `faketls.go` (CCS-quirk) ↔ `td/mtproto/TcpTransport.cpp#L266`
- obfs2 init filter ↔ `td/mtproto/TcpTransport.cpp#L157`

## 3. Telethon (Python) — частичный референс

- Путь: `D:/PycharmProjects/Telethon`
- Remote: `https://codeberg.org/Lonami/Telethon.git`, ветка `v1`, HEAD `577812be`
- `telethon/network/connection/tcpmtproxy.py` — MTProxyIO (obfuscated2).

⚠️ **Telethon НЕ поддерживает FakeTLS.** Строка 145:
```python
return secret_bytes[:16]  # Remove the domain from the secret (until domain support is added)
```
Домен обрезается, faketls не реализован. Брать отсюда **только** логику obfuscated2
(вывод ключей, init-фрейм) — она корректна и читается проще, чем в gotd.

## 4. mtg (Go) — сервер, для отладки

- Локально: `D:/GoProjects/mtg` (упоминается в старой `docs/faketls.md`)
- Remote: `github.com/9seconds/mtg`
- Это **MTProxy-сервер**, на котором тестировали (`server.log` — его лог).
- Полезен, чтобы поднять собственный proxy с известным секретом и смотреть серверный лог
  при отладке handshake'а.

## 5. Что не нашлось (Rust)

Проверено 2026-07-09: **ни одна** чисто-Rust MTProto-библиотека не реализует FakeTLS-клиент:
- `grammers` (Lonami) — только dd/ee-simple, без faketls (issues/PR по faketls отсутствуют).
- `ferogram` / `ferogram-crypto` — есть crypto-примитивы (`build_fake_tls_keys`), но это
  обрывки, не клиентский транспорт; как зависимость ненадёжен.
- `tdlib-rs`, `telegram-client` — обёртки над TDLib (C++), faketls наследуют через TDLib,
  но тянут всю C++-библиотеку. Для чистого-Rust форка grammers — не вариант.

**Вывод:** портировать FakeTLS из gotd/td (Go) в grammers (Rust). Это единственный путь
к чисто-Rust решению.
