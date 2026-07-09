# План: FakeTLS — transport-tag отдельным TLS-record

> Задача для реализации. Контекст расследования —
> `docs/faketls/06-rootcause-init-record.md` (раздел «Часть 2»). Дампы —
> `docs/faketls/dumps/`. Реализуй по коду репозитория сам; ниже — постановка и
> цель, без указания конкретных правок.

## Суть проблемы

FakeTLS-подключение alksef виснет после handshake: handshake проходит полностью,
но Telegram не отвечает на первый MTProto-пакет (`req_pq_multi`). Доказано
сравнением wire-дампов с эталоном (gotd) через один и тот же mtg-сервер.

Корень — в структуре TLS-record'ов на проводе **после** FakeTLS-handshake.

## Эталон (gotd, рабочий)

После FakeTLS-handshake клиент шлёт серию TLS Application-records, и каждый
логический «блок» уходит **отдельным** record'ом:

1. obfs2-init (64 байта) — отдельный record.
2. transport-protocol-tag (`eeeeeeee`, признак Intermediate-транспорта) —
   **отдельный** record (ровно 4 байта).
3. Дальше — каждое MTProto-сообщение своим record'ом.

Это видно в дампе `docs/faketls/dumps/cap4_gotd.pcap`: после CCS идут record'ы
длин 64 (init), 4 (tag), затем данные.

## Текущее поведение alksef (сломанный)

После уже применённого фикса Части 1 init уходит отдельным record'ом (это ок).
Но transport-tag `eeeeeeee` **склеен** с первым MTProto-пакетом и уходит в одном
с ним record'е. Сервер после init-record'а ожидает следующий record как
транспортный тег, а получает tag+MTProto вместе → рассинхронизация потока →
сервер/Telegram молчит.

Причина в том, как транспортный слой (Intermediate) упаковывает первый пакет:
он-prepend'ит transport-tag в тот же буфер, что и `[длина][payload]`. Для
обычных режимов (Simple, прямой TCP) это работает, потому что там нет
TLS-record-границ. Для FakeTLS это ломает stream — tag должен быть отдельным
record'ом.

См. дамп `docs/faketls/dumps/cap5_alksef.pcap`: после CCS идут record'ы длин
64 (init) и 48 (tag+MTProto вместе).

## Цель

Добиться, чтобы на проводе в FakeTLS-режиме transport-tag уходил **своим
отдельным** TLS Application-record, как в gotd:

```
CCS
init (64)             — отдельный record
transport-tag (4)     — отдельный record   ← чего сейчас нет
MTProto-сообщения     — каждый своим record
```

Решение может быть любым корректным — главное соблюсти эту wire-структуру и не
сломать остальные режимы (Simple, DD-Secure, прямой TCP). Вероятно, потребуется
согласовать два слоя: тот, кто формирует transport-tag (transport), и
FakeTlsStream (кто оборачивает данные в TLS-record'ы), чтобы в FakeTLS-режиме
tag не клеился к данным, а уходил отдельным record'ом.

## Где смотреть в коде

- `grammers-mtproto/src/tls/stream.rs` — `FakeTlsStream`, `poll_write`
  (здесь формируются CCS / init / data record'ы).
- `grammers-mtproto/src/tls/framing.rs` — обёртка данных в TLS-record.
- `grammers-mtproto/src/transport/intermediate.rs` — `Intermediate::pack`
  (добавляет transport-tag).
- `grammers-mtsender/src/sender_pool.rs` — выбор транспорта для FakeTLS
  (сейчас plain Intermediate), `TransportWrapper`.
- `grammers-mtsender/src/net/tcp.rs` — создание `FakeTlsStream`, `NetStream`.

## Ограничения (не трогать)

- Крипто-слой obfs2 (`obfuscator.rs`) — байт-идентичен эталону gotd, доказано
  ранее. AES-CTR / key-derivation / init-структура корректны.
- `framing.rs` — TLS-record framing корректен (record-заголовки валидны).
- `client_hello.rs` / `server_hello.rs` — handshake работает.

## Критерий успеха

1. Существующие unit-тесты (`cargo test -p grammers-mtproto --features mtproxy`)
   проходят, регрессий нет.
2. Wire-дамп alksef после фикса содержит **отдельный** 4-байтный record с
   transport-tag между init-record и первым MTProto-record (как в
   `cap4_gotd.pcap`).
3. End-to-end: example `grammers-client/examples/mtproxy.rs` через mtg
   `argeiphontes.ru:16000` (secret `ee7b184b3f7c1ace06fa2efbbaa851f1a8617267656970686f6e7465732e7275`,
   dc=4) получает ответ от Telegram (`Pong`), а не виснет.

## Как проверить

```bash
# тесты
cargo test -p grammers-mtproto --features mtproxy

# сборка example
cargo build --release --example mtproxy --features "mtproxy grammers-session/sqlite-storage" -p grammers-client

# запуск (mtg 16000 должен быть поднят на vps-ru)
MTPROXY_HOST=argeiphontes.ru MTPROXY_PORT=16000 \
  MTPROXY_SECRET=ee7b184b3f7c1ace06fa2efbbaa851f1a8617267656970686f6e7465732e7275 \
  MTPROXY_DC_ID=4 TELEGRAM_API_ID=66326 \
  ./target/release/examples/mtproxy
# успех: "Ping result: Pong { ... }"
```
