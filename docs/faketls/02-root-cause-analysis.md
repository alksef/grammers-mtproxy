# Почему FakeTLS не заработал — точный анализ

Дата анализа: 2026-07-09. Источники: история git репо `D:/RustProjects/grammers`,
логи прошлых прогонов (`mtproxy_test.log`, `log.log`, `server.log`), заметка `text.txt`,
эталон gotd/td.

## 1. Симптомы

Прошлая реализация (`commit f534d9a`, модуль `grammers-mtproto/src/tls/`):
- FakeTLS handshake **проходит полностью**: ClientHello отправлен → ServerHello+CCS+noise
  получены → `ServerHello HMAC verified OK`.
- Затем отправляется 64-байтный obfuscated-init (`FakeTlsWriter: 64-byte obfuscated handshake sent (TLS-framed)`).
- Дальше **соединение рвётся**: `EOF while reading TLS record header`.

В `mtproxy_test.log` иногда первый MTProto-запрос (`req_pq_multi`) успевал дойти и получить
`ResPQ`, но второй (`req_DH_params`) — никогда.

## 2. Главная улика — лог самого сервера MTProxy (`server.log`)

`server.log` — это лог mtg-сервера, не клиента. Ключевые строки:

```
{"dc":2, "message":"client -> telegram has been finished (written 0 bytes):
   incorrect tls version [239 61 255 73]"}
{"dc":2, "message":"client -> telegram has been finished (written 0 bytes):
   incorrect tls version [168 122 253 158]"}
```

Расшифровка:
- `written 0 bytes` — сервер **ничего не релеил** в Telegram, т.е. обрубил поток на стороне клиента.
- `incorrect tls version [239 61 255 73]` = байты `[0xEF 0x3D 0xFF 0x49]`. Меняются каждую попытку
  (рандом init'а) — значит сервер читает **первый байт post-handshake данных как ContentType
  TLS-записи** и видит мусор (`0xEF`, `0xA8`, …), а не `0x17` (Application) или `0x14` (CCS).
- Сервер рвёт соединение **сразу после handshake** — т.е. на **первом** post-handshake пакете.

То, что `ResPQ` иногда доходил — **гонка**: mtg релеит байты до того, как его проверщик
TLS-framing отработает и обрубит поток. Это нестабильность на стороне сервера, не клиента.

## 3. Корневая причина: «raw mode» после handshake

Последняя итерация (`f534d9a`) ввела режим, **противоречащий эталону gotd/td**:

- `grammers-mtproto/src/tls/stream.rs:75`:
  `// Switch reader to raw mode: server sends raw AES-CTR encrypted bytes`
- `grammers-mtproto/src/tls/reader.rs:140`:
  `log::info!("FakeTlsReader: switched to raw mode (no TLS framing)")`

Реализация: FakeTLS framing использовался **только на handshake** (ClientHello, ServerHello,
и один раз на 64-байтный obfs-init). Сразу после — reader/writer переключались в «raw mode»:
просто сырые AES-CTR байты поверх TCP, **без** 5-байтных TLS-record заголовков.

Это **в корне неверно**. gotd/td (`obfuscator.go`) держит FakeTLS-framing **всю жизнь соединения**:
каждый post-handshake пакет обязан приходить обёрнутым в TLS-Application-record.

→ mtg после handshake ждёт очередную TLS-запись, видит первый байт потока (`0xEF`…) как
ContentType, не опознаёт → `incorrect tls version` → обрыв.

**Причина, по которой это сделали:** вероятно, путаница с обычным MTProxy-dd, где после
единственного 64-байтного obfuscated-init действительно идёт «сырой» AES-CTR поток без
дополнительного framing'а. FakeTLS — **другой** режим: framing тут постоянный.

## 4. Опровержение гипотезы из `text.txt`

Заметка `D:/RustProjects/grammers/text.txt` (финальная гипотеза прошлой попытки) гласит:
в `FakeTlsWriter::poll_write` теряется `req_DH_params`, потому что после отправки handshake'а
данные из `buf` не сохраняются при `Poll::Pending` → второй запрос исчезает.

**Это неверно.** Проверка реального кода `writer.rs @ f534d9a`:
- writer имеет явный конечный автомат `WriterState::{Idle, WritingHandshake, WritingRecord, Poisoned}`;
- данные приложения кладутся в `WritingRecord { buffer: BytesMut, offset }` и **досылаются**
  через несколько `poll_write` — буфер **не теряется**;
- код корректен по обычным меркам `tokio::io::AsyncWrite`.

Поэтому запланированный в `text.txt` «финальный рефакторинг конечного автомата writer'а»
проблему **не решил бы**. Writer здесь ни при чём — соединение рвёт **сервер** на framing'е.

Ошибка прошлого расследования: симптом «первый пакет доходит, второй нет» списали на writer,
хотя реальная причина — асинхронный обрыв сервером из-за raw-mode (см. §2, гонка mtg).

## 5. Что нужно исправить (одним предложением)

FakeTLS-framing **не должен сниматься** после handshake. Реализовать честную слоистую
модель gotd/td: `Obfuscated2` пишет **внутрь** `FakeTLS`, `FakeTLS` обрамляет **каждую**
запись в TLS-record на всём протяжении жизни соединения; на чтение — симметрично,
stripping TLS-record заголовков навсегда. Никакого raw-mode.

Детали портирования — [04-implementation-plan.md](04-implementation-plan.md).

## 6. Приложение: как воспроизвести улики

```bash
cd D:/RustProjects/grammers
git show f534d9a:grammers-mtproto/src/tls/stream.rs    # raw-mode switch (§3)
git show f534d9a:grammers-mtproto/src/tls/writer.rs     # корректная буферизация (§4)
git show f534d9a:grammers-mtproto/src/tls/reader.rs     # "switched to raw mode"
# Логи прошлых прогонов:
cat mtproxy_test.log   # клиентский лог: handshake OK → EOF
cat server.log         # серверный лог: incorrect tls version
cat text.txt           # неверная гипотеза прошлого расследования
```
