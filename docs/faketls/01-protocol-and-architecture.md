# FakeTLS — протокол и эталонная архитектура

Источник истины: **gotd/td** (`D:/Projects/td`, ветка `main`, `mtproxy/faketls/` + `mtproxy/obfuscated2/` + `mtproxy/obfuscator/obfuscator.go`).
TDLib (C++, `tdesktop`) и Telethon описывают ту же модель.

## 1. Режимы MTProxy определяются по длине секрета

gotd парсит секрет **по длине**, а не по префиксу (`mtproxy/secret.go`):

| Длина | Тип | Структура | Cloak-домен |
|-------|-----|-----------|-------------|
| 16 | Simple | `secret[16]` | нет |
| 17 | Secured (dd) | `tag[1] + secret[16]` | нет |
| >17 | TLS (FakeTLS) | `tag[1] + secret[16] + domain_hex[var]` | да |

- `tag` — просто первый байт (`0xdd` или `0xee`); **не флаг режима**, режим задаёт длина.
- `domain_hex` — ASCII-домен, hex-закодированный, дописан после 16-байтного ключа.
  Для `argeiphontes.ru` это `617267656970686f6e7465732e7275`.

Пример парсинга ключа `ee7b184b3f7c1ace...617267656970686f6e7465732e7275`:
```
ee                                  — tag (0xEE)
7b184b3f7c1ace06fa2efbbaa851f1a8    — key (16 байт) для HMAC и AES-derivation
617267656970686f6e7465732e7275      — "argeiphontes.ru" (hex) — SNI / cloak host
```

> ⚠️ Важно: прошлая реализация alksef/grammers завела `enum SecretMode { Simple, DDSecure, EEPrefix }`
> и различала режимы по строковому префиксу `"dd"`/`"ee"`. Это **не совпадает** с эталоном
> и надо переделать на определение **по длине** (`<=16` Simple, `==17` Secured, `>17` TLS).

## 2. Стек протоколов — три слоя, framing НЕ снимается

Эталон gotd (`mtproxy/obfuscator/obfuscator.go`):

```go
type tls struct {
    ftls  *faketls.FakeTLS      // слой 3 (верхний): TLS-framing
    obfs2 *obfuscated2.Obfuscated2 // слой 2: AES-CTR
}
func newTLS(rand, conn) tls {
    ftls := faketls.NewFakeTLS(rand, conn)        // faketls оборачивает сокет
    obfs2 := obfuscated2.NewObfuscated2(rand, ftls) // obfs2 пишет В faketls
    return tls{ftls, obfs2}
}
func (t tls) Write(p []byte) (int, error) { return t.obfs2.Write(p) } // obfs2 → faketls → socket
```

То есть направление записи:
```
MTProto payload
  → Obfuscated2.Write  (AES-CTR шифрует)        ┐
  → FakeTLS.Write       (оборачивает в TLS-rec)  ├ framing живёт ЗДЕСЬ, навсегда
  → socket                                       ┘
```

**Критически:** слой FakeTLS framing'ует **каждый** кусок данных, включая 64-байтный
obfuscated2-init. После handshake framing **не отключается**. Это ключевое отличие
от обычного MTProxy-dd, где framing'а нет вовсе.

## 3. Полный handshake (gotd/td)

```
Клиент                                       MTProxy (mtg)
  │
  │ 1. ClientHello (517 байт, TLS-record 0x16) ────────▶
  │    Random = HMAC-SHA256(secret, ClientHello) ^ unix_ts
  │    Extensions: SNI=cloak_domain, key share, ALPN, GREASE …
  │                                            (mtg проверяет Random)
  │ 2. ◀──────── 3 TLS-records:
  │       - Handshake (ServerHello)
  │       - ChangeCipherSpec (0x14, байт 0x01)
  │       - Application (сертификат-шум)
  │
  │ 3. Verify: ServerRandom ?= HMAC-SHA256(secret, ClientRandom ‖ ServerHello_zeros)
  │
  │ 4. obfuscated2-init (64 байта) ──── в TLS Application-record (0x17) ────▶
  │    init = 56 random + protocol_tag[4] + dc[2] + padding[2]
  │    последние 8 байт init зашифрованы AES-CTR (ключи из init+secret)
  │    весь init обёрнут в 5-байтный TLS-rec-header
  │
  │ 5. MTProto трафик ──── каждый пакет в TLS Application-record (0x17) ────▶
  │    write: obfs2(AES-CTR) → faketls(TLS-rec) → socket
  │    read:  socket → faketls(strip TLS-rec) → obfs2(AES-CTR)
```

## 4. Quirk первого пакета (после handshake)

`mtproxy/faketls/faketls.go:62-75` — **первый** post-handshake пакет MTProxy-сервер
ждёт обёрнутым в **ChangeCipherSpec**-запись (`0x14`, payload `0x01`), а не сразу в
Application:

```go
if !o.firstPacket {
    writeRecord(o.conn, record{Type: RecordTypeChangeCipherSpec, Data: []byte("\x01")})
    o.firstPacket = true
}
writeRecord(o.conn, record{Type: RecordTypeApplication, Data: b})
```
Ссылка на TDLib: `td/mtproto/TcpTransport.cpp#L266`.

> Примечание: не все mtg-билды требуют CCS-quirk, но gotd его шлёт всегда — безопасно.
> При портировании воспроизвести дословно.

## 5. Крипто-сводка

| Назначение | Алгоритм | Ключ | Откуда |
|------------|----------|------|--------|
| ClientRandom | HMAC-SHA256 | `secret[16]` | от ClientHello целиком, XOR ts в последн. 4 байта |
| ServerRandom | HMAC-SHA256 | `secret[16]` | `HMAC(secret, ClientRandom ‖ ServerHello_zeros)` |
| Obfs2 encrypt/decrypt keys | SHA256 | `init[8:40]`+secret / rev | `SHA256(init[8:40] ‖ secret)`, decrypt — из reversed init |
| Obfs2 IV (encrypt/decrypt) | — | `init[40:56]` / rev | 16 байт |
| Шифр данных | AES-256-CTR | 32 байта | производные выше |

TLS-record: `ContentType(1) ‖ Version(2, 0x03 0x03) ‖ Length(2, big-endian) ‖ Data`.
Типы: `0x14`=CCS, `0x15`=Alert, `0x16`=Handshake, `0x17`=Application, `0x18`=Heartbeat.
Длина record'a ≤ 16384+24.

## 6. Что уже было реализовано в alksef/grammers (история, удалено из master)

В коммите `f534d9a` модуль `grammers-mtproto/src/tls/` содержал:
`client_hello.rs`, `server_hello.rs`, `record.rs`, `handshake.rs`, `obfuscator.rs`,
`reader.rs`, `writer.rs`, `stream.rs`, `mod.rs`.

Эти файлы — **хорошая основа**: ClientHello с GREASE и SNI, проверка ServerHello по HMAC,
obfuscator с AES-CTR. Что в них **неправильно** — см. [02-root-cause-analysis.md](02-root-cause-analysis.md).
Восстановить: `git show f534d9a:grammers-mtproto/src/tls/<file>.rs`.
