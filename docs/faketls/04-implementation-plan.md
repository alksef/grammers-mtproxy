# План: добавить FakeTLS в grammers (на текущем master)

Дата: 2026-07-09. Контекст: [README.md](README.md), [01-protocol-and-architecture.md](01-protocol-and-architecture.md),
[02-root-cause-analysis.md](02-root-cause-analysis.md), [03-references.md](03-references.md).

Принцип: **порт из gotd/td (Go)**, переиспользуяcrypto/ClientHello/ServerHello из
истории alksef/grammers (коммит `f534d9a`, модуль `tls/`), но **исправив слоистость**
(главная ошибка прошлого — raw-mode).

> Согласно `CLAUDE.md` репо `app-tts-v2`: Claude **не пишет имплементацию** — пишет план,
> код пишет DeepSeek. Этот файл — план для DeepSeek. Финальная задача для итераций —
> в `docs/deepseek/tasks/` репо `app-tts-v2` (или эквивалент здесь).

## 0. Текущая интеграционная точка (master `8519c06`)

- `grammers-mtsender/src/net/tcp.rs`:
  - `enum NetStream { ..., MtProxy(TcpStream), ... }`
  - `enum ServerAddr { ..., MtProxy { host, port, secret, dc_id }, ... }`
  - `async fn connect_mtproxy_stream(...)` → `NetStream::MtProxy(TcpStream)` (raw TCP).
- `grammers-mtproto/src/transport/mod.rs`: `pub use mtproxy::{MtProxy, SecretMode, with_auto_transport}`.
- `grammers-mtproto/src/transport/mtproxy.rs`: `enum SecretMode { Simple, DDSecure, EEPrefix }`
  (определяет режим **по строковому префиксу** — неверно, см. шаг 1).

## 1. Переопределить режим по длине секрета (не по префиксу)

Порт `mtproxy/secret.go` из gotd. Заменить `SecretMode`-логику:
```
len == 16         → Simple
len == 17         → Secured (dd), secret[0]==0xDD
len  > 17         → TLS (FakeTLS): secret[1:17]=key, secret[17:]=hex(domain)
```
Разбор hostname: hex-decode `secret[17:]` → cloak domain (SNI). Для тест-ключа
`ee7b184b3f...617267656970686f6e7465732e7275` → `argeiphontes.ru`.

## 2. Восстановить модуль `grammers-mtproto/src/tls/` из истории + исправить

Из `git show f534d9a:grammers-mtproto/src/tls/` вернуть:
`record.rs`, `client_hello.rs`, `server_hello.rs`, `handshake.rs`, `obfuscator.rs`, `mod.rs`.
Эти части (crypto, layout, HMAC-verify) **корректны** — оставить как есть.

**Переписать `stream.rs` / `reader.rs` / `writer.rs`** по модели gotd `obfuscator.go`:

### 2.1. Слоистая модель (главное исправление)

```
struct FakeTlsStream<S> {           // = gotd `tls` struct
    ftls: FakeTLS<S>,               // слой framing'а (читает/пишет TLS-records ВСЕГДА)
    obfs2: Obfuscated2<FakeTLS<S>>, // пишет В ftls
}
impl AsyncWrite for FakeTlsStream { fn poll_write -> self.obfs2.poll_write }
impl AsyncRead  for FakeTlsStream { fn poll_read  -> self.obfs2.poll_read  }
```

- `FakeTLS<S>` (framing): `poll_write` оборачивает `buf` в TLS-Application-record
  (`0x17 0x03 0x03 ‖ len_be ‖ buf`) и пишет в `S`. `poll_read` — читает 5-байтный заголовок,
  проверяет ContentType, отдаёт payload.
- `Obfuscated2<C>`: `poll_write` шифрует `buf` AES-CTR, пишет в `C`. `poll_read` — читает из `C`,
  расшифровывает AES-CTR.
- **Удалить «raw mode»** полностью. Никакого `switched to raw mode`. Framing живёт на обоих
  направлениях всю жизнь соединения.

### 2.2. Handshake FakeTLS (порядок)

1. Сгенерировать + отправить ClientHello (TLS-record `0x16`), вычислив ClientRandom.
2. Прочитать 3 records: ServerHello (`0x16`) + CCS (`0x14`) + Application-шум (`0x17`).
3. Проверить ServerRandom = `HMAC-SHA256(secret, ClientRandom ‖ ServerHello_zeros)`.
4. Сгенерировать 64-байтный obfuscated2-init, зашифровать хвост (`[56:64]`) AES-CTR,
   **отправить как TLS-Application-record** (не raw!).

### 2.3. Quirk первого пакета (gotd `faketls.go:62-75`)

Перед самым первым MTProto-пакетом послать CCS-record (`0x14`, payload `0x01`).
Реализовать флаг `first_packet` в `FakeTLS`.

### 2.4. Проверить CCS на чтении

На приёме CCS (`0x14`) игнорировать (gotd `faketls.go:102`), Application (`0x17`) — отдавать.

## 3. Подключить в net-слой

В `connect_mtproxy_stream` (или `sender_pool`):
- если секрет распарсен как TLS-режим → собрать `FakeTlsStream::new(tcp, secret, dc, domain).await`,
  выполняющий handshake, и вернуть как новый вариант `NetStream::MtProxyFakeTls(FakeTlsStream<TcpStream>)`.
- транспорт поверх — обычный `Intermediate` (gotd использует intermediate для ee-faketls;
  alksef-история тоже пришла к `use plain Intermediate transport for EE-FakeTLS`).

Псевдокод выбора:
```rust
match parse_secret(secret) {
    Simple | Secured => NetStream::MtProxy(tcp) + MtProxy<RandomizedIntermediate/Intermediate>,
    TLS(domain)      => {
        let s = FakeTlsStream::handshake(tcp, &key16, dc, &domain).await?;
        NetStream::MtProxyFakeTls(s)   // + MtProxy<Intermediate> поверх, obfs2 уже внутри
    }
}
```

## 4. Зависимости

Уже есть в `grammers-mtproto` (история): `hmac`, `sha2`, `aes`, `cipher` (AES-CTR).
Проверить `grammers-mtproto/Cargo.toml` после восстановления `tls/mod.rs`.

## 5. Тестирование

- Юнит: парсинг секрета по длине; вывод ключей obfs2; ClientRandom HMAC; ServerRandom verify.
- Интеграция против `argeiphontes.ru:13371` (`ee...7275`).
  Критерий успеха: доходит `req_pq_multi` → `ResPQ` → `req_DH_params` → `server_DH_params_ok`
  (т.е. генерация auth-key проходит дальше 1-го шага).
- При провале — смотреть **серверный** лог mtg (`incorrect tls version` означает, framing
  всё ещё где-то снимается).
- Smoke: проверить, что Simple-ключ `argeiphontes.ru:13370` не сломался (регрессия).

## 6. Чеклист определения «по ключу, без явного типа» (требование пользователя)

- [ ] Никакого поля «тип прокси» в API/настройках.
- [ ] `connect_mtproxy_stream` сам определяет Simple/Secured/TLS по длине секрета.
- [ ] Рабочий ключ `13370` (Simple) продолжает работать.
- [ ] Целевой ключ `13371` (FakeTLS) проходит handshake и обмен auth-key.

## 7. Опасные места (вынесено из анализа)

1. **Не вводить raw-mode.** Это убило прошлую попытку (§3 root-cause).
2. **CCS-quirk перед первым пакетом** — обязателен для ряда mtg-билдов.
3. **64-байтный obfs2-init шлётся ВНУТРИ TLS-record**, не raw.
4. **decrypt-ключи из reversed init** (`init[55:7:-1]`), не из прямого.
5. **Длина TLS-record — big-endian**, а `dc_id` в init — little-endian. Не перепутать.
