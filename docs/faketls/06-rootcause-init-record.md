# FakeTLS — КОРНЕВАЯ ПРИЧИНА найдена (Round 16, 2026-07-10)

> Финал расследования. Предыдущие раунды: [05-rounds-progress-and-status.md](05-rounds-progress-and-status.md).
> Эта заметка **заменяет** выводы Round 12/14 (они были неверны по направлению) и закрывает Round 15.

## TL;DR

**alksef клеит obfs2-init (64 байта) + первый MTProto-пакет в ОДИН TLS-record.
Сервер (mtg/Telegram) ждёт obfs2-init ОТДЕЛЬНЫМ TLS-record.**

Из-за этого сервер разбирает первый record как init (64B), выводит AES-ключи,
а оставшиеся 48 байт в том же record оказываются рассинхронизированы → расшифровка
даёт мусор → Telegram молчит → mtg пишет `written 0 bytes` → alksef виснет на
`generating new authorization key`.

Доказано побайтовым сравнением wire-дампов **alksef vs gotd-эталон** через ОДИН
mtg-сервер `argeiphontes.ru:16000`.

## Как доказано (4 дампа, один mtg `16000`)

Поднят mtg `argeiphontes.ru:16000` (FakeTLS, secret `ee7b184b...argeiphontes.ru`,
upstream `socks5://127.0.0.1:33072` → s-ui → CZ-нода → Telegram). tcpdump на `any:16000`.

| Клиент | dc | wire-структура post-CCS | ответ Telegram |
|--------|----|--------------------------|----------------|
| **gotd** ✅ | 2 | `17 03 03 0040 <init64>` ← отдельный record, затем `17 03 03 0004 <4B>`, затем `17 03 03 002b <MTProto43>` | **1762 bytes** (`nearestDc`, country=CZ) |
| **tdesktop** ✅ | 4 | CCS+первый record в одном TCP-сегменте (но record-boundaries корректны) | **1971 bytes** |
| **alksef** ❌ | 4 | `17 03 03 0070 <init64+MTProto48>` ← **ОДИН record** (init glued к payload) | **0 bytes** |

gotd-эталон (`gotd/td`, `examples/mtproxy-connect`) через тот же mtg `16000` — **работает**
(получил `help.getNearestDC`, Telegram ответил 1762 байта). alksef через тот же mtg — виснет.

> Это окончательно опровергает **Round 15** (гипотеза «socks5 режет Telegram по IP»).
> Upstream жив: gotd и tdesktop через него получают ответы. Баг — в alksef.

## Побайтовое расхождение

**gotd (рабочий)** — init и MTProto в РАЗНЫХ TLS Application-records:
```
14 03 03 00 01 01                  ← CCS record (6B)
17 03 03 00 40 <64 байта>          ← App record #1 = ТОЛЬКО obfs2-init (len=0x40=64)
17 03 03 00 04 <4 байта>           ← App record #2 = 4B (gotd internal)
17 03 03 00 2b <43 байта>          ← App record #3 = MTProto req_pq_multi (len=0x2b=43)
```

**alksef (сломанный)** — init и MTProto в ОДНОМ record:
```
14 03 03 00 01 01                  ← CCS record (6B)
17 03 03 00 70 <112 байт>          ← App record = init(64) + MTProto(48) СКЛЕЕНЫ (len=0x70=112)
```

alksef-plaintext первого record (дамп из диагностики):
```
init(64)   = 98651ba3...25a852b6
MTProto(48)= eeeeeeee 28000000  <- Intermediate-tag (0xee) + len=0x28=40
             00000000 00000000  <- auth_key_id=0 (plain)
             00000000 00000000  <- msg_id (grammers так шлёт; Simple работает, значит ОК)
             14000000            <- msg_size=20
             f18e7ebe            <- req_pq_multi constructor (0xbe7e8ef1 LE) ✅
             091cad57...3d878921 <- nonce (16B)
```

**Plaintext сам по себе валиден** (Intermediate-framed `req_pq_multi`, constructor корректен).
Проблема не в содержимом — а в том, что init и payload **в одном record**.

## Почему это ломает соединение

Сервер (mtg/Telegram) после FakeTLS-handshake читает первый Application-record и
интерпретирует его как **obfs2-init** (ровно 64 байта: `magic|key|iv|conn_type|dc`).
Из init выводятся AES-256-CTR send/recv ключи. **Все последующие** records сервер
читает как obfs2-зашифрованный MTProto-поток.

Когда alksef кладёт 112 байт в один record:
1. Сервер берёт первые 64B как init → keys выведены.
2. Оставшиеся 48B того же record сервер трактует как начало obfs2-MTProto.
3. Но эти 48B — **не отдельный record**, сервер уже «съел» границу →
   дешифровка рассинхронизирована (или сервер вообще не ожидает данных в record-init).
4. → мусор → Telegram молчит → mtg `telegram -> client has been finished` (0 bytes).

## Код-виновник

`grammers-mtproto/src/tls/stream.rs`, метод `poll_write` (FakeTlsStream):

```rust
let mut payload = prefix;                          // prefix = obfs2-init (64B)
payload.extend_from_slice(&encrypted_chunk);       // + MTProto (зашифрованный) — СКЛЕЙКА
Pin::new(&mut self.framing).poll_write(cx, &payload)  // framing оборачивает ВСЁ в один 0x17-record
```

`first_prefix` (init) prepended к первому data-chunk и пишется через framing как **один** record.

## Как делает gotd (эталон)

Слоистая модель (`mtproxy/obfuscator/obfuscator.go`):

```
obfs2.Handshake()  →  conn.Write(init64)   →  ftls.Write(64B)  →  TLS-record #1 (init)
obfs2.Write(data)  →  conn.Write(enc)      →  ftls.Write(data) →  TLS-record #2..N (MTProto)
```

Каждый `Write` на уровень выше = **отдельный** TLS-record уровнем ниже.
init шлётся `obfs2.Handshake` отдельным `conn.Write` → отдельный record.
Данные шлются `obfs2.Write` → каждый write отдельный record.

`ftls.Write` (faketls.go) на первый вызов additionally prepends CCS-record (отдельным writeRecord),
но CCS и data — разные records (CCS = `0x14`, data = `0x17`). Это подтверждает:
**CCS-split по TCP-сегментам — норма, не баг** (gotd тоже разделяет).

## Round 12/14 были НЕВЕРНЫ по направлению

| Round | Что пробовали | Итог |
|-------|---------------|------|
| 12 | init как **prefix первого record** (встроить init в начало первого data-record) | не помогло |
| 14 (Вариант C) | `first_prefix` + CCS на первом write | не помогло |

Оба раунда двигались в направлении «склеить init с первым data-record».
**Правильно — наоборот:** init отдельным record, data-record'ы отдельно.

Фактически Round 12/14 реализовали ровно то, что и было багом (glue), просто
вариантами. Корректная модель — gotd'овская: init своим record.

## Также опровергнуто в этом расследовании

- **Round 15** (socks5 режет Telegram-IP) — gotd/tdesktop через тот же upstream отвечают.
- **CCS-split** (Round 13/dump-finding) — gotd тоже разделяет CCS по сегментам, работает.
- **anti-replay** — отключён в mtg, alksef всё равно виснет.
- **payload plaintext** — валиден (Intermediate + req_pq_multi + nonce).
- **AES-CTR crypto** — байт-идентичен gotd (Round 8/10).

## Фикс

В `stream.rs` `poll_write`: писать `first_prefix` (init) **отдельным framing-record**
(`self.framing.poll_write(&prefix)`), затем data — отдельным record (без extend/glue).
Структура на проводе должна стать:
```
CCS record
17 03 03 0040 <init64>        ← отдельный record (один раз, при первом write)
17 03 03 <len>  <MTProto>     ← data-record (каждый poll_write данных = свой record)
```

> **ЧАСТИЧНЫЙ ФИКС (2026-07-10, применён).** init-record сделан отдельным — структура
> на проводе стала `17..0040 <init64>` + `17..0030 <MTProto48>`. НО Telegram всё ещё
> молчит. Вскрылась **вторая половина бага** — см. ниже «Часть 2: transport-tag glue».

## Дампы

- `/tmp/cap1_tdesktop.pcap` — tdesktop (рабочий эталон, dc=4)
- `/tmp/cap2_alksef.pcap`, `/tmp/cap3_alksef.pcap` — alksef (виснет)
- `/tmp/cap4_gotd.pcap` — gotd (рабочий эталон, dc=2)

На vps-ru: те же имена в `/tmp/`. Лог mtg: `/tmp/mtg_16000.log`.

---

## Часть 2: transport-tag glue (вторая половина бага, найдена 2026-07-10)

После применения фикса из «Фикс» выше (init отдельным record) alksef **всё ещё виснет**.
Дамп №5 (`docs/faketls/dumps/cap5_alksef.pcap`) показал структуру post-CCS:

```
17 03 03 0040 <init64>        ← init record (стало корректно, как gotd)
17 03 03 0030 <48 байт>       ← data record = eeeeeeee(4) + len(4) + req_pq(40) СКЛЕЕНЫ
```

Сравнение с gotd (`cap4_gotd.pcap`) — gotd шлёт **три** отдельных record post-CCS:
```
17 03 03 0040 <init64>        ← obfs2.Handshake (init)
17 03 03 0004 <eeeeeeee>      ← transport protocol.Handshake WriteHeader (Intermediate tag) ОТДЕЛЬНЫЙ record
17 03 03 002b <MTProto43>     ← первое MTProto сообщение
```

### Корневая причина части 2

alksef `Intermediate::pack` (`transport/intermediate.rs:45`) первый pack упаковывает
`[eeeeeeee][len][MTProto]` в **один** buffer. `MtProxy::pack` (`transport/mtproxy.rs:321`)
prepend'ит init(64) → на net-уровень уходит `[init64][eeeeeeee][len][MTProto]`.

В FakeTLS-stream после фикса это превращается в:
- init-record (64)
- **один** data-record = `eeeeeeee` + len + MTProto (склеено)

gotd же (через `proto/codec/intermediate.go` `WriteHeader`) шлёт transport-tag
**отдельным** `io.Writer.Write` → отдельный TLS-record. Сервер после init-record
читает следующий record как **transport-tag** (`eeeeeeee`), а у alksef там tag+MTProto
вместе → рассинхрон → мусор → Telegram молчит.

### Почему Simple-режим работал

Simple/DD MTProxy — raw AES-CTR поток без TLS-record framing. Там init один, дальше
байты льются сплошным потоком; transport-tag в начале потока читается сервером inline.
FakeTLS же требует **record-границ** на каждый логический write (init / tag / MTProto).

### Фикс части 2 (требует архитектурной правки)

transport-tag (`eeeeeeee`) должен уходить **отдельным TLS-record** в FakeTLS-режиме.
Варианты:
1. В `FakeTlsStream` перехватить первый data-write: если ещё не отправлен transport-tag —
   послать `inner.init_tag()` отдельным framing-record, потом data.
2. На net-уровне (`net/tcp.rs`) перед первым MTProto-write слать transport-tag
   отдельным `stream.write(tag)`.
3. Сделать `Intermediate::pack` не добавляющим TAG в FakeTLS-режиме, а слать tag
   отдельно на уровне transport-Handshake (как gotd `protocol.Handshake`).

Это правка выходит за рамки одной функции (transport ↔ stream ↔ net coupling).
Передаётся в opencode+deepseek с данной спецификацией.

### Состояние

- Фикс Части 1 (init отдельным record) **применён** в `stream.rs`, тесты зелёные (16+53).
- Фикс Части 2 (transport-tag отдельным record) — **применён** (deepseek, `stream.rs`).
  Wire стал `init(64) + tag(4) + MTProto` — три отдельных record'а, как у gotd.
  **НО Telegram всё ещё молчит.** Вскрылась **Часть 3** — см. ниже.

---

## Часть 3: transport-mismatch — alksef шлёт Intermediate (`eeeeeeee`), gotd для FakeTLS шлёт PaddedIntermediate (`dddddddd`)

После фикса Части 2 wire-структура alksef стала 1:1 с gotd (init/tag/MTProto отдельными
record'ами). Дамп №6 (`docs/faketls/dumps/cap6_alksef.pcap`):
```
17 03 03 0040 <init64>     ← init
17 03 03 0004 <4B>         ← transport-tag
17 03 03 002c <MTProto44>  ← данные
```
Plaintext MTProto валиден (`[len40][authkey0][msgid0][size20][req_pq_multi][nonce]`).
Но ответа нет.

### Корень Части 3

gotd для FakeTLS-секрета использует **PaddedIntermediate**, а не Intermediate
(`telegram/dcs/mtproxy.go:118-135`):
```go
var cdc codec.Codec = codec.PaddedIntermediate{}      // НЕ Intermediate
tag := codec.PaddedIntermediateClientStart             // = 0xdddddddd, НЕ 0xeeeeeeee
protocol: transport.NewProtocol(func() transport.Codec {
    return codec.NoHeader{Codec: cdc}                  // NoHeader
})
```
- `PaddedIntermediateClientStart = [4]byte{0xdd,0xdd,0xdd,0xdd}` (`proto/codec/padded_intermediate.go:15`).
- `IntermediateClientStart = [4]byte{0xee,0xee,0xee,0xee}`.

alksef (`sender_pool.rs:419`) для FakeTLS использует `transport::Intermediate` →
шлёт tag `eeeeeeee`. Сервер для FakeTLS-режима ожидает transport-tag `dddddddd`
(PaddedIntermediate). Transport-mismatch → сервер трактует поток по правилам
другого кодека → мусор → Telegram молчит.

Также объясняет разницу размеров data-record: alksef 44B (Intermediate), gotd 43B
(PaddedIntermediate — другая логика len/padding).

### Фикс Части 3 (требует правки)

Для FakeTLS-режима использовать **PaddedIntermediate** transport и tag `dddddddd`:
1. В `sender_pool.rs` FakeTLS-ветка: вместо `transport::Intermediate` —
   `transport::PaddedIntermediate` (или `RandomizedIntermediate`, см. ниже).
2. В `FakeTlsStream` transport-tag = `dddddddd` (`TRANSPORT_TAG`), не `eeeeeeee`.
   (Сейчас deepseek зашил `TRANSPORT_TAG_INTERMEDIATE = eeeeeeee`.)

Примечание: alksef уже имеет `RandomizedIntermediate` (для DD-Secure). gotd юзает
именно PaddedIntermediate. Нужно проверить эквивалентность Randomized vs Padded
и выбрать matching gotd. Скорее всего для FakeTLS = PaddedIntermediate с tag `dddddddd`.

Это план для следующей итерации deepseek — см. `docs/deepseek/`.
