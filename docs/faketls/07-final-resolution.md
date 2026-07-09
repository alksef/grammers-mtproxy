# FakeTLS — Итоговое решение и победа (Round 17, 2026-07-10)

> Предыдущие документы: [README](README.md), [05-rounds-progress-and-status.md](05-rounds-progress-and-status.md), [06-rootcause-init-record.md](06-rootcause-init-record.md).
> Этот документ завершает и полностью закрывает задачу внедрения FakeTLS в `grammers`.

---

## 1. Суть проблемы (Как был найден баг)

В ходе сравнительного анализа дампов `gotd` (Go) и `alksef/grammers` (Rust) на одном тестовом прокси `argeiphontes.ru:16000` было установлено следующее:

1. **Клод ошибочно решил**, что `gotd` отправляет `transport-tag` (`eeeeeeee`/`dddddddd`) в качестве отдельного 4-байтового TLS Application record сразу после 64-байтового `init`.
2. Из-за этого в `FakeTlsStream::poll_write` (`stream.rs`) была добавлена логика перехвата `TRANSPORT_TAG` и отправка его отдельным TLS-рекордом в сеть.
3. **На самом деле:** `gotd` использует `NoHeader` кодек, который полностью вырезает отправку протокольного тега в сеть (`WriteHeader` — noop). Вся необходимая информация о типе кодека передается один раз внутри 64-байтового `init` на 56–60 байтах.
4. **Что за 4 байта видел Клод в дампе `gotd`:** Кодек `PaddedIntermediate` (в Go) отправляет длину первого пакета отдельным вызовом `w.Write(len)`, из-за чего TLS-библиотека оформляла ее в собственный TLS Application record. Клод принял это за транспортный тег.
5. **Итог бага:** Когда наш клиент отправлял в поток тег `0xdddddddd`, Telegram читал его как длину первого пакета (3.7 ГБ), зависал в ожидании данных и рвал соединение по тайм-ауту.

---

## 2. Итоговое решение

Мы полностью убрали отправку протокольного тега в поток в режиме FakeTLS:

1. **Использование `RandomizedIntermediate`**:
   В [`sender_pool.rs`](file:///home/aefimov/RustProjects/grammers-mtproxy/grammers-mtsender/src/sender_pool.rs) в FakeTLS ветке клиент использует `RandomizedIntermediate` транспорт. Он генерирует правильный хендшейк-тег `[0xdd, 0xdd, 0xdd, 0xdd]` и добавляет рандомный паддинг к сообщениям для защиты от DPI.

2. **Фильтрация тега в FakeTLS-стриме**:
   В [`stream.rs`](file:///home/aefimov/RustProjects/grammers-mtproxy/grammers-mtproto/src/tls/stream.rs) мы перехватываем тег при первом вызове `poll_write`:
   ```rust
   if !self.tag_sent && buf.len() >= 4 && buf[..4] == TRANSPORT_TAG {
       self.tag_sent = true;
       return Poll::Ready(Ok(4)); // Просто сбрасываем 4 байта тега
   }
   ```
   Мы не отправляем его в сеть, а возвращаем `Ok(4)`, как будто он записан. Весь остальной пакет (длина + payload) уходит в сеть в следующем рекорде без тега.

Это позволило синхронизировать поток байт с ожиданиями Telegram. Соединение успешно устанавливается, и `grammers` корректно получает `Pong`.

---

## 3. Скрипты и примеры для ручной проверки

Для проверки работоспособности собраны два проверочных скрипта.

### Вариант A. Проверка на Rust (`grammers`)

В репозитории есть готовый пример [`mtproxy_test.rs`](file:///home/aefimov/RustProjects/grammers-mtproxy/grammers-client/examples/mtproxy_test.rs), который выполняет проверку пинга, авторизацию по номеру телефона (с интерактивным вводом в терминале) и получение первых диалогов.

**Запуск проверки:**
```bash
cargo run --release --example mtproxy_test --features mtproxy -- \
  <api_id> <api_hash> argeiphontes.ru 16000 ee7b184b3f7c1ace06fa2efbbaa851f1a8617267656970686f6e7465732e7275 <dc_id_4_или_другой>
```

Скрипт должен вывести:
1. `Testing connection with ping...` -> `✓ Ping successful!`
2. Запросить телефон/код при необходимости авторизации.
3. Вывести первые 3 диалога пользователя.
4. Вывести `✓ All tests passed! MTProxy is working correctly.`

---

### Вариант B. Проверка на Go (`gotd`)

В качестве эталона для проверки на Go собран скрипт [`mtproxy-user-auth`](file:///home/aefimov/Projects/td/examples/mtproxy-user-auth/main.go). Он также проводит пользователя через весь путь авторизации по MTProxy.

**Запуск проверки:**
```bash
cd /home/aefimov/Projects/td/examples
APP_ID=<api_id> APP_HASH=<api_hash> TG_PHONE=<телефон> \
  PROXY_ADDR="argeiphontes.ru:16000" \
  SECRET="ee7b184b3f7c1ace06fa2efbbaa851f1a8617267656970686f6e7465732e7275" \
  go run ./mtproxy-user-auth/main.go
```

Скрипт выведет:
```
Connecting to Telegram via MTProxy...
<интерактивный ввод кода подтверждения>
SUCCESSFULLY CONNECTED AND AUTHENTICATED!
Current User: <Имя> (ID: <id>)
```
