# Server Signal Desk — REST API

Все данные и действия дашборда доступны по HTTP. Когда включён пароль,
скриптам нужен токен: **Настройки → Система → REST API → Сгенерировать**.

```
curl -H "Authorization: Bearer <токен>" http://localhost:8081/api/status
```

Поддерживается также заголовок `X-Api-Token: <токен>`. Без пароля API открыт
для всей LAN (как и дашборд) — токен не требуется.

## Чтение (GET)

| Эндпоинт | Что отдаёт |
|---|---|
| `/api/status` | все хосты + статусы + сводка + версия. `generated` — когда собран ответ, `last_cycle` — когда **завершился** последний цикл проверок (для внешнего контроля живости бери именно его: веб-сервер отвечает и при мёртвом цикле) |
| `/api/config` | публичная конфигурация (без секретов) |
| `/api/host?id=<id>&hours=24` | детали хоста: график, события, аптайм |
| `/api/events?limit=200` | журнал инцидентов по всем хостам |
| `/api/inventory` | инвентарь: MAC, вендор, имя, ОС, порты |
| `/api/network` | карта сети: живые/ушедшие устройства |
| `/api/topology` | граф топологии: `{gateway, nodes, edges}` (шлюз → /24 → устройства) |
| `/api/report?days=7` | SLA-отчёт: аптайм/инциденты/простой |
| `/api/log?lines=300&errors=1` | хвост журнала монитора (`logs\monitor.log`), опционально только ошибки |
| `/api/services` | сервисы и их статус (`ok/warn/down/unknown`, причина) |
| `/api/diag?ip=…` | что видит сам монитор: пользователь, исходный адрес до цели, TCP :80, вывод ping / route print / ipconfig / arp |
| `/api/update` | GET: версия, новые exe в «Загрузках», копии в backup\, итог последнего обновления. POST `{action: update|rollback}` — запустить |
| `/api/video` | регистраторы, камеры по каналам, кто на связи, дубли, камеры вне регистраторов |
| `/api/video/snap?nvr=IP&ch=N` | JPEG-кадр канала N (через логин монитора; только регистраторы из nvr.json) |
| `/api/nvr/check` | что монитор видит в nvr.json: путь, читается ли, заполнены ли user/password (только да/нет) |
| `/api/scan?cidr=192.168.2.0/24` | разовый обход подсети, только чтение, до /22 |
| `/api/issues` | давние проблемы («Висит» на Обзоре) с отметкой «принято» |
| `/api/silence` | что сейчас глушит алерты (мьюты, обслуживание, окна, очередь) |
| `/api/recovery` | план и прогресс «Поднять упавшие» |
| `/api/dhcp` | DHCP-надзор: конфиг, последняя проба (адреса, ответившие серверы, ошибки) |
| `/api/tg_sent?hours=168` | что бот реально отправил в Telegram: всего/ошибки, по источнику (`kind` — функция-отправитель), по дням, по часам, последние 500 текстов; `muted` — сколько проглотил фильтр (`/mute` в боте), в `failed` не входят. Хранится 90 дней |

## Действия (POST, JSON-тело)

| Эндпоинт | Тело | Действие |
|---|---|---|
| `/api/hosts/add` | `{type, name, host, port, url, expect, mac, parent, priority}` | добавить хост |
| `/api/hosts/delete` | `{id}` | удалить |
| `/api/hosts/toggle` | `{id}` | вкл/выкл |
| `/api/hosts/wake` | `{id}` | Wake-on-LAN |
| `/api/hosts/priority` | `{id, priority}` | critical/normal/watch |
| `/api/hosts/rename` | `{id, name}` | переименовать |
| `/api/hosts/mute` | `{id, seconds}` (`null` — снять) | 🔇 хоста |
| `/api/hosts/maint` | `{id или "*", seconds}` (`null` — снять) | обслуживание хоста / всей сети |
| `/api/alerts/kind` | `{kind, seconds}` (`0` — до включения, `null` — снять) | заглушить тип алерта |
| `/api/recovery/start` | `{}` | «Поднять упавшие» |
| `/api/services` | `{services: [{id, name, hosts?\|wan?\|unifi?\|group?: {cidr, min_pct}}]}` | задать сервисы |
| `/api/issues/ack` | `{key, ack}` | «принято» / вернуть |
| `/api/unifi/config` | `{ap_quiet: {from, to}}` или `{ap_quiet: null}` | тихое окно точек UniFi (не сообщать об их отключении) |
| `/api/hosts/parent` | `{id, parent}` | родитель (`""` — снять) |
| `/api/subnets/add` | `{cidr, type, port, parent}` | добавить подсеть |
| `/api/subnets/scan` | `{id}` | скан подсети → хосты |
| `/api/switches/add` | `{name, parent?}` | добавить узел-свитч (ручной, для карты) |
| `/api/switches/delete` | `{id}` | удалить свитч |
| `/api/trace/run` | `{}` | трассировать пути до хостов (фоном) → узлы-роутеры на карте |
| `/api/network/scan` | `{}` | скан сети + диф |
| `/api/inventory/scan` | `{id?}` | опросить одно/все устройства |
| `/api/schedule/add` | `{name, time, days[], hosts[], verify}` | правило WoL-расписания |
| `/api/schedule/run` | `{id}` | прогнать правило сейчас |
| `/api/settings` | см. дашборд | общие настройки |
| `/api/token/generate` | `{}` | новый API-токен (показывается один раз) |
| `/api/token/revoke` | `{}` | отозвать токен |
| `/api/login` | `{username, password}` | вход, ставит сессионную куку |
| `/api/logout` | `{}` | выйти на этом устройстве |
| `/api/auth/set` | `{username, password, password2, current}` | задать/сменить пароль; `current` обязателен, если пароль уже включён |
| `/api/auth/disable` | `{current}` | снять пароль |
| `/api/auth/logout-all` | `{}` | сбросить все сессии, включая свою |

Ответы: `{"ok": true, ...}` либо `{"ok": false, "error": "..."}` (или
`{"error": "unauthorized"}` с кодом 401).

**Про сессии.** Кука подписана HMAC и содержит время выпуска. Смена пароля
ротирует секрет подписи, а смена пароля и `logout-all` двигают `session_epoch` —
всё, что выпущено раньше, перестаёт приниматься. То есть смена пароля реально
выкидывает чужие устройства, а не только меняет строку для следующего входа.

**Троттлинг входа.** 5 неверных попыток с одного IP → `429` на 15 минут.
Счётчик в памяти, сбрасывается перезапуском монитора.

Пример — упавшие хосты одной строкой (PowerShell):

```powershell
(Invoke-RestMethod -Headers @{Authorization="Bearer <токен>"} `
  http://localhost:8081/api/status).servers | ? status -eq down | % name
```
