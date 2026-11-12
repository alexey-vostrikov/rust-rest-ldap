# Обзор: gorestldap против ApacheDS, OpenLDAP, Samba AD DC, 389 Directory Server

Документ отвечает на три вопроса: что умеет gorestldap, чего у него нет по сравнению с четырьмя
распространёнными каталогами, и какие десять возможностей имеет смысл реализовать в rrl-directory
первыми. Оценки «есть/нет» относятся к gorestldap 0.10.1 (проверено по коду и README).

Ссылки на источники — в конце файла.

## 1. Что есть у gorestldap

| Возможность | Как сделано |
|---|---|
| Операции | bind (simple), search, compare, modify — только с операцией `replace`; add/del/modifyDN нет |
| Данные | JSON из бэкенда в память; перезагрузка по таймеру, HTTP `HEAD /callback` с токеном, `SIGUSR1` |
| Бэкенды | Go-плагины `file`, `rest`, `null` (`-buildmode=plugin`, имя из конфига) |
| Структура DIT | один suffix, ровно два OU (`users`, `groups`), записи пользователей и групп, домен и OU синтетические |
| rootDSE | да (`objectClass`, `vendorVersion`, `supportedLDAPVersion`, `supportedControl`, `namingContexts`) |
| Контролы | paged results (1.2.840.113556.1.4.319), флаг `respect_control_criticality` |
| Атрибуты | `*`, `+`, `entryDN`; операционные `entryUUID`, `hasSubordinates` |
| Пароли | только `{SSHA}`, проверка в bind |
| Авторизация | бинарная: `ldapAdmin` — видит всё, остальные — только собственную запись; анонимный — ничего |
| Транспорт | LDAPS (`use_tls`, PEM-пара), без StartTLS; SASL нет |
| Прочее | нет схемы, нет репликации, нет ACL, нет метрик; `whoami` не реализован |

Это осознанно узкий сервер: «показать REST-данные как LDAP», а не каталог общего назначения.

## 2. Точки сравнения

### 2.1 Бэкенды хранения

| Система | Бэкенды |
|---|---|
| OpenLDAP | `mdb` (основной, LMDB), `ldif` (файлы, на нём же `cn=config`), `ldap` (прокси), `meta`/`relay` (агрегация нескольких серверов), `sock`, `null`, `passwd`, `dnssrv`; BDB/HDB удалены в 2.5 |
| ApacheDS | партиции: JDBM, Mavibot, LDIF, in-memory; интерсепторы поверх хранилища (аутентификация, схема, ACI, pwd policy, changelog) |
| 389 DS | LMDB/BDB-бэкенды, LDIF-файлы, chaining (передача запросов в другой сервер), retro changelog |
| Samba AD DC | `sam.ldb` (LMDB) через LDB; «бэкенда» как подключаемого слоя нет — данные AD-специфичные |
| gorestldap | `file`, `rest`, `null`; формат жёстко задан структурой (`User`, `Group`) |

### 2.2 Протокол и контролы

Что поддерживают все четыре зрелых каталога и нет в gorestldap:

- **StartTLS** (расширенная операция 1.3.6.1.4.1.1466.20037) — повышение шифрования на уже открытом
  соединении; в Samba с 4.13 простой bind без шифрования вообще отклоняется
  (`BindSimple: Transport encryption required`).
- **SASL/GSSAPI** (Kerberos), SASL EXTERNAL поверх TLS-клиентского сертификата, LDAPI-сокет с
  peercred (OpenLDAP, 389) — вход без пароля.
- **Server-side sort** (1.2.840.113556.1.4.473/474) и **VLV** (2.16.840.1.113730.3.4.9/10) — без
  них веб-панели и почтовые клиенты сортируют и листают большие списки на клиенте.
- **Assertion control** (1.3.6.1.1.12) и **permissiveModify** (1.2.840.113556.1.4.1413) — запись
  «только если значение не изменилось», защита от гонок.
- **ManageDsaIT** (2.16.840.1.113730.3.4.2) и **referral**-объекты — управление ссылками на
  подчинённые серверы.
- **Password Modify** (1.3.6.1.4.1.4203.1.11.1) и **whoami** (1.3.6.1.4.1.4203.1.11.3).
- **Content Synchronization** (RFC 4533) — syncrepl у OpenLDAP, основа мультимастер-репликации
  ApacheDS.
- **LDAP-объекты конфигурации и схемы**: `cn=config`, `cn=schema`, `subschemaSubentry` — клиент
  может прочитать схему и настройки тем же протоколом.

### 2.3 Схема и модель данных

| Система | Схема |
|---|---|
| OpenLDAP | строгая: `objectClass` → обязательные/разрешённые атрибуты, `cn=schema` публикуется, `slaptest` проверяет |
| ApacheDS | строгая, LDIF-схема, расширяемая на ходу |
| 389 DS | строгая, загрузка схемы на ходу (Schema Reload plugin) |
| Samba AD | AD-схема с расширениями (`sAMAccountName`, `userPrincipalName`, `objectSid`, `objectGUID`) |
| gorestldap | схемы нет: что бэкенд прислал, то и в записи; проверить `objectClass` или обязательные атрибуты нечем |

### 2.4 Пароли и политика

- OpenLDAP: `{SSHA}`, `{SHA256}`/`{SHA512}` (`pw-sha2`), `{ARGON2}` (`pw-argon2`), overlay `ppolicy`
  (срок жизни, история, блокировка, must-change, grace).
- ApacheDS: политика по draft-behera-ldap-password-policy (полный набор `pwd*`), Change Password
  Protocol.
- 389 DS: Account Policy plugin, Password Storage plugin (PBKDF2-SHA256/SHA512, SSHA), history.
- Samba AD: политика домена (срок, сложность, история, lockout), Kerberos как основной способ входа.
- gorestldap: только `{SSHA}`, никакой политики; старый SHA-1 с солью — ниже современных требований.

### 2.5 Авторизация

- OpenLDAP: `olcAccess` — правила «кому, к чему, какое право» с масками по DN, атрибутам, фильтрам.
- ApacheDS: адаптация X.500 basic access control + subentries (ACI-объекты в DIT).
- 389 DS: ACIs в записях, RootDN Access Control plugin, плагины как постоп-хуки.
- Samba AD: ACL в дескрипторах безопасности AD, проверка через `objectSid`/группы.
- gorestldap: `ldapAdmin` — флаг в данных; ни групп, ни правил.

### 2.6 Управление и конфигурирование

| Система | Как настраивается | Как управляется в работе |
|---|---|---|
| OpenLDAP | `slapd.conf` (устаревший) или `cn=config` (LDIF, `olc*`), правка через `ldapmodify` без перезапуска | `slapcat`/`slapadd` (офлайн), `ldapsearch`/`ldapmodify` (онлайн), `slaptest` |
| ApacheDS | LDIF-файл конфигурации, правка в Apache Directory Studio | Studio, LDIF-импорт/экспорт |
| 389 DS | `cn=config` как LDIF, `dscreate` (первичная установка) | `dsconf`/`dsctl`, LDIF, плагины с «shared configuration area», которую можно реплицировать |
| Samba AD | `smb.conf` + `sam.ldb` | `samba-tool`, `ldbsearch`/`ldbedit`/`ldbdel`, DRS-репликация |
| gorestldap | плоский YAML + флаги + переменные окружения, только при старте | HTTP `HEAD /callback`, `SIGUSR1` — и только для перезагрузки данных |

Важное наблюдение: у всех четырёх конфигурация либо сама лежит в каталоге (`cn=config`, LDIF), либо
управляется утилитой, которая пишет в каталог. У gorestldap нет ни того, ни другого: чтобы изменить
OU, suffix или бэкенд, нужен перезапуск.

### 2.7 Репликация и отказоустойчивость

- OpenLDAP: `syncrepl` (refreshOnly, refreshAndPersist), delta-syncrepl через `accesslog`, multi-
  provider, зеркальный режим, `syncprov` на провайдере.
- ApacheDS: мультимастер по RFC 4533, совместим с OpenLDAP.
- 389 DS: multi-supplier, Retro Changelog, winsync с AD, `ds-replcheck` для сверки.
- Samba AD: DRS (собственный протокол AD), Global Catalog на 3268/3269.
- gorestldap: нет; «репликация» заменена тем, что данные приходят из общего бэкенда (REST/файл),
  то есть несколько серверов могут читать один источник. Это рабочая модель для read-mostly, но
  запись (`modify`) рассчитана на один экземпляр.

### 2.8 Наблюдаемость

- OpenLDAP: `cn=monitor`, `slapd-config` статистика, auditlog/accesslog overlay (журнал в каталоге).
- 389 DS: `cn=monitor`, логи, SNMP-агент, Last Login History, Entry USN.
- ApacheDS: JMX, интерсепторы changelog.
- Samba AD: логи, `samba-tool dbcheck`, метрики через `samba-exporter`.
- gorestldap: текстовый лог и `pprof`; ни метрик, ни журнала изменений, ни health-эндпоинта
  (последнее — то, из-за чего в нашем скилле `gorestldap` появляется совет «держать под супервизором»).

## 3. Чего нет у gorestldap (сводно)

1. Схемы и валидации атрибутов.
2. `add`, `del`, `modifyDN`; в `modify` — только `replace`.
3. StartTLS, SASL, LDAPI, клиентских сертификатов.
4. Политики паролей, смены пароля клиентом, современных хешей.
5. ACL: только «админ / не админ».
6. Server-side sort и VLV.
7. Assertion control и защиты от гонок при записи.
8. Ссылок (referral) и проксирования (chaining / `ldap`-бэкенд).
9. Репликации и Content Sync.
10. Схемы-как-данных: `cn=schema`, `subschemaSubentry`, `cn=config`.
11. Нескольких suffix: один `baseDN`, два OU, жёсткая форма записи.
12. Операционных атрибутов `createTimestamp`, `modifyTimestamp`, `creatorsName`, `modifiersName`,
    `entryCSN`, `structuralObjectClass`.
13. Материализации `memberOf` из групп (у 389 это плагин MemberOf, у OpenLDAP — overlay `memberof`).
14. Уникальности атрибутов и ссылочной целостности (overlay `unique`, `refint`; плагины 389 DS).
15. Метрик, аудита и health-эндпоинта; `whoami` не реализован.
16. Content Sync и persistent search.
17. Управления во время работы: конфигурация только при старте.

## 4. Практики, которые стоит перенять

Из перечисленных систем имеет смысл взять приёмы, а не объём:

- **Конфигурация как данные** (OpenLDAP `cn=config`, 389 DS LDIF в `cn=config`). Даже без правки
  через LDAP стоит публиковать действующую конфигурацию только для чтения — это снимает половину
  вопросов «а какой у вас сейчас baseDN».
- **Конфигурация плагинов в отдельной записи, которая реплицируется** (389 DS «shared configuration
  area») — то же, что сейчас делается YAML-ом, но проверяемое на месте.
- **Постоп-хуки вместо копирования логики** (389 DS плагины, OpenLDAP overlays): `memberof`,
  `refint`, `unique` живут отдельно от бэкенда и включаются конфигом.
- **Строгий вход по умолчанию** (Samba AD: простой bind без шифрования отклоняется). Для
  rrl-directory это дешёвая настройка с большим эффектом.
- **Офлайн-инструменты** (`slapcat`/`slapadd`, `dsctl`) — при ошибке в данных нужен способ выгрузить
  каталог, не поднимая сервер.
- **LDIF как формат обмена** — экспорт и импорт, читаемый глазами и совместимый со всеми клиентами.
- **Health/ready и метрики** — неизбежный минимум для запуска в кластере.

Чего копировать не нужно: X.500-ACI ApacheDS (сложнее, чем нужно для REST-фасада), DRS Samba,
BDB-историю OpenLDAP, `sock`/`dnssrv`-бэкенды.

## 5. Первые десять кандидатов на реализацию

Порядок — по отношению «польза / стоимость» для нашей задачи (LDAP-фасад над REST-данными), а не по
объёму функций конкурентов.

| № | Возможность | Зачем | Стоимость |
|---|---|---|---|
| 1 | **StartTLS + LDAPS на rustls-rustcrypto**, опция «требовать шифрование» (как Samba) | Без TLS сервер пригоден только для лаборатории; StartTLS нужен клиентам, которые не умеют LDAPS-порт | Средняя: расширенная операция, переключение потока, самоподписанный сертификат через `rcgen` в тестах |
| 2 | **`add` / `del` / `modifyDN` + полный `modify` (add/delete/replace)** | Сейчас каталог только читается и точечно правится `replace`; без этого нельзя ни завести пользователя, ни удалить | Средняя: расширение контракта бэкендов (`EntryChange`), проверки leaf/not-leaf |
| 3 | **Схема-минимум**: реестр `objectClass` → обязательные и разрешённые атрибуты, однозначность, `cn=schema` и `subschemaSubentry` | Отсекает мусор на входе и делает сервер предсказуемым для клиентов | Средняя: декларативная таблица в коде + публикация в DIT |
| 4 | **Операционные атрибуты**: `createTimestamp`, `modifyTimestamp`, `creatorsName`, `modifiersName`, `entryCSN`, корректный `hasSubordinates` | Их спрашивают все клиенты и системы аудита; без них нельзя ни инкрементальную выгрузку, ни разбор «кто изменил» | Низкая-средняя: поля в модели, заполнение при загрузке и записи |
| 5 | **Пароли и политика**: `{SSHA256}`/`{SSHA512}`/`{ARGON2}`, Password Modify (RFC 3062), минимальная политика (длина, история, must-change) | `{SSHA}` на SHA-1 — ниже современных требований; смена пароля клиентом сейчас невозможна вообще | Средняя: argon2-крейт, расширенная операция, состояние политики |
| 6 | **ACL вместо флага `ldapAdmin`**: правила «кто / к чему / какое право» (по образцу `olcAccess`), с группами | Единственная защита сейчас — «админ или своя запись»; для нескольких приложений на одном каталоге этого мало | Средняя: разбор правил, проверка по DN/атрибуту/фильтру |
| 7 | **Server-side sort (1.2.840.113556.1.4.473) и VLV** | Веб-панели и почтовые адресные книги без них листают и сортируют на клиенте, а с пагинацией это заметно | Низкая-средняя: сортировка списка перед пагинацией, разбор контролов |
| 8 | **Наблюдаемость**: `/healthz`, `/metrics` (Prometheus), журнал изменений (запись в отдельный файл по образцу `accesslog`) | Нужно для запуска в кластере и для разбора «кто удалил пользователя» | Низкая: HTTP-эндпоинты, счётчики, формат журнала |
| 9 | **Проксирование: `ldap`-бэкенд и referral/ManageDsaIT** | Позволяет поставить rrl-directory перед AD или OpenLDAP и отдавать свои данные рядом — самый дешёвый способ закрыть пробелы «настоящего» каталога | Средняя: LDAP-клиент, правила перенаправления |
| 10 | **Уникальность и ссылочная целостность** (по образцу overlay `unique` и `refint`) | Дубли `cn` ломают bind и поиск, «висячие» `memberUid` — группы; в gorestldap ни то, ни другое не проверяется | Низкая: проверки при загрузке и записи + отчёт |

Вне первой десятки, но понадобятся: Assertion control (1.3.6.1.1.12) и permissiveModify — вместе с
`add`/`del` они закрывают гонки при записи; `memberOf`-материализация из групп; несколько suffix
(сейчас ровно один `baseDN`); SASL EXTERNAL поверх LDAPS и LDAPI; Content Sync для инкрементальной
выгрузки; экспорт/импорт LDIF; перезагрузка конфигурации без рестарта.

## 6. Куда это ложится в текущем коде

Швы под эти задачи уже есть:

- `Session::may_access` — точка расширения до ACL (пункт 6): сигнатура «кто и к какой записи»
  остаётся, меняется реализация.
- `backend::EntryChange` — расширяется до `add`/`del`/`modifyDN` без ломки `file`-бэкенда
  (пункт 2).
- `Directory` неизменяем, перезагрузка подменяет ссылку — операционные атрибуты (пункт 4) и
  уникальность (пункт 10) считаются на входе, а не в обработчиках.
- Диспетчер `ldap::handle` возвращает `Action` — StartTLS (пункт 1) встаёт как отдельная ветка
  расширенной операции с переключением потока на уровне соединения.
- `ldap::paged` уже реализует разбор/сборку контрольного значения по байтам — по тому же образцу
  делаются sort и VLV (пункт 7).
- HTTP-служба (callback) уже есть — health и метрики (пункт 8) добавляются в тот же роутер.

## Источники

- OpenLDAP Admin Guide 2.6: backends — https://www.openldap.org/doc/admin26/backends.html
- OpenLDAP Admin Guide 2.6: overlays — https://www.openldap.org/doc/admin26/overlays.html
- OpenLDAP Admin Guide 2.6: replication — https://www.openldap.org/doc/admin26/replication.html
- slapd-pw-argon2(5) — https://manpages.debian.org/unstable/slapd-contrib/slapd-pw-argon2.5.en.html
- ApacheDS (возможности, сертификация Open Group, Kerberos, RFC 4533, ppolicy, LDIF-конфиг) —
  https://directory.apache.org/apacheds/
- ApacheDS PasswordPolicy (draft-behera) —
  https://apache.googlesource.com/directory-site/+/refs/heads/master/source/apacheds/internal-design-guide/ppolicy.md
- 389 DS: MemberOf plugin — https://www.port389.org/docs/389ds/design/memberof-plugin-configuration.html
- 389 DS: Referential Integrity plugin — https://www.port389.org/docs/389ds/design/ri-plugin-configuration.html
- SambaWiki FAQ (strong auth по умолчанию, ограничения AD DC) — https://wiki.samba.org/index.php/FAQ
