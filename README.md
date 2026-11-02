# rust-rest-ldap

LDAP-сервер на Rust: каталог в памяти, данные из бэкенда, запись через протокол.

Порт [gorestldap](https://github.com/ps78674/gorestldap) 0.10.1, доведённый до состояния, в
котором его можно поставить как сервис: паритет по протоколу плюс то, без чего каталог не
работает на практике — запись, схема, ACL, TLS, наблюдаемость и первый администратор.

Без C-зависимостей: `#![forbid(unsafe_code)]`, rustls с `rustls-rustcrypto`, `redb` для
хранения, `serde-saphyr` для YAML.

## Что умеет

Протокол (RFC 4511 и расширения):

| | |
|---|---|
| bind | simple, анонимный; отказ в простом bind без шифрования по умолчанию |
| search | фильтры RFC 4515, scope, `baseObject`/`singleLevel`/`wholeSubtree` |
| запись | `add`, `delete`, `modify` (add/delete/replace), `modifyDN` |
| расширения | StartTLS, Password Modify (RFC 3062), `whoami` (1.3.6.1.4.1.4203.1.11.3) |
| фильтры | `=`, `*` (подстрока), `>=`, `<=`, `&`, `|`, `!`; `~=` отвечает «не реализовано», а не пустым результатом |
| контролы | paged results (1.2.840.113556.1.4.319), server-side sort (1.2.840.113556.1.4.473) с VLV, assertion (1.3.6.1.1.12) |
| прочее | `compare`, rootDSE, `cn=Subschema` с полными `attributeTypes`/`objectClasses` |

Данные и поведение:

- **схема как данные** — RFC 4512, режимы `strict`/`warn`/`off`, расширяется файлами
  `.schema`; проверяются обязательные и разрешённые атрибуты по `objectClass`;
- **операционные атрибуты** — `createTimestamp`, `modifyTimestamp`, `creatorsName`,
  `modifiersName`, `entryCSN`; отдаются по `+` или по имени, не отдаются по `*`;
- **ACL** — правила по субъекту (`admin`, `users`, `anonymous`, `self`, `dn=`, `group=`),
  поддереву и атрибутам;
- **целостность** — уникальность `cn`/`uid`, чистка `memberUid` при удалении пользователя;
- **индексы** — `pres`, `eq`, `sub` (триграммы) и `ord` (диапазоны), настраиваются по атрибутам;
- **пароли** — Argon2id (по умолчанию) или PBKDF2-SHA512; слабые схемы только по явной фразе
  в конфиге, и с их обновлением при успешном bind;
- **наблюдаемость** — `/healthz`, `/metrics` в формате Prometheus, журнал изменений
  (JSON Lines: кто, что, откуда, с каким результатом);
- **эксплуатация** — перезагрузка по таймеру, `SIGUSR1` и HTTP-callback; плавная остановка по
  `SIGTERM`; LDAPS и StartTLS; выгрузка в LDIF и YAML.

## Сборка

Rust на хосте не нужен: сборка идёт в закреплённом контейнере (`scripts/cargo.sh`), версия
тулчейна — в `rust-toolchain.toml`.

```
make build     # ./scripts/cargo.sh build --release
make check     # fmt --check, clippy -D warnings, все тесты
make install   # копирует бинарь в /usr/local/bin (sudo)
```

Артефакт появляется в `~/.cache/rrl/target/release/rust-rest-ldap`: каталог сборки вынесен из
репозитория, чтобы root в контейнере не оставлял мусор в дереве.

## Быстрый старт

Файловый бэкенд, простой bind разрешён — только для проверки на своей машине.

```sh
./rust-rest-ldap -c config.yaml -b file -B dc=example,dc=com -L 127.0.0.1:10389
ldapsearch -H ldap://127.0.0.1:10389 -x -b dc=example,dc=com "(objectClass=*)" dn
```

Данные для `file`-бэкенда — `examples/file/users.json` и `groups.json`.

## Установка как сервиса

```
sudo useradd --system --home /var/lib/rust-rest-ldap --shell /usr/sbin/nologin rust-rest-ldap
sudo install -d -m 0750 -o rust-rest-ldap -g rust-rest-ldap /etc/rust-rest-ldap
sudo install -m 0640 -o root -g rust-rest-ldap deploy/config.example.yaml /etc/rust-rest-ldap/config.yaml
sudo install -m 0644 deploy/rust-rest-ldap.service /etc/systemd/system/
sudo install -m 0755 rust-rest-ldap /usr/local/bin/
```

Дальше — сертификат, пароль первого администратора и запуск:

```sh
# Сертификат: цепочка и ключ в PEM.
#
# `basicConstraints=critical,CA:FALSE` обязателен. `openssl req -x509` без него делает
# сертификат удостоверяющим центром, а клиенты со строгой проверкой (rustls, современные
# браузеры) отказывают такому сертификату в роли серверного: "CA used as end entity".
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /etc/rust-rest-ldap/server.key \
  -out /etc/rust-rest-ldap/server.crt \
  -subj "/CN=ldap.example.com" \
  -addext "subjectAltName=DNS:ldap.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

# Пароль первого администратора — файлом, не аргументом: аргументы видны в ps.
sudo sh -c 'openssl rand -base64 24 > /etc/rust-rest-ldap/admin.pass'
sudo chown root:rust-rest-ldap /etc/rust-rest-ldap/admin.pass
sudo chmod 0640 /etc/rust-rest-ldap/admin.pass

sudo systemctl daemon-reload
sudo systemctl enable --now rust-rest-ldap
```

Первый администратор создаётся при старте, если хранилище пустое, и в лог пишется его DN.
Возьмите пароль из `admin.pass`, войдите им один раз и **уберите секцию `bootstrap:` из
конфигурации**: оставленная, она безвредна (сработает только на пустой базе), но пароль на
диске, который никто не читает, — это пароль, который забыли.

```
ldapwhoami -H ldaps://ldap.example.com -x \
  -D "cn=admin,ou=users,dc=example,dc=com" \
  -w "$(sudo cat /etc/rust-rest-ldap/admin.pass)"
```

## Конфигурация

Полный пример с комментариями — `deploy/config.example.yaml`. Настройки читаются из трёх
источников, и старший побеждает: флаг командной строки → переменная окружения → файл.

| Флаг | Переменная | Ключ в файле |
|---|---|---|
| `-b`, `--backend` | `BACKEND` | `backend` |
| `-B`, `--basedn` | `BASE_DN` | `base_dn` |
| `-L`, `--listen` | `LDAP_LISTEN_ADDR` | `listen_addr` |
| `-I`, `--interval` | `UPDATE_INTERVAL` | `update_interval` |
| `-c`, `--config` | `CONFIG_PATH` | — |
| `-l`, `--log` | — | — |
| `-d`, `--debug` | — | — |

Бэкенды: `file` (два JSON-файла, только чтение), `null` (пустой), `redb` (запись, одна
транзакция на набор изменений). Для данных, которые важны, — только `redb`: JSON-бэкенд
перезаписывает файл, которым владеет не он.

### Опасные настройки — фразой, а не `true`

Настройки, ослабляющие сервер, включаются только дословной фразой, и каждая — вместе с
мастер-подтверждением:

```yaml
AllowDangerousSettings: "Yes I know this is bad idea"   # обязательно для любой из нижних
bind:
  AllowUnencryptedBind: "Yes I know this is bad idea"
AllowPlainHttpRest: "Yes I know this is bad idea"
passwords:
  AllowWeakHashes: "Yes I know this is bad idea"
  AllowedWeakHashes: ssha, crypt-md5
```

`AllowUnencryptedBind: true` — ошибка с объяснением, что нужно написать фразу. Конфигурация,
скопированная из руководства по укреплению, не включает ничего случайно.

### Одна ловушка в ACL

Правило с перечисленными `attributes` не покрывает сам поиск: поддерево ищется по записи
целиком, без конкретного атрибута, и правило `attributes: [cn, mail]` на этот вопрос не
отвечает — клиент получает `no such object`. Анонимному чтению нужно `attributes: ["*"]`
(пароли при этом не выдаются: они помечены чувствительными).

## Утилиты

Собственный клиент — чтобы проверять сервер не только чужими бинарями.

```
./ldapsearch -H ldaps://ldap.example.com --cacert /etc/rust-rest-ldap/server.crt \
  -D "cn=admin,ou=users,dc=example,dc=com" -w "$(sudo cat /etc/rust-rest-ldap/admin.pass)" \
  -b "dc=example,dc=com" -LLL "(uid=alice)" cn mail
```

Флаги те же, что у OpenLDAP: `-H`/`-h`/`-p`, `-D`/`-w`/`-W`, `-b`/`-s`/`-a`, `-z`/`-l`,
`-LLL`, `-o ldif-wrap=no`, `-Z`/`-ZZ` (StartTLS), `-E pr=N` (paged results), `-S attr[-]`
(сортировка на сервере). `--cacert` — свой ЦС, `--insecure` — не проверять (шифрование без
проверки личности сервера).

### Загрузка LDIF

```
./ldapadd    -H ldaps://ldap.example.com --cacert ... -D "$ADMIN" -w ... -f dump.ldif
./ldapmodify -H ldaps://ldap.example.com --cacert ... -D "$ADMIN" -w ... -f changes.ldif
```

`ldapadd` — это `ldapmodify` под другим именем (симлинк, как в OpenLDAP): единственная
разница в том, что `-a` отказывает на записи `changetype:`, а не применяет её.

Поддерживается RFC 2849 целиком: `changetype: add | modify | delete | modrdn`,
`newsuperior`, `deleteoldrdn`, `::` base64, `:< file://` (только файлы: импорт каталога не
должен зависеть от сети), `version: 1`, комментарии, свёрнутые строки, файл без последней
пустой строки, вывод `slapcat`.

`-c` продолжает после отказа и печатает каждый; без `-c` работа останавливается на первом.
Файл разбирается целиком до отправки: синтаксическая ошибка в строке 900 означает, что не
ушло ничего.

### Остальные утилиты

Одна программа под пятью именами (как в OpenLDAP): имя говорит, что делать.

```
ldapwhoami  -H ldaps://host -D "$DN" -w ...                    # кем я привязан
ldapcompare -H ldaps://host -D "$DN" -w ... "$DN" "cn:alice"    # TRUE / FALSE
ldapmodrdn  -H ldaps://host -D "$DN" -w ... "$DN" "cn=newname"
ldapdelete  -H ldaps://host -D "$DN" -w ... "$DN"
ldapdelete  -r ... "$DN"                                        # с поддеревом
ldappasswd  -H ldaps://host -D "$DN" -w ... "$TARGET" -s newpass
ldappasswd  -H ldaps://host -D "$DN" -w ... "$TARGET"           # пароль сгенерирует сервер
```

`ldapcompare` принимает обе записи аргументов (`attr:value DN` и `DN attr:value`) и отвечает
теми же кодами, что OpenLDAP: **`6` TRUE, `5` FALSE, `16` нет атрибута, `32` нет записи**.
`-z` молчит — код и есть ответ.

`ldapdelete -r` удаляет детей раньше родителей: сервер отказывает в удалении записи, у которой
есть потомки, поэтому удаление сверху вниз остановилось бы на первом же узле.

**Код возврата — код результата LDAP**, как у OpenLDAP: `0` успех, `4` превышен предел
размера, `32` нет такого объекта, `49` неверные учётные данные. Скрипт ветвится по числу, а
не разбирает текст.

## Эксплуатация

```
curl --silent http://127.0.0.1:8080/healthz
curl --silent http://127.0.0.1:8080/metrics | grep ldap_
kill -USR1 "$(pidof rust-rest-ldap)"      # перечитать данные сейчас
curl --silent -I -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/callback
```

Метрики (`/metrics`) не требуют аутентификации: они описывают программу, а не данные.
Журнал изменений пишется строкой на операцию — удаление записи уносит её `modifiersName`,
поэтому «кто удалил» отвечается только журналом.

## Выгрузка

```
./rust-rest-ldap -c config.yaml --export-ldif - > dump.ldif
./rust-rest-ldap -c config.yaml --export-yaml - > dump.yaml
./rust-rest-ldap -c config.yaml --export-ldif --export-operational - > full.ldif
```

LDIF — формат обмена: его читают `ldapadd` и `slapadd`. YAML — тот же набор записей для
чтения глазами и правки в git; обратно в каталог он не загружается.

Выгрузка читает хранилище напрямую, поэтому с `redb` её надо делать при остановленном
сервисе: файл базы заперт на запись, и второй процесс получает `Database already open`.

## Загрузка без сервера: `--import-ldif`

Аналог `slapadd`: наполняет хранилище из LDIF, не поднимая порт. Это и есть ответ на вопрос
«как завести первый каталог» — по протоколу пустую базу наполнить нельзя, потому что `add`
требует bind, а bind требует записи, которой ещё нет.

```
./rust-rest-ldap -c /etc/rust-rest-ldap/config.yaml --import-ldif dump.ldif
./rust-rest-ldap -c config.yaml --import-ldif -            # из stdin
./rust-rest-ldap -c config.yaml --import-ldif extra.ldif --allow-existing-entry
```

- **Одна транзакция**: всё проверяется и собирается до записи. Нарушение схемы в записи
  9000 оставляет хранилище как было.
- **Только в пустое хранилище** (если не указан `--allow-existing-entry`): опечатка в пути не
  должна сливать дамп с рабочей базой.
- **Отказ называет запись и причину**: `record 2 (cn=broken,...) breaks the schema: ...`.

## Проверка конфигурации: `--check-config`

Аналог `slaptest`: говорит, запустится ли эта конфигурация, не занимая порт. Проверяет файл,
схему, бэкенд и все записи хранилища на соответствие схеме. Код возврата — ответ, поэтому
скрипт развёртывания ветвится по нему.

```
./rust-rest-ldap -c config.yaml --check-config
# конфигурация работоспособна: бэкенд 'redb', база 'dc=example,dc=com', записей 20003,
# с нарушениями схемы 0
```

## Проверка и перестройка индексов

```
./rust-rest-ldap -c config.yaml --check-index   # сверить индекс с перебором
./rust-rest-ldap -c config.yaml --reindex       # перестроить и показать цену
curl -X POST -H "Authorization: Token $TOKEN" http://127.0.0.1:8080/reindex
```

`--check-index` сравнивает ответы индекса с ответами перебора. Опасная ошибка здесь —
**ложный минус**: индекс, который не отдаёт запись, существующую в данных. Такой поиск просто
возвращает меньше, и по короткому ответу ничего не видно. Код возврата `1`, если индекс теряет
записи.

`--reindex` и `POST /reindex` не чинят устаревший индекс — его не бывает: каждая запись и каждая
перезагрузка строят индекс заново. Они отвечают на вопрос «сколько это стоит здесь»: записи,
атрибуты, байты, миллисекунды.

## Перезагрузка схемы без рестарта

```
kill -USR2 "$(pidof rust-rest-ldap)"
curl -X POST -H "Authorization: Token $TOKEN" http://127.0.0.1:8080/schema/reload
```

Файлы из `schema: files:` перечитываются целиком и собираются заново от `Schema::core()` —
никогда не дополняются к живой схеме, иначе определение, убранное из файла, осталось бы навсегда.

Перед тем как схема вступит в силу, существующие записи проверяются по ней: если данные уже
нарушают новые правила, схема не принимается, иначе каждая следующая запись стала бы отказом.

Отказы различаются кодом: `400` — файл не читается или не разбирается (неверный ввод), `409` —
файл понят, но данные под него не подходят (неверное состояние). Битый файл оставляет прежнюю
схему в силе, и в журнале это сказано прямо.

## Хранилище конфигурации: генерации

Аналог `slapd.d`, но с тремя свойствами, которых у него нет: атомарность, история и сборка
мусора. `-c` может указывать либо на файл конфигурации, либо на **каталог** — каталог это
хранилище.

```
config.d/current -> generations/0000000003-…yaml
config.d/generations/
    0000000001-20261102183835.108510Z.yaml
    0000000002-20261102183843.793679Z.yaml
    0000000003-20261102183857.210982Z.yaml
```

Каждая генерация — **полная конфигурация в одном файле**, а не diff. Метаданные лежат в
комментариях сверху, поэтому генерация остаётся обычной конфигурацией для любого YAML-парсера и
при этом помнит, кто её зафиксировал, когда и почему.

```
./rust-rest-ldap -c /etc/rust-rest-ldap/config.d --config-history
./rust-rest-ldap -c /etc/rust-rest-ldap/config.d --config-commit --from config.yaml --note "начальная"
./rust-rest-ldap -c /etc/rust-rest-ldap/config.d --config-commit --note "отметка перед правкой"
./rust-rest-ldap -c /etc/rust-rest-ldap/config.d --config-rollback 3
```

- **Коммит атомарен**: временный файл → `fsync` → `rename` в имя генерации → новый указатель
  через `rename` поверх `current`. Сбой на любом шаге оставляет либо прежнюю генерацию, либо
  новую, и никогда — их смесь или висячий указатель.
- **Указатель относительный**, поэтому хранилище можно скопировать на другую машину, и оно
  останется рабочим.
- **Откат — это новый коммит** старого документа, а не сдвинутый назад указатель: история должна
  говорить, что кто-то откатился и когда.
- **Сборка мусора** идёт вместе с коммитом, по умолчанию хранится 10 генераций
  (`--config-keep N`); генерация в силе не удаляется никогда.
- **Коммиты сериализованы** файловой блокировкой: два одновременных коммита иначе получили бы
  один номер и опубликовали два файла под ним.

### Подводный камень YAML

`backend: null` — это **не** имя бэкенда `null`, а YAML-значение null, то есть «не задано», и
сервер возьмёт значение по умолчанию (`rest`). Имя бэкенда, совпадающее с ключевым словом YAML,
надо брать в кавычки:

```yaml
backend: "null"
```

## `cn=config`: конфигурация по протоколу

```
ldapsearch -x -H ldap://127.0.0.1:389 -D "cn=admin,..." -w ... -b cn=config -s sub "(objectClass=*)"
ldapsearch ... -b cn=config -s sub "(objectClass=*)" "*" "+"   # плюс restldap-origin
```

Поддерево **генерируется из документа конфигурации**, а не хранится: второй копии нет, значит нет
и расхождения с файлом, который сервер прочитал. Уровень документа — уровень дерева, ключи получают
префикс `restldap-`:

```
cn=config                                    restldap-backend, restldap-base-dn, ...
 cn=backends                                 (раздел)
  cn=rest                                    restldap-url, restldap-auth-token, ...
  cn=redb                                    restldap-path, restldap-durability
 cn=indexes
  cn=attributes                              restldap-cn: eq, pres
```

- Скаляр — значение атрибута, список скаляров — многозначный атрибут, отображение — запись,
  список отображений — запись на ключ и по записи на элемент (`cn=1`, `cn=2`; порядок сохраняется
  номером, как `{X}` в `slapd.d`).
- Префикс нужен не для красоты: записи разделов названы по `cn`, и ключ документа `cn` (индекс по
  атрибуту `cn`) иначе означал бы в одной записи две вещи. Оба эталона делают то же (`olc*`,
  `nsslapd-*`).
- Публикуется **документ**, а не развёрнутая конфигурация: умолчаний, которых в файле нет, здесь
  нет — иначе следующая запись вернула бы их в файл как настройки, которых никто не выбирал.
  Переопределения из командной строки и окружения тоже не публикуются: `slapd.d` не помнит `-h`.
- `restldap-origin` (операционный, нужен `+`) говорит, откуда документ: `file:/etc/...` или
  `store:/etc/config.d generation 3`.
- Читает **только администратор**: в документе `auth_token`, `callback_auth_token` и всё остальное
  из файла. Ответ анониму — `insufficientAccessRights (50)`, а не мнимое «no such object».
- Запись пока отвергается с `unwillingToPerform (53)` и причиной: поддерево ещё только читается.
  Записываемый `cn=config` — следующий шаг, и он будет коммитом поколения через хранилище выше.

## Разработка

```
make check                                    # форматирование, clippy, тесты
./scripts/cargo.sh test --test bootstrap      # один набор
```

Правила и история решений — `docs/ub-log.md` (каждый шаг: зачем, что, почему так, как
проверено), план и остаток — `docs/plan.md`.
