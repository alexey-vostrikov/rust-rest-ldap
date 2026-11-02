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
- **индексы** — `pres` и `eq`, настраиваются по атрибутам;
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

## Разработка

```
make check                                    # форматирование, clippy, тесты
./scripts/cargo.sh test --test bootstrap      # один набор
```

Правила и история решений — `docs/ub-log.md` (каждый шаг: зачем, что, почему так, как
проверено), план и остаток — `docs/plan.md`.
