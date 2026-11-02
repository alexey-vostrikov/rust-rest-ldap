# rust-rest-ldap

LDAP server with REST API & file backends, written in Rust.

Порт [gorestldap](https://github.com/ps78674/gorestldap) 0.10.1: сервер загружает данные из
бэкенда (`file` или `rest`) в виде JSON и держит их в памяти, отвечая на LDAP-запросы.
Поддерживаются bind, search, compare и modify (только replace), paged results
(1.2.840.113556.1.4.319), rootDSE, LDAPS и HTTP-callback для перезагрузки данных.

Сборка идёт в контейнере (`scripts/cargo.sh`), на хосте Rust-тулчейн не нужен.

## Сборка

```
make build      # ./scripts/cargo.sh build --release
make check      # fmt --check, clippy -D warnings, тесты
```

## Запуск

```
./target/debug/rust-rest-ldap -c config.yaml -b file -B dc=example,dc=com -L 0.0.0.0:10389
```

Пример конфигурации и данные лежат в `config.yaml` и `examples/file/`.
