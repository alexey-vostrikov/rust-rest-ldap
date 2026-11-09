# Задачи из стенда AD-join (от того, кто правит KDC)

Записано по результатам прогона стенда, который вводит Samba в домен против этого каталога и
`rust-heimdal-kdc`. Стенд лежит в `~/DevOps/rust-heimdal-kdc/stand/ad-join/`, его README — в
`stand.sh`. Код этого репозитория здесь **не правился**: всё ниже — находки с воспроизведением,
решать и делать тому, кто ведёт `rust-rest-ldap`.

## Состояние на 9 ноября

| п. | что | состояние |
| --- | --- | --- |
| 1 | доктест `sync.rs` валит `cargo test` | закрыт, `5d1ac8f` |
| 2 | передача channel binding не покрыта | закрыт, тест на `accept_options` |
| 3 | формулировка §про SASL в плане | открыт |
| 4 | нет `currentTime` в root DSE | открыт |
| 5 | следующий блокер — MS-RPC | открыт, отказ сдвинулся дважды |

По п. 5 за день стало известно больше, чем было при записи: `NT_STATUS_OBJECT_NAME_NOT_FOUND`
(труба `lsarpc` не открывалась) → `The procedure number is out of range` (клиент зовёт
`lsa_OpenPolicy`, opnum 6, а был реализован 44) → `{Buffer Too Small}`. То есть до Netlogon
дело не дошло: упирается в lsarpc, а не в secure channel.

## 1. Блокер: `cargo test` падает на доктесте

`src/ldap/sync.rs`, начало файла: блок с ASN.1 открыт как `//! ``` ` без языка, поэтому rustdoc
компилирует его как Rust.

```
$ ./scripts/cargo.sh test --release --doc ldap::sync
error: expected identifier, found `=`
 --> src/ldap/sync.rs:7:20
7 | syncRequestValue ::= SEQUENCE {
test result: FAILED
```

Это валит `cargo test` целиком, то есть и job `checks`. Воспроизведено на `HEAD` (`a4c7af8`) без
единой правки. Починка — открыть блок как ` ```text `; других блоков без языка, содержащих не-Rust,
в `src/` нет (проверены все десять).

## 2. Канал-биндинг: строка не покрыта ни одним тестом

`src/ldap/sasl_bind.rs`, `begin`: `options.channel_bindings = security.channel_binding.clone();`

Мутация «заменить на `options.channel_bindings = None`» оставляет **1009 тестов зелёными**.
Причина: `tests/channel_binding.rs` работает с акцептором `krb5` напрямую, то есть доказывает
арифметику RFC 5929 и ничего не говорит о том, передаёт ли сервер привязку в него. Ровно этот
класс ошибки уже был в этом файле с SASL-слоем (см. п. 3): тесты строились из того, что удобно
построить, а не из того, что идёт по проводу.

Предложение, проверенное у себя (22 теста, мутация убита, откат подтверждён): вынести построение
опций в функцию и тестировать её.

```rust
fn accept_options(security: &Security, gssapi: &crate::sasl::Gssapi) -> krb5::acceptor::AcceptOptions {
    let mut options = krb5::acceptor::AcceptOptions::default();
    options.replay_cache = Some(gssapi.replay());
    options.channel_bindings = security.channel_binding.clone();
    options
}
```

```rust
#[test]
fn a_bind_hands_the_acceptor_the_channel_binding_it_was_given() {
    let (mut security, _dir) = security_with_keytab();
    let gssapi = security.gssapi.clone().expect("the fixture loads a keytab");
    assert!(accept_options(&security, &gssapi).channel_bindings.is_none());
    let binding = krb5::ChannelBindings::new(b"tls-server-end-point:abc".to_vec());
    security.channel_binding = Some(binding.clone());
    let options = accept_options(&security, &gssapi);
    assert_eq!(options.channel_bindings, Some(binding));
    assert!(options.replay_cache.is_some());
}
```

## 3. Раздел плана про SASL security layer стоит переформулировать

`docs/plan.md` §«SASL security layer (integrity / confidentiality). **Не делать.**» объясняет
отсутствие слоя. Но настоящая проблема была не в отсутствии слоя, а в **чтении выбора клиента**:
cyrus-sasl защищает свой четырёхоктетный выбор Wrap-токеном со снятым `Sealed` (integrity, потому
что negotiated layer = none), а сервер читал только sealed-путём. Любой реальный `ldapsearch -Y
GSSAPI` получал

```
Invalid credentials (49)
  additional info: security layer: the client's security-layer choice could not be unwrapped:
  Wrap token has Sealed=false, but the privacy service was requested
```

то есть сообщение обвиняло токен клиента. Исправлено коммитом `0bc3c6f` (разбор по биту `Sealed`,
`unwrap` либо `verify_wrap_unsealed`, плюс два теста). Сам security layer по-прежнему не сделан —
и это осознанно, причина в плане верная.

Практическое следствие для плана: в маске остаётся только `NO_LAYER`, поэтому клиент обязан просить
`-O maxssf=0`. Это стоит написать в §про SASL, иначе первый же человек с `ldapsearch` решит, что
сломан сервер.

## 4. root DSE: нет `currentTime`

`net ads info` печатает

```
Failed to get server's current time!
Server time: Thu, 01 Jan 1970 00:00:00 UTC
Server time offset: 0
```

В root DSE нет `currentTime` (RFC 4512 §5.1). Kerberos живёт без него, но AD-клиенты и Samba
сверяют по нему часы и печатают предупреждение; при расхождении часов это первое, что проверяют.
Формат — `GeneralizedTime`, хелпер уже есть: `crate::operational::generalized_time`.

## 5. Следующий блокер после этого — Netlogon, и он измерен

Что стенд показал по шагам (факты, не оценки):

| шаг | результат |
|---|---|
| `kinit administrator@AD.EXAMPLE.COM` | TGT выдан `rust-heimdal-kdc`, MIT-клиент |
| `ldapsearch -Y GSSAPI -O maxssf=0` | bind прошёл (после `0bc3c6f`) |
| `net ads info -S samba.ad.example.com` | DC найден: LDAP 127.0.0.1:389, realm `AD.EXAMPLE.COM`, KDC найден |
| `net ads join -k` | **отказ**: `failed to lookup DC info for domain 'AD.EXAMPLE.COM' over rpc: The transport-connection attempt was refused by the remote system` |

То есть Kerberos и LDAP для вступления уже достаточны; упирается в MS-RPC (Netlogon secure channel,
endpoint mapper 135 / SMB 445). Это совпадает с §плана «MS-NRPC Netlogon» — но теперь у него есть
воспроизведение: `~/DevOps/rust-heimdal-kdc/stand/ad-join/run.sh all`, четыре шага, отказ печатается
как есть.

Полезное для планирования: `-k` в Samba 4.23 помечен deprecated, а `net ads join` без `-k`
спрашивает пароль администратора и идёт тем же путём — то есть альтернативы RPC нет, и «offline
join» стоит проверить отдельно, прежде чем считать эту работу неделями.

## Чего в этом файле нет

Правок в коде этого репозитория. Всё выше либо воспроизводится командой, либо измерено прогоном.
