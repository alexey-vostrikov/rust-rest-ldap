# Локальный патч `rasn-ldap`

## Зачем

`ResultCode` в `rasn-ldap` (и в 0.29, и в 0.30) — закрытое перечисление, в котором есть только коды
из исходного RFC 4511. Кодов, добавленных позже, там нет:

| Код | Имя | Где нужен |
|---|---|---|
| 118 | `canceled` | Cancel operation |
| 119 | `noSuchOperation` | Cancel |
| 120 | `tooLate` | Cancel |
| 121 | `cannotCancel` | Cancel |
| 122 | `assertionFailed` | Assertion control (RFC 4528) |
| 123 | `authorizationDenied` | Proxy authorization |

Перечисление нерасширяемое, поэтому ответ с кодом, для которого нет варианта, отправить нельзя
вообще: `Control`-путь не спасает, потому что `LdapResult.result_code` имеет тип `ResultCode`.

Без `assertionFailed` assertion control теряет смысл: клиент не отличит «твоё условие не совпало»
от общего отказа сервера и не сможет повторить чтение и решение.

## Что именно изменено

Один файл — `vendor/rasn-ldap/src/lib.rs`, шесть вариантов в конце `enum ResultCode`:

```rust
Canceled = 118,
NoSuchOperation = 119,
TooLate = 120,
CannotCancel = 121,
AssertionFailed = 122,
AuthorizationDenied = 123,
```

Больше ничего: ни декодирования, ни типов, ни зависимостей. Копия сделана из опубликованного
крейта 0.30.0, `Cargo.toml.orig` и `Cargo.lock` из неё удалены, чтобы сборка шла от манифеста
основного проекта.

Подключение:

```toml
[patch.crates-io]
rasn-ldap = { path = "vendor/rasn-ldap" }
```

## Как убрать

Когда в upstream появится релиз с этими кодами:

1. поднять версию в `Cargo.toml` (`rasn-ldap = "0.3x"`);
2. удалить блок `[patch.crates-io]` и каталог `vendor/rasn-ldap`;
3. `./scripts/cargo.sh update -p rasn-ldap` и прогнать тесты.

Проверка, что патч больше не нужен: `grep -c AssertionFailed` по исходникам нового релиза в
`~/.cache/rrl/cargo/registry/src/`.

## Проверено

`ldapmodify -e 'assert=(cn=nope)'` против живого сервера получает ровно `Assertion Failed (122)`,
а `-e 'assert=(cn=group_a)'` проходит и запись сохраняется.
