# Задачи из стенда AD-join (от того, кто правит KDC)

Записано по результатам прогона стенда, который вводит Samba в домен против этого каталога и
`rust-heimdal-kdc`. Стенд лежит в `~/DevOps/rust-heimdal-kdc/stand/ad-join/`, его README — в
`stand.sh`. Код этого репозитория здесь **не правился**: всё ниже — находки с воспроизведением,
решать и делать тому, кто ведёт `rrl-directory`.

## Состояние на 12 ноября: всё закрыто

`net ads join` против этого каталога проходит целиком: `JOIN_EXIT=0`, `net ads testjoin` →
`Join is OK`, `kinit -k SAMBA$` → TGT, `ldapwhoami -Y GSSAPI` → `dn:cn=samba$,ou=users,...`.
Ни одного открытого пункта в файле не осталось; что нашлось по дороге сверх списка — в конце
раздела §9 (соль ключей машины по `dNSHostName`) и в `docs/plan.md`, «Домен Windows».

| п. | что | состояние |
| --- | --- | --- |
| 1 | доктест `sync.rs` валит `cargo test` | закрыт, `5d1ac8f` |
| 2 | передача channel binding не покрыта | закрыт, тест на `accept_options` |
| 3 | формулировка §про SASL в плане | закрыт, раздел переписан |
| 4 | нет `currentTime` в root DSE | закрыт, `ed7e77a` |
| 5 | следующий блокер — MS-RPC | **неверно**: блокером был выключенный SMB в стенде; см. §5 |
| 6 | в стенде нет `smb:`, поэтому SMB-путь не измерялся ни разу | закрыт, §6 |
| 7 | клиентский TGS для `cifs/…` падает на FAST/сроках тикета (сторона KDC) | закрыт, §7 |
| 8 | SASL security layer: `net ads join` заворачивает LDAP (`ADS_SASL_SEAL`), сервер не умеет | закрыт, §8 |
| 9 | `WKGUID` в базе поиска не разбирается — контейнер компьютеров не находится | закрыт по разбору и по контейнеру, §9 |
| 10 | `net ads join` создаёт учётку через трубу `samr` — её в `IPC$` нет | закрыт: труба есть, учётка создаётся, `CreateUser2` отказывает честно (§10) |

По п. 5 за день стало известно больше, чем было при записи: `NT_STATUS_OBJECT_NAME_NOT_FOUND`
(труба `lsarpc` не открывалась) → `The procedure number is out of range` (клиент зовёт
`lsa_OpenPolicy`, opnum 6, а был реализован 44) → `{Buffer Too Small}`. Все три закрыты, и
последний прогон стенда (§5) показывает, что `lsarpc` отдаёт члену домена доменное имя, лес и SID.

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

## 5. Следующий блокер — LDAP, а не MS-RPC: SMB в стенде был выключен

Что стенд показал по шагам (факты, не оценки), прогон 10 ноября, Samba 4.17.12:

| шаг | результат |
|---|---|
| `kinit administrator@AD.EXAMPLE.COM` | TGT выдан `kdc-stand`, MIT-клиент |
| `ldapsearch -Y GSSAPI -O maxssf=0` | bind прошёл (после `0bc3c6f`) |
| `net ads info -S samba.ad.example.com` | DC найден: LDAP 127.0.0.1:389, realm `AD.EXAMPLE.COM`, KDC найден, `currentTime` сверен |
| `net ads join -k` (как есть) | отказ: `failed to lookup DC info … over rpc: The transport-connection attempt was refused by the remote system` |
| `net ads join -k` (с `smb:` в конфиге) | SMB и `lsarpc` пройдены, отказ сдвинулся на LDAP: `failed to connect to AD: Authentication method not supported` |

Причина первого отказа — не RPC: в `stand/ad-join/rrd.yaml` нет секции `smb:`, процесс не слушает
445, `/dev/tcp/127.0.0.1/445` даёт `Connection refused`. `libnet_join_connect_dc_ipc` упирается в
закрытый порт, и всё, что дальше, стенд не измерял ни разу.

Когда SMB включили, путь прошёл целиком: `NEGOTIATE` до `Smb311`, Kerberos session setup на
`cifs/samba.ad.example.com`, `TREE_CONNECT IPC$`, `lsarpc`, и join получил из `QueryInfoPolicy2`
доменное имя, лес и `domain_sid = S-1-5-21-3982645575-1531477709-3248814646` (`domain_is_ad = 1`).

**Про `netr_DsRGetDCName` (это была задача «следующий блокер»).** На пути `net ads join` его нет.
`source3/libnet/libnet_join.c` 4.17.12: строка 1197 открывает `ndr_table_lsarpc`, 1213 зовёт
`QueryInfoPolicy2`; `ndr_table_netlogon` появляется на 1274 и 1853, но это `ServerAuthenticate3` и
`ServerPasswordSet2` (защищённый канал, RRL-2.9). Контролёра ищет `dsgetdcname()` — CLDAP-пинг,
который уже отвечается. `netr_DsRGetDCName` (opnum 0x14) нужен Windows-клиенту, а не Samba-члену.

Следующий настоящий блокер — RRL-2.15 (SASL-механизм для `ads_connect`), код этого репозитория.

Полезное для планирования: `-k` в Samba 4.23 помечен deprecated, а `net ads join` без `-k`
спрашивает пароль администратора и идёт тем же путём — то есть альтернативы RPC нет, и «offline
join» стоит проверить отдельно, прежде чем считать эту работу неделями.

## 6. В стенде нет `smb:` — и секция нигде не описана

Чтобы SMB заработал, в конфиг стенда достаточно добавить:

```yaml
smb:
  enabled: true
  netbios_name: SAMBA
  keytab: /shared/service.keytab
  dns_domain: ad.example.com
  domain_netbios: AD
```

Отдельно стоит знать: секции `smb:` нет ни в `README.md`, ни в `deploy/config.example.yaml`, ни в
`config.yaml` — единственное её описание в `src/smb/mod.rs`. Поэтому её и не включили ни в стенде,
ни где-либо ещё, а SMB-часть проверялась только тестами `smb-server`.

## 7. Клиентский TGS для `cifs/…` падает на FAST и сроках (сторона KDC)

На свежем ccache первый же `net ads join` падает у клиента, в `gse_get_client_auth_token`, и отказ
чередуется между прогонами:

```
FAST fast response is missing FX-FAST (cifs/samba.ad.example.com@AD.EXAMPLE.COM)
the TGT expires before the ticket would start (KRB-ERROR 11) (cifs/...)
```

`kvno cifs/samba.ad.example.com` тем же MIT-клиентом билет получает, после чего join идёт дальше.
RRL-2.16, 2.18 и 2.21 помечены закрытыми — на этом стенде их надо перепроверить. Отдельно:
`wait_for_port` в `stand.sh` ждёт 10 секунд, а `kdc-stand` под нагрузкой сеялся дольше (один прогон
упал на «the KDC did not start»).

## 8. SASL security layer: join заворачивает LDAP, и это не настройка

**Состояние: закрыт по реализации, 10 ноября.** Приём и выдача sealed-wrap работают, проверено живым
`net ads join` (см. ниже). Осталось то, что описано в §9.

После правки §3 (`supportedSASLMechanisms` + `GSS-SPNEGO`, начиная с сервера) `net ads join` проходит
SMB, lsarpc и LDAP-bind — и на первом же запросе после bind присылает не LDAP:

```
00 00 00 b7 05 04 02 ff ...
```

Это четырёхоктетная длина и токен RFC 4121 с id `05 04` и flags `02` (sealed): Samba завернула
LDAP-запрос в SASL. Причина не в конфигурации клиента: `libnet_connect_ads`
(`source3/libnet/libnet_join.c`, 4.17.12, строка 148) вызывает `ads_init(..., ADS_SASL_SEAL)`
безусловно. Проверено: `client ldap sasl wrapping = plain` в `smb.conf` перехват не меняет —
sealed-токен на том же месте.

Следствия:

- `net ads join` этим каталогом не завершается, пока не реализован слой (seal как минимум, sign —
  следующим). Это меняет оценку §плана «SASL security layer. **Не делать.**»: для LDAP-клиентов
  libsasl слой действительно необязателен (`-O maxssf=0`), а для вступления машины он обязателен.
- Сервер теперь называет отказ в журнале (`FrameError::SaslWrapped`) вместо `message is not a BER
  sequence (tag 0x00)`, после которого клиент через 20 секунд печатал `Time limit exceeded` — то есть
  жаловался на таймаут, а не на слой.

Что нужно знать, если брать это в работу: обёртка по RFC 4752 §3.2 — четырёхоктетный префикс длины
поверх обычного `gss_wrap` (RFC 4121), маска слоёв согласуется **только** у libsasl-клиентов; клиент
на `gensec` её не согласует вовсе и начинает заворачивать сразу после контекста. То есть сервер обязан
принимать wrap и без предварительного обмена маской.

### Как это сделано и что дал прогон

`src/ldap/sasl_bind.rs` — `Wrap`: пара `PerMessageTokens` (ключ из билета), свои счётчики `send` и
`recv`, флаг `pending` до момента, когда объявляющий ответ записан. `src/ldap/codec.rs` —
`read_message_with`/`write_message_with`: если слой в силе, кадр — четыре октета длины и токен Wrap.

**Подводный камень, найденный только живым клиентом: SND_SEQ начинается не с нуля.** Первый прогон
после реализации дал

```
client 127.0.0.1:58316: SASL security layer: the client's message carries sequence number
316063208 where 0 was next: a repeated or reordered wrap on one connection is not a retransmission
```

Токен расшифровался (значит, ключ верный), и отказал только счётчик. Причина: RFC 4121 §4.2.1
разрешает случайный начальный номер, и MIT/Heimdal так и делают. Правило стало другим: **первый**
номер задаёт базу, каждый следующий обязан быть ровно на единицу больше. Тест на повтор номера
переписан под это: сначала сообщение с произвольным `seq`, потом то же самое ещё раз — второе
отвергается.

**Результат на стенде.** `net ads join -k` после правки проходит SMB, lsarpc, LDAP-bind и **sealed
поиск**: сервер расшифровал запрос, ответил зашифрованным ответом, клиент его принял. Следующий отказ
— уже не про слой, а про содержимое каталога (§9).

## 9. `WKGUID` в базе поиска: `/computers` ищется виртуально

**Состояние: закрыт, 10 ноября.** База разбирается (обе записи — с угловыми скобками и без), GUID
разрешается через `wellKnownObjects` родителя, а при отсутствии значения — по таблице AD; контейнер
`cn=Computers` создаётся при старте. Проверено живым клиентом: строка
`Failed while searching for: <WKGUID=…>` из журнала join'а ушла.

Две вещи, которые выяснились только прогоном:

- **Samba присылает базу в угловых скобках** — `<WKGUID=…,dc=…>` (её собственная `dsdb_dn`-нотация,
  которую настоящий AD принимает). Сервер, понимавший только «голую» форму, отказывал клиенту за
  написание, о необычности которого клиент не знал. Обе формы теперь читаются (`parse`), тест
  сверяет их равенство.
- **Контейнера `cn=Computers` в каталоге не было вовсе.** Разрешённый GUID указывал на DN, которого
  нет, и Samba получала «объект не найден» уже на своей стороне. Теперь `src/provision.rs` создаёт
  его при старте, когда сервер обслуживает домен, с классом AD `container` (1.2.840.113556.1.5.2,
  добавлен в `ad_schema`).

Что осталось от исходной записи: `wellKnownObjects` в доменном разделе этим каталогом не хранится
(доменная запись синтезируется), поэтому используется таблица AD — `cn=computers` и `cn=users`;
значение из стора, если оно есть, всегда важнее таблицы.

## 10. Следующая стена: труба `samr`, а не LDAP

**Состояние: труба добавлена в `rust-smb-server` (`a44c2c8`), 10 ноября.** Отказ сдвинулся с
«нет трубы» на честный отказ самой операции: `The request is not supported` — это `CreateUser2`.

После §8 и §9 join на стенде проходит SMB, lsarpc, LDAP-bind, sealed-поиск и находит контейнер
компьютеров. Отказ сдвинулся на создание учётной записи:

```
Error connecting to SAM pipe. Error was NT_STATUS_OBJECT_NAME_NOT_FOUND
error_string : 'failed to join domain 'AD.EXAMPLE.COM' over rpc: The object name is not found.'
```

В журнале сервера — то же место и та же причина:

```
pipe opened name=lsarpc
no such pipe name=samr
```

То есть `libnet_join` создаёт учётку машины не по LDAP, а через `samr` (`samr_Connect2`,
`samr_OpenDomain`, `samr_CreateUser2`, `samr_SetUserInfo2`), и без этой трубы дальше не идёт.
Прежняя запись «Failed to pre-create account … Time limit exceeded» была тем же отказом, только
медленным: клиент ждал ответа на открытие трубы, которой нет.

### Что сделано в `rust-smb-server`

`src/rpc/samr.rs`: `Connect`, `Connect2`, `Connect5`, `Close`, `OpenDomain`, `LookupDomain`
отвечаются — это факты о собственном домене сервера (его SID из `ServerConfig::domain_sid`, его
NetBIOS- и DNS-имя). `CreateUser2` **отказывает** `NT_STATUS_NOT_SUPPORTED`: создание учётной
записи машины — запись в каталог, а этот крейт каталога не читает. Ответить `success` и ничего не
записать значило бы выдать клиенту RID, которым нечего делать, и получить отказ позже — «машина не
может аутентифицироваться», что диагностируется хуже, чем честный отказ сейчас. Труба зарегистрирована
в списке известных, синтаксис `samr` — в `negotiate`.

**Три вещи, которые знал только клиент** (каждая — отдельный прогон стенда):

1. **Версия синтаксиса `samr` — 1.0, а не 0.0.** Скопированная с `lsarpc` константа отвергалась на
   каждом bind, и клиент печатал `{Buffer Too Small}` вместо «интерфейс не принят».
2. **Контекстный хэндл маршалится без referent id**, хотя в IDL стоит `[out,ref] policy_handle *`.
   С referent'ом клиент прочитал `samr` из тела хэндла как статус: `NT code 0x726d6173`.
3. **Два скаляра `CreateUser2` тоже читаются inline**, без referent'ов: иначе клиент читает
   `NT code 0x00020004` — второй referent вместо статуса.

**Что осталось.** Ответ на `CreateUser2` (и `SetUserInfo2` с паролем машины) — работа того, кто
владеет каталогом: `rrl-directory` уже умеет путь записи учётной записи компьютера (тест
`a_member_can_add_its_computer_account`), но `samr` живёт в `rust-smb-server`, и связать их — это
обратный вызов из `ServerConfig` в каталог. Форма: трейт вида `MachineAccounts` с
`create_user2(account, flags) -> Result<(rid, handle)>`, реализуемый демоном.

## Чего в этом файле нет

Чего здесь нет: правок кода. Всё выше либо воспроизводится командой, либо измерено прогоном; код,
который эти отказы закрывал, лежит в `src/ldap/` этого репозитория и в журнале (`docs/ub-log.md`)
описан отдельно.
