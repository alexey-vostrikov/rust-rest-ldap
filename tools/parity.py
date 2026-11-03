#!/usr/bin/env python3
"""Сверка rust-rest-ldap с настоящим gorestldap на одном и том же входе.

Зачем: «полный паритет» — заявление, а не факт, пока его не с чем сверить. Этот скрипт поднимает
оба сервера на одних и тех же данных, задаёт им одни и те же вопросы и сообщает о расхождениях.

Расхождения делятся на три вида, и разница между ними — суть проверки:

  same     ответы совпали;
  better   ответы разные, и правильный — наш (это записано здесь же, с причиной);
  TODO     ответы разные, и мы не знаем, кто прав: такой случай валит прогон.

Последнее — главное. Молча «известное расхождение» превращается в вечное; расхождение, которое
приходится переобъяснять каждый прогон, — нет.

Запуск:
    tools/parity.py --go-ref ../gorestldap        # поднимет оба и сравнит
    tools/parity.py --go-url ldap://127.0.0.1:11800 --rust-url ldap://127.0.0.1:11801
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

BASE_DN = "dc=example,dc=com"
BIND_DN = "cn=admin,ou=users,dc=example,dc=com"
BIND_PW = "admin"


@dataclass
class Case:
    name: str
    args: list[str]          # аргументы ldapsearch после подключения
    verdict: str             # same | better | TODO
    reason: str = ""


CASES = [
    Case("дерево целиком", ["-b", BASE_DN, "-s", "sub", "(objectClass=*)", "dn", "cn"], "same"),
    Case(
        "одна запись, все атрибуты",
        ["-b", BASE_DN, "-s", "sub", "(cn=admin)", "*"],
        "better",
        "gorestldap отдаёт userPassword (хеш пароля) в ответ на *; мы его не отдаём. "
        "Утечка хеша — дефект эталона; RFC 4519 §2.5 не требует отдавать пароль клиенту вовсе",
    ),
    Case("только cn", ["-b", BASE_DN, "-s", "sub", "(cn=admin)", "cn"], "same"),
    Case("равенство", ["-b", BASE_DN, "-s", "sub", "(uid=admin)", "dn", "uid"], "same"),
    Case("существование", ["-b", BASE_DN, "-s", "sub", "(mail=*)", "dn", "mail"], "same"),
    Case(
        "подстрока с ведущим шаблоном",
        ["-b", BASE_DN, "-s", "sub", "(cn=*dmin)", "dn", "cn"],
        "better",
        "gorestldap читает фильтр как «вернуть всё»: в search.go он берёт "
        "_attrValue.(ldap.SubstringInitial), отбрасывает ошибку приведения типа, и для *dmin "
        "получает пустую строку, а HasPrefix(val, \"\") истинно всегда. Наш ответ — одна запись",
    ),
    Case("подстрока с хвостовым шаблоном", ["-b", BASE_DN, "-s", "sub", "(cn=adm*)", "dn"], "same"),
    Case("И", ["-b", BASE_DN, "-s", "sub", "(&(objectClass=posixAccount)(uid=admin))", "dn"], "same"),
    Case(
        "ИЛИ",
        ["-b", BASE_DN, "-s", "sub", "(|(uid=admin)(uid=nobody))", "dn", "uid"],
        "same",
    ),
    Case(
        "НЕ",
        ["-b", BASE_DN, "-s", "sub", "(!(objectClass=posixGroup))", "dn"],
        "better",
        "gorestldap возвращает пусто на любой фильтр с ! — отрицание не реализовано. "
        "Наш ответ — 4 записи, которых posixGroup не касается",
    ),
    Case("область base", ["-b", BASE_DN, "-s", "base", "(objectClass=*)", "dn", "cn"], "same"),
    Case("область one", ["-b", BASE_DN, "-s", "one", "(objectClass=*)", "dn"], "same"),
    Case(
        "несуществующая база",
        ["-b", f"ou=nothing,{BASE_DN}", "-s", "sub", "(objectClass=*)", "dn"],
        "same",
    ),
    Case(
        "операционные атрибуты (+)",
        ["-b", BASE_DN, "-s", "sub", "(cn=admin)", "+"],
        "better",
        "мы отдаём subschemaSubentry (RFC 4512 §5.1), эталон — нет",
    ),
    Case("сортировка", ["-b", BASE_DN, "-s", "sub", "(objectClass=*)", "dn", "cn", "-E", "sss=cn"], "same"),
    Case(
        "сортировка по убыванию",
        ["-b", BASE_DN, "-s", "sub", "(objectClass=*)", "dn", "-E", "sss=-cn"],
        "same",
    ),
    Case(
        "сортировка с правилом",
        ["-b", BASE_DN, "-s", "sub", "(objectClass=*)", "dn", "-E", "sss=cn:caseExactOrderingMatch"],
        "same",
    ),
    Case(
        "страницы по одной",
        ["-b", BASE_DN, "-s", "sub", "(objectClass=*)", "dn", "-E", "pr=1/noprompt"],
        "same",
    ),
]

GO_CONFIG = """log_timestamp: false
log_caller: false
backend_dir: {backends}
backends:
  file:
    users_path: {users}
    groups_path: {groups}
respect_control_criticality: true
users_ou_name: users
groups_ou_name: groups
use_tls: false
"""

RUST_CONFIG = """base_dn: {base}
listen_addr: {listen}
backend: file
backends:
  file:
    users_path: {users}
    groups_path: {groups}
users_ou_name: users
groups_ou_name: groups
AllowDangerousSettings: "Yes I know this is bad idea"
passwords:
  # Эталон умеет только {SSHA}; наш сервер по умолчанию его не принимает, и это правильно.
  AllowWeakHashes: "Yes I know this is bad idea"
  AllowedWeakHashes: "ssha"
  upgrade_on_bind: false
bind:
  AllowUnencryptedBind: "Yes I know this is bad idea"
schema:
  mode: off
access:
  - subject: admin
    attributes: ["*"]
    rights: [read, search, compare, auth, write]
  - subject: anonymous
    attributes: ["*"]
    rights: [read, search, compare]
"""


def normalize(text: str) -> list[str]:
    """Записи как множества строк: порядок записей и атрибутов — не поведение."""
    entries = []
    current = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if not line.strip():
            if current:
                entries.append(current)
                current = []
            continue
        if line.startswith("dn:") and current:
            entries.append(current)
            current = []
        current.append(line.rstrip())
    if current:
        entries.append(current)
    return sorted("\n".join(sorted(entry)) for entry in entries)


def ask(url: str, args: list[str]) -> tuple[list[str], str]:
    result = subprocess.run(
        ["ldapsearch", "-x", "-LLL", "-H", url, "-D", BIND_DN, "-w", BIND_PW, *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return normalize(result.stdout), result.stderr.strip()


def wait_for(url: str, seconds: float = 20.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        result = subprocess.run(
            ["ldapsearch", "-x", "-LLL", "-H", url, "-D", BIND_DN, "-w", BIND_PW,
             "-b", BASE_DN, "-s", "base", "(objectClass=*)"],
            capture_output=True,
        )
        if result.returncode == 0:
            return True
        time.sleep(0.3)
    return False


def start(reference: Path, work: Path, rust_binary: Path) -> tuple[subprocess.Popen, subprocess.Popen]:
    users = work / "users.json"
    groups = work / "groups.json"
    shutil.copy(reference / "examples" / "file" / "users.json", users)
    shutil.copy(reference / "examples" / "file" / "groups.json", groups)

    go_config = work / "go.yaml"
    go_config.write_text(
        GO_CONFIG.format(
            backends=reference / "build" / "backends", users=users, groups=groups
        )
    )
    rust_config = work / "rust.yaml"
    rust_config.write_text(
        RUST_CONFIG.format(
            base=BASE_DN, listen="127.0.0.1:11801", users=users, groups=groups
        )
    )

    go = subprocess.Popen(
        [str(reference / "build" / "gorestldap"), "-b", "file", "-c", str(go_config),
         "-B", BASE_DN, "-L", "127.0.0.1:11800"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    rust = subprocess.Popen(
        [str(rust_binary), "-c", str(rust_config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return go, rust


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-ref", type=Path, help="checkout gorestldap с собранным build/")
    parser.add_argument("--go-url", default="ldap://127.0.0.1:11800")
    parser.add_argument("--rust-url", default="ldap://127.0.0.1:11801")
    parser.add_argument("--rust-binary", type=Path, default=Path("./rust-rest-ldap"))
    args = parser.parse_args()

    servers = ()
    work = None
    if args.go_ref:
        work = Path(tempfile.mkdtemp(prefix="parity-"))
        servers = start(args.go_ref, work, args.rust_binary)

    try:
        if servers:
            for url in (args.go_url, args.rust_url):
                if not wait_for(url):
                    print(f"сервер {url} не поднялся", file=sys.stderr)
                    return 2

        failures = []
        print(f"{'случай':34} {'вердикт':9} что")
        for case in CASES:
            go, go_err = ask(args.go_url, case.args)
            rust, rust_err = ask(args.rust_url, case.args)
            matched = go == rust

            if matched and case.verdict == "same":
                print(f"{case.name:34} совпало")
            elif not matched and case.verdict == "same":
                print(f"{case.name:34} РАСХОЖДЕНИЕ")
                print(f"  gorestldap: {go or go_err}")
                print(f"  rust:       {rust or rust_err}")
                failures.append(f"{case.name}: ответы разошлись, а должны совпадать")
            elif matched and case.verdict == "better":
                print(f"{case.name:34} совпало (ожидалось расхождение)")
                failures.append(
                    f"{case.name}: расхождение исчезло — обновите запись о нём"
                )
            else:
                print(f"{case.name:34} отличается, как записано")
                print(f"  почему: {case.reason}")
            if case.verdict == "TODO":
                failures.append(f"{case.name}: расхождение не объяснено")

        print()
        if failures:
            for failure in failures:
                print(f"ПРОВАЛ: {failure}", file=sys.stderr)
            return 1
        print(f"все {len(CASES)} случаев объяснены")
        return 0
    finally:
        for server in servers:
            server.terminate()
        for server in servers:
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        if work:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
