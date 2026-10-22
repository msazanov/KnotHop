#!/usr/bin/env python3
"""Create and audit a sanitized, build-preserving public copy."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IP_RE = re.compile(r"(?<![\w.])(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?P<prefix>/\d{1,2})?(?![\w.])")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
BRAND = "big" + "ping"
BRAND_RE = re.compile(rf"(?i)\b{BRAND}\b")
DOMAIN_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9-]+\.)*(?:duckdns\.org|ddns\.net)(?![\w.-])")
HOME_RE = re.compile(r"/home/[A-Za-z0-9._-]+")
SERIAL_RE = re.compile(r"\b[A-Z]{4}\d{12}\b")
HOST_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![\w.-])")

KNOWN_PUBLIC_SERVICES = {
    "1.0.0.1", "1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9",
    "149.112.112.112", "208.67.220.220", "208.67.222.222",
    "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0",
}
DOC_NET = ipaddress.ip_network("203.0.113.0/24")
CODE_SUFFIXES = {
    ".rs", ".java", ".py", ".sh", ".nft", ".toml", ".xml", ".service",
    ".gradle", ".json", ".yml", ".yaml", ".properties", ".cfg", ".conf",
    ".ini", ".lock", ".mk", ".c", ".h", ".cpp", ".js", ".kt", ".go",
}
EXACT_EXCLUDES = {
    "AGENTS.md", "bench/AWG.md", "bench/Dockerfile.awg", "deploy/hosts.tsv",
    "deploy/push-report.json", "deploy-pilot", "deploy-0013/node.json",
    "deploy-0013/public_rns.txt", "deploy-0013/SHA256SUMS",
    "docs/experiments-log.md", "docs/benchmarks-1core.md",
    "docs/benchmarks-lev-iroh.md", "docs/README.md", "docs/development.md",
    "deploy/README.md", "bench/android/exits.txt",
}
EXCLUDED_DIRS = {
    ".git", ".codegraph", ".beads", "target", "__pycache__", ".pytest_cache",
    "results", "results-raw", "dist", "state", "reviews", "archive", "decisions",
}
EXCLUDED_SUFFIXES = {".apk", ".aab", ".whl", ".pyc", ".keystore", ".jks", ".p12", ".pem", ".key", ".log"}


def text_or_none(path: Path) -> str | None:
    try:
        data = path.read_bytes()
        if b"\0" in data[:4096]:
            return None
        return data.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def whitelist(source: Path) -> tuple[set[str], set[str]]:
    ips: set[str] = set()
    hosts: set[str] = set()
    path = source / "deploy" / "public-rns-whitelist.txt"
    if not path.is_file():
        return ips, hosts
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = raw.split("#", 1)[0].strip().lower()
        if not value:
            continue
        try:
            ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            hosts.add(value)
    return ips, hosts


def should_exclude(rel: Path) -> bool:
    name = rel.as_posix()
    if name in EXACT_EXCLUDES or any(name.startswith(x + "/") for x in EXACT_EXCLUDES if "/" not in x):
        return True
    if any(part in EXCLUDED_DIRS for part in rel.parts) or rel.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    if rel.name in {"identity.key", "group.key", "trust.json", "node.json", "known_hosts"}:
        return True
    if rel.name.startswith("invite") or rel.name.endswith(".profile"):
        return True
    lower = rel.name.lower()
    if lower in {"awg.md", "dockerfile.awg", "benchmarks-awg.md"}:
        return True
    if rel.parts[:1] == ("bench",) and lower.startswith(("awg_", "awg-")):
        return True
    if name.startswith("bench/results") or name.startswith("deploy/dist/") or name.startswith("deploy-pilot/"):
        return True
    if name.startswith(("docs/reviews/", "docs/decisions/", "docs/archive/")):
        return True
    if rel.parts[:1] == ("bench",) and rel.suffix.lower() in {".md", ".rst"}:
        return True
    if name.startswith("deploy-0013/") and ".env." in rel.name:
        return True
    return False


def is_private_document(rel: Path) -> bool:
    name = rel.as_posix()
    return (
        name in EXACT_EXCLUDES
        or name == "AGENTS.md"
        or name.startswith(("docs/archive/", "docs/reviews/", "docs/decisions/"))
        or (rel.parts[:1] == ("bench",) and rel.suffix.lower() in {".md", ".rst"})
    )


def add_values(tokens: dict[str, set[str]], kind: str, values) -> None:
    bucket = tokens.setdefault(kind, set())
    bucket.update(v.strip() for v in values if v and v.strip())


def collect_private_tokens(source: Path, fork: Path | None = None) -> dict[str, set[str]]:
    """Build exact private identifiers in memory; never serialize or print token values."""
    tokens: dict[str, set[str]] = {}
    allowed_ips, allowed_hosts = whitelist(source)

    inventory = source / "deploy" / "hosts.tsv"
    if inventory.is_file():
        for raw in inventory.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            fields = raw.split("\t")
            for field in fields:
                value = field.strip()
                if not value or value.startswith("<"):
                    continue
                add_values(tokens, "inventory_ip", (m.group("ip") for m in IP_RE.finditer(value)))
                add_values(tokens, "email", EMAIL_RE.findall(value))
                add_values(tokens, "domain", DOMAIN_RE.findall(value))
                if "@" in value:
                    login, endpoint = value.rsplit("@", 1)
                    if login and login.lower() not in {"root", "user", "node"}:
                        add_values(tokens, "login", (login,))
                    add_values(tokens, "endpoint", (value,))
                    value = endpoint
                port_match = re.search(r":(\d{1,5})\s*$", value)
                if port_match and int(port_match.group(1)) <= 65535:
                    add_values(tokens, "port", (port_match.group(1),))
                host_value = re.sub(r":\d{1,5}\s*$", "", value)
                if host_value.startswith("[") and "]" in host_value:
                    host_value = host_value[1:host_value.index("]")]
                if host_value and host_value.lower() not in {"root", "user", "node"} and ("." in host_value or ":" in host_value):
                    add_values(tokens, "host", (host_value,))

    private_docs: list[Path] = []
    for path in source.rglob("*"):
        if not path.is_file() or not is_private_document(path.relative_to(source)):
            continue
        private_docs.append(path)
    for path in private_docs:
        text = text_or_none(path)
        if text is None:
            continue
        add_values(tokens, "email", EMAIL_RE.findall(text))
        add_values(tokens, "domain", DOMAIN_RE.findall(text))
        add_values(tokens, "home", HOME_RE.findall(text))
        add_values(tokens, "serial", SERIAL_RE.findall(text))
        for match in IP_RE.finditer(text):
            raw = match.group("ip")
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                continue
            # Public addresses in private reports are private identifiers; special-use,
            # documentation, whitelist and known public services remain untouched.
            if address.is_global and raw not in allowed_ips and raw not in KNOWN_PUBLIC_SERVICES:
                add_values(tokens, "public_ip", (raw,))

    # Remove globally public RNS transports and service endpoints from the private set.
    tokens.setdefault("public_ip", set()).difference_update(allowed_ips, KNOWN_PUBLIC_SERVICES)
    tokens.setdefault("host", set()).difference_update(allowed_hosts)
    return tokens


def is_legal_file(rel: Path) -> bool:
    name = rel.name.lower()
    return name in {"license", "copying", "notice", "notice-knotHop.md".lower()} or "license" in name


def replacement_for(kind: str, value: str) -> str:
    if kind in {"ip", "inventory_ip", "public_ip"}:
        address = ipaddress.ip_address(value)
        if address.is_global:
            # Keep tests and code paths that validate public/global addresses in the same class.
            return "1.1.1.1"
        classes = (
            (ipaddress.ip_network("10.0.0.0/8"), "10.254.254.254"),
            (ipaddress.ip_network("172.16.0.0/12"), "172.31.255.254"),
            (ipaddress.ip_network("192.168.0.0/16"), "192.168.254.254"),
            (ipaddress.ip_network("100.64.0.0/10"), "100.127.255.254"),
            (ipaddress.ip_network("198.18.0.0/15"), "198.19.255.254"),
            (ipaddress.ip_network("169.254.0.0/16"), "169.254.255.254"),
            (ipaddress.ip_network("127.0.0.0/8"), "127.0.0.2"),
        )
        for network, replacement in classes:
            if address in network:
                return replacement
        octet = 1 + hashlib.sha256(value.encode()).digest()[0] % 253
        return f"203.0.113.{octet}"
    if kind in {"host", "endpoint"}:
        return "node.invalid" if kind == "host" else "operator@node.invalid"
    if kind == "login":
        return "operator"
    if kind == "port":
        return "2222"
    if kind == "email":
        return "redacted@example.invalid"
    if kind == "domain":
        return "node.invalid"
    if kind == "home":
        return "~"
    if kind == "serial":
        return "TEST000000000000"
    return value


def _replace_exact(text: str, value: str, replacement: str, kind: str) -> str:
    if kind in {"ip", "inventory_ip", "public_ip"}:
        pattern = re.compile(rf"(?<![\w.]){re.escape(value)}(?![\w.])")
    elif kind == "port":
        pattern = re.compile(rf"(?<=:){re.escape(value)}(?!\d)")
    elif kind == "login":
        pattern = re.compile(rf"(?<![\w.-]){re.escape(value)}(?=@)")
    else:
        pattern = re.compile(rf"(?<![\w.-]){re.escape(value)}(?![\w.-])", re.IGNORECASE if kind in {"host", "domain"} else 0)
    return pattern.sub(replacement, text)


def sanitize_line(line: str, tokens: dict[str, set[str]]) -> str:
    # Brand removal is the only general lexical rule; all other replacements are exact tokens.
    order = ("endpoint", "email", "home", "serial", "public_ip", "inventory_ip", "ip", "domain", "host", "login", "port")
    result = line
    for kind in order:
        for value in sorted(tokens.get(kind, ()), key=len, reverse=True):
            if kind == "endpoint":
                # Replace the private endpoint as a unit before any component can be changed.
                result = _replace_exact(result, value, replacement_for(kind, value), "host")
            else:
                result = _replace_exact(result, value, replacement_for(kind, value), kind)
    return BRAND_RE.sub("KnotHop", result)


def sanitize_text(text: str, tokens: dict[str, set[str]], *, code: bool = False) -> str:
    # Code and configs are processed line-by-line: no neighboring syntax or identifiers change.
    return "".join(sanitize_line(line, tokens) for line in text.splitlines(keepends=True))


def is_code_config(rel: Path) -> bool:
    return rel.suffix.lower() in CODE_SUFFIXES or rel.name in {"Dockerfile", "Justfile", "Makefile"}


def line_has_private_token(line: str, tokens: dict[str, set[str]]) -> bool:
    if BRAND_RE.search(line):
        return True
    return sanitize_line(line, tokens) != line


def changed_source_line_count(before: str, after: str, tokens: dict[str, set[str]]) -> tuple[int, bool]:
    a, b = before.splitlines(), after.splitlines()
    if len(a) != len(b):
        return max(len(a), len(b)), False
    count = 0
    valid = True
    for source_line, output_line in zip(a, b):
        if source_line == output_line:
            continue
        count += 1
        if not line_has_private_token(source_line, tokens):
            valid = False
    return count, valid


def audit_pair(src: Path, dst: Path, rel: Path, tokens: dict[str, set[str]], report: dict[str, int]) -> bool:
    before = text_or_none(src)
    after = text_or_none(dst)
    if before is None or after is None or not is_code_config(rel):
        return True
    expected = sanitize_text(before, tokens, code=True)
    count, has_explicit_tokens = changed_source_line_count(before, after, tokens)
    if before != after:
        report[rel.as_posix()] = count
    return after == expected and has_explicit_tokens


def audit_tree(source: Path, destination: Path, tokens: dict[str, set[str]]) -> tuple[dict[str, int], bool]:
    report: dict[str, int] = {}
    valid = True
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(source)
        if should_exclude(rel):
            continue
        target = destination / rel
        if target.is_file() and is_code_config(rel):
            valid = audit_pair(path, target, rel, tokens, report) and valid
    return report, valid


def check_fork_pin(source: Path, fork: Path) -> str:
    """Форк должен стоять на коммите из deploy/leviculum.ref и без незакоммиченных правок.

    Публикуется ссылка на коммит, а не снимок дерева: иначе в KnotHop попало бы то, что не собрано в CI.
    """
    pin = (text_or_none(source / "deploy/leviculum.ref") or "").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", pin):
        raise SystemExit("deploy/leviculum.ref: нужен полный SHA-1 коммита форка")
    head = subprocess.run(["git", "-C", str(fork), "rev-parse", "HEAD"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout.strip()
    if head != pin:
        raise SystemExit("HEAD форка не совпадает с deploy/leviculum.ref: обновите ref или переключите форк")
    dirty = subprocess.run(["git", "-C", str(fork), "status", "--porcelain"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout.strip()
    if dirty:
        raise SystemExit("в форке есть незакоммиченные изменения: закоммитьте или уберите их, ref закрепляет только коммит")
    return pin


def create_notice(source: Path, fork: Path | None, destination: Path, tokens: dict[str, set[str]]) -> None:
    cargo_text = text_or_none(source / "bench/rns-iroh-node/Cargo.toml") or ""
    rev_match = re.search(r'leviculum-std\s*=\s*\{[^}]*rev\s*=\s*"([0-9a-f]{40})"', cargo_text)
    base = rev_match.group(1) if rev_match else "unknown"
    pin = (text_or_none(destination / "deploy/leviculum.ref") or "").strip() or "unknown"
    commits = ""
    if fork is not None and base != "unknown" and pin != "unknown":
        commits = subprocess.run(["git", "-C", str(fork), "log", "--oneline", f"{base}..{pin}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout.strip()
    listing = "".join(f"- {line}\n" for line in commits.splitlines()) or "- список не сформирован (нужен --leviculum-fork и база в истории форка)\n"
    text = (
        "# NOTICE для Leviculum (зависимость KnotHop)\n\n"
        "Первоисточник: https://codeberg.org/Lew_Palm/Leviculum (автор Lew_Palm).\n"
        f"Используется изменённый форк https://github.com/msazanov/leviculum на коммите `{pin}` (см. deploy/leviculum.ref).\n"
        f"База в Cargo.toml: `{base}`.\n"
        "Лицензия Leviculum и форка: AGPL-3.0-or-later; см. LICENSE.\n\n"
        "## Коммиты форка поверх базы\n\n" + listing
    )
    (destination / "NOTICE-KNOTHOP.md").write_text(sanitize_text(text, tokens), encoding="utf-8")


def sanitize(source: Path, destination: Path, fork: Path | None = None) -> dict[str, int]:
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_dir():
        raise SystemExit("исходный каталог не существует")
    if destination.exists():
        raise SystemExit("каталог назначения уже существует; выберите новый чистый путь")
    if fork is not None:
        check_fork_pin(source, fork)
    tokens = collect_private_tokens(source, fork)

    for path in source.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(source)
        if should_exclude(rel) or path.stat().st_size > 2 * 1024 * 1024:
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        text = text_or_none(path)
        if text is None:
            continue
        if is_legal_file(rel):
            output = text
        else:
            output = sanitize_text(text, tokens, code=is_code_config(rel))
        target.write_text(output, encoding="utf-8")
        if path.stat().st_mode & 0o111:
            target.chmod(target.stat().st_mode | 0o111)

    (destination / "README.md").write_text(
        "# KnotHop\n\n"
        "KnotHop — экспериментальный пилот IPv4-VPN поверх Reticulum. Он передаёт IP-пакеты; "
        "проект не является готовым публичным VPN.\n\n"
        "## Сборка и проверки\n\nСм. [docs/ci.md](docs/ci.md).\n\n"
        "## Происхождение и лицензии\n\n"
        "Leviculum: первоисточник — [Lew_Palm/Leviculum](https://codeberg.org/Lew_Palm/Leviculum); "
        "изменённый форк подключается по коммиту из `deploy/leviculum.ref` (github.com/msazanov/leviculum), "
        "лицензия AGPL-3.0-or-later; см. [NOTICE-KNOTHOP.md](NOTICE-KNOTHOP.md).\n\n"
        "Reticulum: [reticulum.network](https://reticulum.network). KnotHop распространяется по AGPL-3.0-or-later; см. [LICENSE](LICENSE).\n",
        encoding="utf-8",
    )
    (destination / "docs" / "README.md").write_text(
        "# Документация KnotHop\n\n- [Архитектура](architecture.md)\n- [Сборка, тесты и CI](ci.md)\n- `patches/` — исторические патчи.\n",
        encoding="utf-8",
    )

    # форк Leviculum в публикацию не вендорится: CI берёт его по коммиту из deploy/leviculum.ref
    create_notice(source, fork, destination, tokens)

    report, valid = audit_tree(source, destination, tokens)
    print("DIFF AUDIT (изменённые строки кода/конфигов):")
    if report:
        for name, count in sorted(report.items()):
            print(f"  {name}: {count}")
    else:
        print("  нет")
    if not valid:
        raise SystemExit("DIFF AUDIT FAILED: найдены изменения вне явного списка приватных идентификаторов")
    return report


def scan(tree: Path, source: Path, fork: Path | None = None) -> int:
    tokens = collect_private_tokens(source, fork)
    findings: dict[str, int] = {}
    for path in tree.rglob("*"):
        if not path.is_file():
            continue
        text = text_or_none(path)
        if text is None:
            continue
        hits = len(BRAND_RE.findall(text))
        # Exact locally-derived private values only. Public services, special-use ranges,
        # and ordinary identifiers are not findings.
        for kind, values in tokens.items():
            for value in values:
                if kind in {"ip", "inventory_ip", "public_ip"}:
                    hits += len(re.findall(rf"(?<![\w.]){re.escape(value)}(?![\w.])", text))
                elif kind == "port":
                    hits += len(re.findall(rf"(?<=:){re.escape(value)}(?!\d)", text))
                elif kind == "login":
                    hits += len(re.findall(rf"(?<![\w.-]){re.escape(value)}(?=@)", text))
                else:
                    hits += len(re.findall(rf"(?<![\w.-]){re.escape(value)}(?![\w.-])", text, re.IGNORECASE if kind in {"host", "domain"} else 0))
        if hits:
            findings[path.relative_to(tree).as_posix()] = hits
    for name, count in sorted(findings.items()):
        print(f"FINDING {name}: {count}")
    print(f"Сканирование: {len(findings)} файлов с находками; всего совпадений: {sum(findings.values())}")
    return 1 if findings else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--leviculum-fork", type=Path, default=None,
                        help="checkout форка: проверить, что HEAD совпадает с deploy/leviculum.ref и дерево чистое")
    args = parser.parse_args()
    if args.scan:
        return scan(args.destination.resolve(), args.source.resolve(), args.leviculum_fork)
    if args.audit_only:
        source, destination = args.source.resolve(), args.destination.resolve()
        tokens = collect_private_tokens(source, args.leviculum_fork)
        report, valid = audit_tree(source, destination, tokens)
        print("DIFF AUDIT (изменённые строки кода/конфигов):")
        for name, count in sorted(report.items()):
            print(f"  {name}: {count}")
        if not report:
            print("  нет")
        return 0 if valid else 1
    sanitize(args.source, args.destination, args.leviculum_fork)
    return scan(args.destination.resolve(), args.source.resolve(), args.leviculum_fork)


if __name__ == "__main__":
    sys.exit(main())
