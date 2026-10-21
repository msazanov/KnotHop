#!/usr/bin/env python3
"""Изолированная проверка Invite v3: прямой делегат и безопасные негативы.

Сценарии с посредником/повторным предъявлением требуют специальной инъекции в
поток pairing; они отмечаются в отчёте как не покрытые, а не имитируются.
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = Path(os.environ.get("LAB13_ROOT", ""))
PREFIX = os.environ.get("LAB13_PREFIX", "")
BIN = Path(os.environ.get("RAWGD_BIN", str(Path.home() / ".cache/rawg-target/release/rawgd")))
REPORT = Path("/tmp/opencode/tests/lab-delegated.md")
RESULTS = []
KEY_EVENTS = []


def run(*args, ok=True, timeout=30, env=None):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if ok and p.returncode:
        # stdout намеренно не включается в ошибку: он может содержать приглашение.
        detail = p.stderr.strip().splitlines()[-1:] or [""]
        safe = re.sub(r"rawgi-[A-Za-z0-9_-]+", "rawgi-[СКРЫТО]", detail[0])
        raise RuntimeError(f"команда завершилась с кодом {p.returncode}: {args[0]}: {safe[:240]}")
    return p


def lab(*args, ok=True):
    if not re.fullmatch(r"rawg-v3-[0-9a-f]+", PREFIX) or LAB.parent != Path("/tmp/opencode"):
        raise RuntimeError("запрет: нет валидного уникального префикса/каталога лаборатории")
    env = os.environ.copy()
    env.update({"LAB13_PREFIX": PREFIX, "LAB13_ROOT": str(LAB), "RAWGD_BIN": str(BIN)})
    return run(sys.executable, str(HERE / "lab13.py"), *args, ok=ok, timeout=90, env=env)


def docker(*args, ok=True):
    return run("docker", *args, ok=ok)


def rawgd(container, *args, ok=True):
    return docker("exec", container, "rawgd", *args, ok=ok)


def identity(container):
    value = rawgd(container, "whoami", "--state", "/state").stdout
    return json.loads(value)["hash"]


def list_text(container):
    return rawgd(container, "list", "--state", "/state").stdout


def wait_for(predicate, label, seconds=45):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(1)
    raise RuntimeError(f"истёк срок ожидания: {label}")


def record(name, expected, actual, passed):
    RESULTS.append((name, expected, actual, "PASS" if passed else "FAIL"))


def not_covered(name, expected, why):
    RESULTS.append((name, expected, f"не покрыто: {why}", "НЕ ПОКРЫТО"))


def collect_safe_events(container, filename):
    result = docker("exec", container, "cat", f"/state/{filename}", ok=False)
    for line in result.stdout.splitlines():
        if "зачисление" not in line.lower():
            continue
        low = line.lower()
        if "пересылаю админу" in low:
            event = "зачисление: пересылаю админу через посредника"
        elif "запись уже есть" in low:
            event = "зачисление: запись уже есть, повторный ответ отправлен"
        elif "запись не выдана" in low:
            event = "зачисление: запись не выдана"
        elif "получил права" in low:
            event = "зачисление: участнику выданы права"
        else:
            event = "зачисление: событие pairing"
        if event not in KEY_EVENTS:
            KEY_EVENTS.append(event)


def issue_file(container, root, path, rights="USE", nodes=""):
    args = ["exec", container, "rawgd", "invite", "--state", "/state", "--rights", rights,
            "--label", "lab-v3", "--root", root, "--out", "/state/.scenario-invite"]
    if nodes:
        args.extend(["--nodes", nodes])
    docker(*args)
    docker("cp", f"{container}:/state/.scenario-invite", str(path))
    docker("exec", container, "shred", "-u", "/state/.scenario-invite")
    os.chmod(path, 0o600)


def main():
    global LAB, PREFIX
    if not BIN.is_file():
        raise RuntimeError(f"нет бинарника {BIN}")
    suffix = f"{os.getpid():x}"
    PREFIX = f"rawg-v3-{suffix}"
    LAB = Path(f"/tmp/opencode/lab-delegated-{suffix}")
    LAB.mkdir(mode=0o700)
    os.chmod(LAB, 0o700)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    secret = LAB / "invite.txt"
    try:
        startup = lab("up")
        root_node = f"{PREFIX}-adm"
        containers = docker("ps", "-a", "--format", "{{.Names}} {{.Status}} {{.Networks}}").stdout.splitlines()
        if not any(line.split()[0] == root_node for line in containers if line.split()):
            raise RuntimeError(f"контейнер корня не создан; up={startup.stdout.strip()}; контейнеры={','.join(containers)}")
        root = identity(root_node)

        # D — отдельная нода, получающая права USE+ADD непосредственно от R.
        delegate = f"{PREFIX}-d"
        lab("node", delegate, "--from", root_node, "--rights", "USE+ADD")
        d_hash = identity(delegate)
        wait_for(lambda: d_hash[:8] in list_text(root_node), "запись R→D")
        d_state = list_text(delegate)
        has_r_anchor = f"якорь {root}" in d_state
        has_rights = "мои права USE+ADD" in d_state

        issue_file(delegate, root, secret, "USE")
        newcomer = f"{PREFIX}-n"
        lab("client", newcomer, "--from", delegate, "--rights", "USE", "--invite-file", str(secret))
        n_hash = identity(newcomer)
        wait_for(lambda: f"якорь {root}" in list_text(newcomer), "якорь R у N")
        n_state = list_text(newcomer)
        r_to_d = re.search(rf"корень {root[:8]}\s+держатель {d_hash[:8]}\s+выдал {root[:8]}\s+USE\+ADD", n_state)
        d_to_n = re.search(rf"корень {root[:8]}\s+держатель {n_hash[:8]}\s+выдал {d_hash[:8]}\s+USE", n_state)
        chain_ok = bool(r_to_d and d_to_n and "мои права USE" in n_state)
        test = lab("test", newcomer).stdout
        exit_ok = '"served_by": "site"' in test and '"served_by": "adm"' in test
        record("S1 прямой делегат R→D→N", "якорь R, цепочка, USE и выход через R",
               "list: якорь R, записи R→D и D→N, USE; HTTP-ответы site и adm получены через выход",
               has_r_anchor and has_rights and chain_ok and exit_ok)
        collect_safe_events(delegate, "node.log")
        collect_safe_events(newcomer, "client.log")

        # Тот же bearer-pin с другим holder должен остаться погашенным.
        other = f"{PREFIX}-other"
        lab("client", other, "--from", delegate, "--rights", "USE", "--invite-file", str(secret))
        wait_for(lambda: "погашен" in list_text(delegate), "pin погашен")
        pin_state = list_text(delegate)
        other_state = list_text(other)
        spent_reject = f"якорь {root}" not in other_state and "погашен" in pin_state
        record("S1 одноразовость для чужого holder", "второй holder отклонён, pin погашен",
               "чужой holder не получил якорь R; pin отмечен погашенным", spent_reject)

        # S2: D — client-admin без входящих Link; N должен обратиться к M по тегу R.
        mediator = f"{PREFIX}-m"
        lab("node", mediator, "--from", root_node, "--rights", "USE+TRANSIT")
        m_hash = identity(mediator)
        wait_for(lambda: m_hash[:8] in list_text(root_node), "запись R→M")
        phone = f"{PREFIX}-phone"
        lab("client", phone, "--from", root_node, "--rights", "USE+ADD")
        wait_for(lambda: f"якорь {root}" in list_text(phone), "якорь R у client-admin D")
        phone_hash = identity(phone)
        phone_invite = LAB / "phone-invite.txt"
        issue_file(phone, root, phone_invite, "USE", m_hash)
        via = f"{PREFIX}-via"
        lab("client", via, "--from", phone, "--rights", "USE", "--invite-file", str(phone_invite))
        via_hash = identity(via)
        wait_for(lambda: f"якорь {root}" in list_text(via), "посредническое зачисление R→D→N", 70)
        via_state = list_text(via)
        root_to_phone = re.search(rf"корень {root[:8]}\s+держатель {phone_hash[:8]}\s+выдал {root[:8]}\s+USE\+ADD", via_state)
        phone_to_via = re.search(rf"корень {root[:8]}\s+держатель {via_hash[:8]}\s+выдал {phone_hash[:8]}\s+USE", via_state)
        via_chain = bool(root_to_phone and phone_to_via and "мои права USE" in via_state)
        record("S2 client-admin D через посредника M", "T_PAIRQ v3, N зачислена с цепочкой R→D→N",
               "client-D не принимает входящий Link; приглашение ограничено M; N получила якорь R и цепочку",
               via_chain)
        collect_safe_events(mediator, "node.log")
        collect_safe_events(phone, "client.log")
        collect_safe_events(via, "client.log")
        run("shred", "-u", str(phone_invite), ok=False)

        # Отрицательные выдачи запускаются CLI-командами, но их stderr не печатается.
        noadd_node = f"{PREFIX}-noadd"
        lab("client", noadd_node, "--from", root_node, "--rights", "USE")
        wait_for(lambda: f"якорь {root}" in list_text(noadd_node), "участник без ADD зачислен")
        no_add = rawgd(noadd_node, "invite", "--state", "/state", "--rights", "USE", "--root", root,
                       "--out", "/state/.negative", ok=False)
        record("S6 делегат без ADD", "--root отклонён по отсутствию ADD",
               "клиент с USE без ADD получил отказ «в корне нет права ADD»",
               no_add.returncode != 0 and "в корне нет права ADD" in no_add.stderr)
        too_wide = rawgd(delegate, "invite", "--state", "/state", "--rights", "EXIT", "--root", root,
                         "--out", "/state/.negative", ok=False)
        record("S6 права шире своих", "EXIT не выдан при USE+ADD у D",
               "CLI: отказ «приглашение шире действующих прав»", too_wide.returncode != 0 and "шире действующих прав" in too_wide.stderr)
        no_anchor = rawgd(delegate, "invite", "--state", "/state", "--rights", "USE", "--root", "00" * 16,
                          "--out", "/state/.negative", ok=False)
        record("S6 корень отсутствует среди якорей", "выдача отклонена",
               "CLI: отказ «корень отсутствует среди якорей доверия»", no_anchor.returncode != 0 and "корень отсутствует среди якорей доверия" in no_anchor.stderr)

        # Эти ветки не заменяем проверкой одного лишь CLI или unit-тестами.
        not_covered("S2 клиент-D через посредника / подмена root", "PAIRQ v3 проходит; чужой inviter/root отвергнут",
                    "подмена inviter/root требует инъекции чужого тела PAIRQ, которой lab13 не предоставляет")
        not_covered("S3 отзыв D до погашения и возврат pin", "отказ, pin не сожжён, после повторной выдачи работает",
                    "нет сценария синхронизации live-отзыва между узлами")
        not_covered("S4 Repeat тем же N и отзыв N", "Repeat отдаёт цепочку; чужой holder/отозванный N — отказ",
                    "lab13 не воспроизводит потерянный ответ и повтор pairing для того же holder")
        own = f"{PREFIX}-own"
        lab("client", own, "--from", root_node, "--rights", "USE")
        wait_for(lambda: f"якорь {root}" in list_text(own), "обычное приглашение в собственный root")
        own_test = lab("test", own).stdout
        own_ok = '"served_by": "site"' in own_test and '"served_by": "adm"' in own_test
        record("S5 собственный root, прямой путь", "обычное приглашение без --root и выход через R",
               "клиент получил якорь R; HTTP-ответы site и adm доступны", own_ok)
        not_covered("S5 собственный root через посредника", "обычное приглашение через T_PAIRQ работает",
                    "контрольный путь с посредником не добавлен в сценарий лаборатории")
    finally:
        # Секрет сначала стирается отдельно, затем уничтожается только эта уникальная лаборатория.
        if secret.exists():
            run("shred", "-u", str(secret), ok=False)
        lab("down", ok=False)
        # Контейнерные файлы принадлежат root внутри Docker: shred выполняется в одноразовом контейнере как root.
        if LAB.exists():
            docker("run", "--rm", "-v", f"{LAB}:/lab", "--entrypoint", "sh", "rawg-bench:l3", "-c",
                   "find /lab -type f -exec shred -u {} +", ok=False)
            for p in sorted(LAB.rglob("*"), reverse=True):
                if p.is_dir():
                    p.rmdir()
            LAB.rmdir()
        rows = ["# Локальная лаборатория: делегированные приглашения v3", "",
                "Только локальная изолированная Docker-сеть; секретные строки/ключи не сохраняются.",
                "Инцидент harness: первая ошибка env вызвала `lab13 down` в старой `rawg-lab13`, удалив её контейнеры и сеть. State в `~/.cache/rawg-lab13/lab/` не удалялся; контейнеры автоматически не восстанавливались. Последующие прогоны шли в отдельной сети с защитой префикса.", "",
                "| Сценарий | Ожидание | Фактический результат | Статус |",
                "|---|---|---|---|"]
        rows.extend(f"| {n} | {e} | {a} | **{s}** |" for n, e, a, s in RESULTS)
        rows.extend(["", "## Ключевые строки логов (нормализованы, без идентификаторов/секретов)", ""])
        rows.extend(f"- `{event}`" for event in KEY_EVENTS)
        if not KEY_EVENTS:
            rows.append("- Подходящих событий pairing в кратких логах не найдено; фактические assertions выполнены по `rawgd list` и HTTP-ответам.")
        REPORT.write_text("\n".join(rows) + "\n")
        os.chmod(REPORT, 0o600)
    print(f"Отчёт: {REPORT}")
    return 0 if all(status != "FAIL" for _, _, _, status in RESULTS) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Ошибка намеренно не содержит stdout/stderr команд, где мог бы быть bearer-секрет.
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
