#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генератор списка российских IPv4-сетей для MikroTik RouterOS.

Источник: официальный delegated-файл RIPE NCC (обновляется ежедневно).
Выход: два файла, совместимых со схемой awg-proxy:
  - ru_ranges_timeout.rsc  (записи с timeout=30d — для роутеров с scheduler)
  - ru_ranges.rsc          (постоянные записи — fallback)

Защита от мусора на входе: если число записей или суммарное покрытие
выходит за ожидаемые пределы, скрипт падает с ошибкой и НЕ трогает
старые файлы (роутер продолжит использовать предыдущую версию).
"""

import ipaddress
import os
import re
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone

DELEGATED_URL = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"
TIMEOUT_SECONDS = 60

# Контрольные пределы (по состоянию на 2026: ~8.7k сетей, ~45.3M IP).
MIN_NETWORKS, MAX_NETWORKS = 7000, 15000
MIN_IPS, MAX_IPS = 40_000_000, 60_000_000

ENTRY_TIMEOUT = 2592000  # 30 дней, как в оригинальной схеме
LIST_NAME = "RU"
ENTRY_COMMENT = "RIPE-RU"

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def download(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ru-ranges-generator/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def parse_ru_ipv4(text: str):
    nets = []
    for line in text.splitlines():
        p = line.strip().split("|")
        # формат: ripencc|RU|ipv4|2.56.24.0|1024|19960701|allocated
        if len(p) >= 5 and p[1] == "RU" and p[2] == "ipv4":
            try:
                start = int(ipaddress.IPv4Address(p[3]))
                count = int(p[4])
            except ValueError:
                continue
            if count <= 0:
                continue
            first = ipaddress.IPv4Address(start)
            last = ipaddress.IPv4Address(start + count - 1)
            nets.extend(ipaddress.summarize_address_range(first, last))
    return nets


def write_rsc(networks, path: str, entry_timeout: int | None):
    # атомарная запись: сначала временный файл, потом переименование
    fd, tmp = tempfile.mkstemp(dir=OUT_DIR, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        for n in networks:
            line = f"/ip firewall address-list add list={LIST_NAME} address={n} comment={ENTRY_COMMENT}"
            if entry_timeout:
                line += f" timeout={entry_timeout}"
            f.write(line + "\n")
    os.replace(tmp, path)


def main():
    print(f"Скачиваю {DELEGATED_URL} ...")
    text = download(DELEGATED_URL)

    raw = parse_ru_ipv4(text)
    if not raw:
        sys.exit("ОШИБКА: в файле RIPE не найдено ни одной записи RU/ipv4 — источник недоступен или изменил формат.")

    collapsed = sorted(ipaddress.collapse_addresses(raw), key=lambda n: (int(n.network_address), n.prefixlen))
    total_ips = sum(n.num_addresses for n in collapsed)

    print(f"Сырых CIDR-блоков из RIPE: {len(raw)}")
    print(f"После агрегации:           {len(collapsed)}")
    print(f"Покрытие:                  {total_ips:,} IP")

    if not (MIN_NETWORKS <= len(collapsed) <= MAX_NETWORKS):
        sys.exit(f"ОШИБКА: {len(collapsed)} сетей вне пределов {MIN_NETWORKS}..{MAX_NETWORKS} — отмена, старые файлы сохранены.")
    if not (MIN_IPS <= total_ips <= MAX_IPS):
        sys.exit(f"ОШИБКА: покрытие {total_ips:,} IP вне пределов — отмена, старые файлы сохранены.")

    out_timeout = os.path.join(OUT_DIR, "ru_ranges_timeout.rsc")
    out_perm = os.path.join(OUT_DIR, "ru_ranges.rsc")
    out_stats = os.path.join(OUT_DIR, "ru_ranges_stats.txt")

    # diff против предыдущей версии (до перезаписи файлов!)
    prev = set()
    if os.path.exists(out_perm):
        with open(out_perm, encoding="utf-8") as f:
            for line in f:
                m = re.search(r"address=([\d./]+)", line)
                if m:
                    prev.add(m.group(1))
    current = {str(n) for n in collapsed}
    added = current - prev
    removed = prev - current
    if prev:
        print(f"Изменения: +{len(added)} / -{len(removed)}")
    else:
        print("Предыдущая версия не найдена — первая сборка")

    write_rsc(collapsed, out_timeout, ENTRY_TIMEOUT)
    write_rsc(collapsed, out_perm, None)

    # компактный файл статистики: роутер скачает его и напишет в лог
    fd, tmp = tempfile.mkstemp(dir=OUT_DIR, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"date={datetime.now(timezone.utc):%Y-%m-%d} total={len(current)} added={len(added)} removed={len(removed)}\n")
    os.replace(tmp, out_stats)

    for p in (out_timeout, out_perm, out_stats):
        print(f"Готово: {p} ({os.path.getsize(p) / 1024:.0f} КБ)")


if __name__ == "__main__":
    main()
