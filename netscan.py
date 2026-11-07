#!/usr/bin/env python3
"""
netscan - pequeno scanner e monitor de rede, só com a biblioteca standard do Python.

Comandos:
  discover  Descobre os hosts ativos numa rede (ping sweep).
  ports     Testa portas TCP abertas num host.
  monitor   Faz ping periódico a uma lista de hosts e regista quando caem/voltam.

Usar apenas em redes próprias ou com autorização.
Autor: Guilherme Martins (github.com/gui198gui)
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import platform
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime

# Portas mais comuns e o serviço habitual de cada uma
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-alt",
}

IS_WINDOWS = platform.system().lower() == "windows"


# --------------------------------------------------------------------------- #
# Utilitários
# --------------------------------------------------------------------------- #
def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_ports(spec: str) -> list[int]:
    """Converte '22,80,8000-8010' numa lista ordenada de portas."""
    if spec.strip().lower() == "common":
        return sorted(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"Portas inválidas: {invalid}")
    return sorted(ports)


def hosts_in_network(cidr: str, limit: int = 4096) -> list[str]:
    """Lista os endereços utilizáveis de uma rede (ex: 192.168.1.0/24)."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > limit + 2:
        raise ValueError(
            f"A rede {net} tem {net.num_addresses} endereços; o limite é {limit}. "
            "Usa uma máscara mais pequena (ex: /24)."
        )
    hosts = [str(h) for h in net.hosts()]
    return hosts or [str(net.network_address)]


def ping(host: str, timeout: float = 1.0) -> float | None:
    """Faz um ping e devolve o tempo em ms, ou None se não houver resposta."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    start = time.perf_counter()
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout + 2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    elapsed = (time.perf_counter() - start) * 1000
    # No Windows o código de saída pode ser 0 com "Destination host unreachable"
    if result.returncode != 0 or (IS_WINDOWS and "TTL=" not in result.stdout.upper()):
        return None
    return round(elapsed, 1)


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def check_port(host: str, port: int, timeout: float = 0.8) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


# --------------------------------------------------------------------------- #
# Resultados
# --------------------------------------------------------------------------- #
@dataclass
class HostResult:
    ip: str
    latency_ms: float | None
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)


def export(results: list[HostResult], path: str) -> None:
    """Exporta os resultados para .json ou .csv, conforme a extensão."""
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
    elif path.lower().endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "hostname", "latency_ms", "open_ports"])
            for r in results:
                w.writerow([r.ip, r.hostname, r.latency_ms,
                            " ".join(map(str, r.open_ports))])
    else:
        raise ValueError("O ficheiro de saída tem de acabar em .json ou .csv")
    print(f"\nResultados guardados em {path}")


# --------------------------------------------------------------------------- #
# Comandos
# --------------------------------------------------------------------------- #
def cmd_discover(args: argparse.Namespace) -> int:
    hosts = hosts_in_network(args.network)
    print(f"[{now()}] A procurar hosts ativos em {args.network} "
          f"({len(hosts)} endereços, {args.workers} threads)...\n")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        latencies = list(pool.map(lambda h: ping(h, args.timeout), hosts))

    alive = [HostResult(ip, lat) for ip, lat in zip(hosts, latencies) if lat is not None]

    if args.resolve and alive:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for r, name in zip(alive, pool.map(reverse_dns, [r.ip for r in alive])):
                r.hostname = name

    if args.ports and alive:
        ports = parse_ports(args.ports)
        for r in alive:
            r.open_ports = scan_ports(r.ip, ports, args.workers, args.timeout)

    print(f"{'IP':<16} {'Latência':>10}  {'Hostname':<30} Portas abertas")
    print("-" * 80)
    for r in alive:
        ports_txt = ", ".join(f"{p}/{COMMON_PORTS.get(p, '?')}" for p in r.open_ports)
        print(f"{r.ip:<16} {str(r.latency_ms) + ' ms':>10}  {r.hostname[:30]:<30} {ports_txt}")
    print(f"\n{len(alive)} host(s) ativo(s) de {len(hosts)}.")

    if args.output:
        export(alive, args.output)
    return 0


def scan_ports(host: str, ports: list[int], workers: int, timeout: float) -> list[int]:
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        states = list(pool.map(lambda p: check_port(host, p, timeout), ports))
    return [p for p, is_open in zip(ports, states) if is_open]


def cmd_ports(args: argparse.Namespace) -> int:
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Não foi possível resolver '{args.host}'.", file=sys.stderr)
        return 1
    ports = parse_ports(args.ports)
    print(f"[{now()}] A testar {len(ports)} porta(s) TCP em {args.host} ({ip})...\n")
    open_ports = scan_ports(ip, ports, args.workers, args.timeout)

    if open_ports:
        print(f"{'Porta':<8} {'Estado':<8} Serviço")
        print("-" * 32)
        for p in open_ports:
            print(f"{p:<8} {'aberta':<8} {COMMON_PORTS.get(p, '?')}")
    print(f"\n{len(open_ports)} porta(s) aberta(s) de {len(ports)} testadas.")

    if args.output:
        export([HostResult(ip, None, args.host, open_ports)], args.output)
    return 0


def read_hosts(args: argparse.Namespace) -> list[str]:
    hosts = list(args.hosts or [])
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    hosts.append(line)
    return hosts


def cmd_monitor(args: argparse.Namespace) -> int:
    hosts = read_hosts(args)
    if not hosts:
        print("Indica hosts (ex: monitor 8.8.8.8 192.168.1.1) ou um ficheiro com -f.",
              file=sys.stderr)
        return 1

    state: dict[str, bool | None] = {h: None for h in hosts}
    log = open(args.log, "a", newline="", encoding="utf-8") if args.log else None
    writer = csv.writer(log) if log else None
    if log and log.tell() == 0:
        writer.writerow(["timestamp", "host", "estado", "latencia_ms"])

    print(f"[{now()}] A monitorizar {len(hosts)} host(s) a cada {args.interval}s. "
          "Ctrl+C para parar.\n")
    rounds = 0
    try:
        while True:
            with ThreadPoolExecutor(max_workers=min(32, len(hosts))) as pool:
                results = list(pool.map(lambda h: ping(h, args.timeout), hosts))
            for host, lat in zip(hosts, results):
                up = lat is not None
                if state[host] is None or state[host] != up:
                    label = "UP  " if up else "DOWN"
                    extra = f" ({lat} ms)" if up else ""
                    change = "" if state[host] is None else "  <-- mudou de estado"
                    print(f"[{now()}] {label} {host}{extra}{change}")
                    if writer:
                        writer.writerow([now(), host, "UP" if up else "DOWN", lat or ""])
                        log.flush()
                state[host] = up
            rounds += 1
            if args.count and rounds >= args.count:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitorização terminada.")
    finally:
        if log:
            log.close()
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscan",
        description="Scanner e monitor de rede simples (Python standard library).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="descobrir hosts ativos numa rede")
    d.add_argument("network", help="rede em notação CIDR, ex: 192.168.1.0/24")
    d.add_argument("-p", "--ports", help="também testar portas: 'common' ou '22,80,443'")
    d.add_argument("-r", "--resolve", action="store_true", help="resolver hostnames (DNS reverso)")
    d.add_argument("-w", "--workers", type=int, default=64, help="threads em paralelo (64)")
    d.add_argument("-t", "--timeout", type=float, default=1.0, help="timeout em segundos (1.0)")
    d.add_argument("-o", "--output", help="guardar em .json ou .csv")
    d.set_defaults(func=cmd_discover)

    pt = sub.add_parser("ports", help="testar portas TCP num host")
    pt.add_argument("host", help="IP ou nome do host")
    pt.add_argument("-p", "--ports", default="common", help="'common' (omissão) ou '1-1024,8080'")
    pt.add_argument("-w", "--workers", type=int, default=100, help="threads em paralelo (100)")
    pt.add_argument("-t", "--timeout", type=float, default=0.8, help="timeout em segundos (0.8)")
    pt.add_argument("-o", "--output", help="guardar em .json ou .csv")
    pt.set_defaults(func=cmd_ports)

    m = sub.add_parser("monitor", help="monitorizar hosts e registar quedas")
    m.add_argument("hosts", nargs="*", help="hosts a monitorizar")
    m.add_argument("-f", "--file", help="ficheiro com um host por linha")
    m.add_argument("-i", "--interval", type=float, default=10, help="segundos entre rondas (10)")
    m.add_argument("-t", "--timeout", type=float, default=1.0, help="timeout do ping (1.0)")
    m.add_argument("-l", "--log", help="ficheiro CSV onde registar as mudanças de estado")
    m.add_argument("-c", "--count", type=int, default=0, help="nº de rondas (0 = infinito)")
    m.set_defaults(func=cmd_monitor)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in ("discover", "monitor") and shutil.which("ping") is None:
        print("Erro: o comando 'ping' não foi encontrado no sistema.", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except ValueError as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
