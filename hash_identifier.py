#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║         Hash Identifier v1.0                 ║
║   Identificador de hashes por prefijo,       ║
║   longitud y juego de caracteres             ║
╚══════════════════════════════════════════════╝
"""

import argparse
import re
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

console = Console()

# ── Colores ───────────────────────────────────────────────────────────────────
COLOR_TITLE   = "bold magenta"
COLOR_INFO    = "bold cyan"
COLOR_OK      = "bold green"
COLOR_WARN    = "bold yellow"
COLOR_DANGER  = "bold red"
COLOR_DIM     = "dim white"

# ── Patrones de juego de caracteres ──────────────────────────────────────────
HEX     = re.compile(r"^[0-9a-fA-F]+$")
BASE64  = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
DECIMAL = re.compile(r"^[0-9]+$")

CHARSETS = {
    "hexadecimal": HEX,
    "base64":      BASE64,
    "decimal":     DECIMAL,
}

# ── Base de datos de hashes ───────────────────────────────────────────────────
HASH_DB = [
    {"name": "CRC32",                    "regex": r"^[0-9a-fA-F]{8}$",                                                              "hashcat": "11500",          "john": "crc32"},
    {"name": "MySQL323",                 "regex": r"^[0-9a-fA-F]{16}$",                                                             "hashcat": "200",            "john": "mysql"},
    {"name": "MD5 / NTLM / MD4",        "regex": r"^[0-9a-fA-F]{32}$",                                                             "hashcat": "0 / 1000 / 900", "john": "raw-md5 / nt / raw-md4"},
    {"name": "SHA1",                     "regex": r"^[0-9a-fA-F]{40}$",                                                             "hashcat": "100",            "john": "raw-sha1"},
    {"name": "MySQL 4.1+ (SHA1)",        "regex": r"^\*[0-9a-fA-F]{40}$",                                                           "hashcat": "300",            "john": "mysql-sha1"},
    {"name": "SHA224",                   "regex": r"^[0-9a-fA-F]{56}$",                                                             "hashcat": "1300",           "john": "raw-sha224"},
    {"name": "SHA256",                   "regex": r"^[0-9a-fA-F]{64}$",                                                             "hashcat": "1400",           "john": "raw-sha256"},
    {"name": "SHA384",                   "regex": r"^[0-9a-fA-F]{96}$",                                                             "hashcat": "10800",          "john": "raw-sha384"},
    {"name": "SHA512",                   "regex": r"^[0-9a-fA-F]{128}$",                                                            "hashcat": "1700",           "john": "raw-sha512"},
    {"name": "MD5 crypt (Unix)",         "regex": r"^\$1\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22}$",                                "hashcat": "500",            "john": "md5crypt"},
    {"name": "SHA256 crypt (Unix)",      "regex": r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$",                 "hashcat": "7400",           "john": "sha256crypt"},
    {"name": "SHA512 crypt (Unix)",      "regex": r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$",                 "hashcat": "1800",           "john": "sha512crypt"},
    {"name": "bcrypt",                   "regex": r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$",                                         "hashcat": "3200",           "john": "bcrypt"},
    {"name": "phpBB3 / WordPress",       "regex": r"^\$[HP]\$[./A-Za-z0-9]{31}$",                                                   "hashcat": "400",            "john": "phpass"},
    {"name": "Django PBKDF2-SHA256",     "regex": r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/]+={0,2}$",                    "hashcat": "10000",          "john": "django"},
    {"name": "LDAP SSHA",                "regex": r"^\{SSHA\}[A-Za-z0-9+/]+={0,2}$",                                               "hashcat": "111",            "john": "ssha"},
    {"name": "LDAP SHA1",                "regex": r"^\{SHA\}[A-Za-z0-9+/]+={0,2}$",                                                 "hashcat": "101",            "john": "nsldap"},
]

for entry in HASH_DB:
    entry["compiled"] = re.compile(entry["regex"])


# ── Funciones de análisis ─────────────────────────────────────────────────────
def detect_charset(s: str) -> str:
    for name, pattern in CHARSETS.items():
        if pattern.match(s):
            return name
    if re.match(r"^[A-Za-z0-9./]+$", s):
        return "alfanumérico"
    return "otro"


def detect_prefix(s: str) -> str | None:
    match = re.match(r"^(\$[a-zA-Z0-9]*\$|\{[^}]+\}|pbkdf2_sha256\$|\*)", s)
    return match.group(1) if match else None


def find_candidates(hash_value: str):
    return [e for e in HASH_DB if e["compiled"].match(hash_value)]


# ── Salida con Rich ───────────────────────────────────────────────────────────
def mostrar_banner():
    banner = Text()
    banner.append("\n  🔍 Hash Identifier\n", style=COLOR_TITLE)
    banner.append("  Identificador de tipos de hash · v1.0\n", style=COLOR_DIM)
    console.print(Panel(banner, border_style="magenta", padding=(0, 2)))
    console.print()


def mostrar_info(hash_value: str, prefix, charset: str):
    tabla = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    tabla.add_column("", style=COLOR_INFO, min_width=12)
    tabla.add_column("", style="white")
    tabla.add_row("Hash",       hash_value)
    tabla.add_row("Longitud",   str(len(hash_value)))
    tabla.add_row("Prefijo",    prefix or "(ninguno detectado)")
    tabla.add_row("Caracteres", charset)
    console.print(tabla)
    console.print()


def mostrar_sin_resultados():
    console.print(
        Panel(
            Text.assemble(
                ("  ❌  Sin coincidencias\n\n", COLOR_DANGER),
                ("  No se encontró ningún tipo de hash en la base de datos\n", COLOR_DIM),
                ("  que coincida con el formato proporcionado.", COLOR_DIM),
            ),
            border_style="red",
            padding=(0, 1),
        )
    )


def mostrar_candidatos(candidates: list):
    console.print(Rule(f"[cyan]Posibles tipos detectados ({len(candidates)})[/cyan]", style="cyan"))
    console.print()

    tabla = Table(
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        padding=(0, 1),
    )
    tabla.add_column("Tipo de hash",   style="bold white",  min_width=30)
    tabla.add_column("Hashcat mode",   style="yellow",      min_width=16)
    tabla.add_column("John format",    style="green",       min_width=20)

    for c in candidates:
        tabla.add_row(c["name"], c["hashcat"], c["john"])

    console.print(tabla)
    console.print()

    if len(candidates) > 1:
        console.print(
            f"  [dim]⚠  Se encontraron {len(candidates)} posibles tipos. "
            "Verifica el contexto para determinar el correcto.[/dim]\n"
        )


def analyze(hash_value: str):
    hash_value = hash_value.strip()

    if not hash_value:
        console.print("  [red]Error: no se proporcionó ningún hash.[/red]")
        sys.exit(1)

    prefix    = detect_prefix(hash_value)
    charset   = detect_charset(hash_value)
    candidates = find_candidates(hash_value)

    mostrar_info(hash_value, prefix, charset)

    if not candidates:
        mostrar_sin_resultados()
    else:
        mostrar_candidatos(candidates)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Identifica el tipo de hash por prefijo, longitud y caracteres.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "hash",
        nargs="?",
        help="Hash a analizar. Si se omite, se lee desde stdin.",
    )
    args = parser.parse_args()

    mostrar_banner()

    hash_value = args.hash or sys.stdin.readline()

    if not hash_value or not hash_value.strip():
        parser.error("No se proporcionó ningún hash.")

    analyze(hash_value)


if __name__ == "__main__":
    main()
