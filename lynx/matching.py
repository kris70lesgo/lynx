"""Conservative, IDA-independent matching for PDB local names."""

from __future__ import annotations

import re
from dataclasses import dataclass


_DEFAULT_LOCAL = re.compile(r"^v\d+$", re.IGNORECASE)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class LocalVariable:
    name: str
    register: str
    defea: int
    width: int
    user_named: bool = False


@dataclass(frozen=True)
class RegisterLiveRange:
    name: str
    register: str
    start_ea: int
    end_ea: int


@dataclass(frozen=True)
class Match:
    local: LocalVariable
    live_range: RegisterLiveRange

    @property
    def debug_name(self) -> str:
        return self.live_range.name

    @property
    def register(self) -> str:
        return self.local.register


def _register_family(name: str) -> str:
    """Normalize common register aliases (for example EDX and RDX)."""
    name = name.strip().lower().lstrip("%")
    aliases = {
        "rax": "a", "eax": "a", "ax": "a", "al": "a", "ah": "a",
        "rbx": "b", "ebx": "b", "bx": "b", "bl": "b", "bh": "b",
        "rcx": "c", "ecx": "c", "cx": "c", "cl": "c", "ch": "c",
        "rdx": "d", "edx": "d", "dx": "d", "dl": "d", "dh": "d",
        "rsi": "si", "esi": "si", "si": "si", "sil": "si",
        "rdi": "di", "edi": "di", "di": "di", "dil": "di",
        "rbp": "bp", "ebp": "bp", "bp": "bp", "bpl": "bp",
        "rsp": "sp", "esp": "sp", "sp": "sp", "spl": "sp",
        "rip": "ip", "eip": "ip", "ip": "ip",
        "fp": "x29", "lr": "x30",
    }
    if name in aliases:
        return aliases[name]
    match = re.fullmatch(r"r(\d+)(d|w|b)?", name)
    if match:
        return f"r{match.group(1)}"
    match = re.fullmatch(r"w(\d+)", name)
    if match:
        return f"x{match.group(1)}"
    return name


def find_matches(
    locals_: list[LocalVariable],
    live_ranges: list[RegisterLiveRange],
) -> tuple[list[Match], int]:
    """Return only unique register-and-address matches for default vN locals.

    Matches are deliberately conservative: user-renamed locals, invalid names,
    missing definition addresses, and collisions are left untouched.
    """
    eligible: list[tuple[LocalVariable, RegisterLiveRange]] = []
    ambiguous = 0
    occupied_names = {local.name.casefold() for local in locals_}

    for local in locals_:
        if local.user_named or not _DEFAULT_LOCAL.fullmatch(local.name):
            continue
        if local.defea < 0 or not local.register:
            continue

        candidates = [
            live_range
            for live_range in live_ranges
            if live_range.start_ea <= local.defea < live_range.end_ea
            and _register_family(live_range.register) == _register_family(local.register)
            and _IDENTIFIER.fullmatch(live_range.name)
            and live_range.name.casefold() != local.name.casefold()
        ]
        if len(candidates) == 1:
            eligible.append((local, candidates[0]))
        elif len(candidates) > 1:
            ambiguous += 1

    # Do not guess when multiple decompiler locals point at one debug range.
    range_counts: dict[RegisterLiveRange, int] = {}
    for _, live_range in eligible:
        range_counts[live_range] = range_counts.get(live_range, 0) + 1

    matches: list[Match] = []
    reserved: set[str] = set()
    for local, live_range in eligible:
        target = live_range.name.casefold()
        if range_counts[live_range] != 1 or target in occupied_names or target in reserved:
            ambiguous += 1
            continue
        matches.append(Match(local, live_range))
        reserved.add(target)

    return matches, ambiguous
