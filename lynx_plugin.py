"""Lynx: review PDB register-variable names against Hex-Rays locals."""

from __future__ import annotations

from typing import Any

import ida_frame
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin

from lynx.matching import LocalVariable, RegisterLiveRange, find_matches


PLUGIN_NAME = "Lynx — PDB local mapper"
def _value(obj: Any, name: str, default: Any = None) -> Any:
    """Read an IDAPython property or zero-argument method across SDK versions."""
    value = getattr(obj, name, default)
    return value() if callable(value) else value


def _current_register_name(lvar: Any) -> str | None:
    """Translate a Hex-Rays micro-register location to an IDA register name."""
    location = _value(lvar, "location")
    if location is None or not _value(location, "is_reg1", False):
        return None

    micro_reg = _value(location, "reg1", -1)
    width = int(_value(lvar, "width", 0) or 0)
    if micro_reg < 0 or width <= 0:
        return None

    processor_reg = ida_hexrays.mreg2reg(micro_reg, width)
    if processor_reg < 0:
        return None
    return ida_idp.get_reg_name(processor_reg, width) or None


def _collect_locals(cfunc: Any) -> list[LocalVariable]:
    lvars = cfunc.get_lvars()
    count = lvars.size() if hasattr(lvars, "size") else len(lvars)
    locals_: list[LocalVariable] = []

    for index in range(count):
        lvar = lvars[index]
        name = str(_value(lvar, "name", ""))
        register = _current_register_name(lvar)
        if not name or not register:
            continue

        defea = int(_value(lvar, "defea", ida_idaapi.BADADDR))
        width = int(_value(lvar, "width", 0) or 0)
        if defea == ida_idaapi.BADADDR:
            continue
        is_user_name = bool(_value(lvar, "has_user_name", False))
        locals_.append(LocalVariable(name, register, defea, width, is_user_name))

    return locals_


def _collect_register_ranges(func_ea: int) -> list[RegisterLiveRange]:
    """Read names and address ranges already imported into IDA's regvar table."""
    regvars = ida_frame.regvars_t()
    if not ida_frame.get_func_regvars(regvars, func_ea):
        return []

    ranges: list[RegisterLiveRange] = []
    for index in range(regvars.size()):
        regvar = regvars.at(index)
        name = str(_value(regvar, "user", ""))
        register = str(_value(regvar, "canon", ""))
        start_ea = int(_value(regvar, "start_ea", ida_idaapi.BADADDR))
        end_ea = int(_value(regvar, "end_ea", ida_idaapi.BADADDR))
        if name and register and start_ea < end_ea:
            ranges.append(RegisterLiveRange(name, register, start_ea, end_ea))
    return ranges


class _SuggestionChooser(ida_kernwin.Choose):
    """A small review table; selecting a row asks before changing the IDB."""

    def __init__(self, func_ea: int, matches: list[Any]):
        self.func_ea = func_ea
        self.matches = matches
        columns = [
            ["Local", 10],
            ["PDB name", 20],
            ["Register", 10],
            ["Local definition", 18],
            ["PDB live range", 28],
            ["Match", 8],
        ]
        super().__init__(PLUGIN_NAME, columns, flags=ida_kernwin.Choose.CH_MODAL)

    def OnGetSize(self) -> int:
        return len(self.matches)

    def OnGetLine(self, index: int) -> list[str]:
        match = self.matches[index]
        return [
            match.local.name,
            match.debug_name,
            match.register,
            f"{match.local.defea:#x}",
            f"[{match.live_range.start_ea:#x}, {match.live_range.end_ea:#x})",
            "Unique",
        ]


def _apply_matches(func_ea: int, matches: list[Any]) -> None:
    remaining = list(matches)
    renamed = 0

    while remaining:
        chooser = _SuggestionChooser(func_ea, remaining)
        selected = chooser.Show(modal=True)
        if selected is None or not isinstance(selected, int) or selected < 0:
            break

        match = remaining.pop(selected)
        prompt = (
            f"Rename {match.local.name} to {match.debug_name}?\n\n"
            f"PDB says {match.register} is named {match.debug_name} at "
            f"0x{match.live_range.start_ea:X}–0x{match.live_range.end_ea:X}.\n"
            f"The decompiler local is defined at 0x{match.local.defea:X}.\n\n"
            "Lynx found one matching local and one matching PDB range."
        )
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, prompt) != ida_kernwin.ASKBTN_YES:
            continue

        if ida_hexrays.rename_lvar(func_ea, match.local.name, match.debug_name):
            renamed += 1
            ida_kernwin.msg(
                f"[Lynx] Renamed {match.local.name} to {match.debug_name}.\n"
            )
        else:
            ida_kernwin.warning(
                f"Lynx could not rename {match.local.name}. "
                "The decompiler may have changed the local variable."
            )

    ida_kernwin.msg(f"[Lynx] Finished. Renamed {renamed} local(s).\n")


class LynxPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Map PDB register-variable names onto matching Hex-Rays locals"
    help = "Open pseudocode, then run Lynx from Edit > Plugins."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Shift-L"

    def init(self) -> int:
        return (
            ida_idaapi.PLUGIN_OK
            if ida_hexrays.init_hexrays_plugin()
            else ida_idaapi.PLUGIN_SKIP
        )

    def run(self, arg: int) -> None:
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is None:
            ida_kernwin.warning("Lynx: place the cursor inside a function first.")
            return

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except Exception as exc:
            ida_kernwin.warning(f"Lynx: Hex-Rays could not decompile this function: {exc}")
            return
        if cfunc is None:
            ida_kernwin.warning("Lynx: Hex-Rays could not decompile this function.")
            return

        register_ranges = _collect_register_ranges(func.start_ea)
        if not register_ranges:
            ida_kernwin.warning(
                "Lynx found no named register-variable ranges in this function.\n\n"
                "Load a PDB with a loader that imports optimized local ranges into "
                "IDA's register-variable table, then try again."
            )
            return

        matches, ambiguous = find_matches(_collect_locals(cfunc), register_ranges)
        if not matches:
            detail = f" Lynx skipped {ambiguous} ambiguous match(es)." if ambiguous else ""
            ida_kernwin.info(
                "Lynx found no clear PDB-to-decompiler local matches.\n\n"
                "It only suggests default vN names when the register and live range "
                f"match uniquely.{detail}"
            )
            return

        _apply_matches(func.start_ea, matches)


def PLUGIN_ENTRY() -> LynxPlugin:
    return LynxPlugin()
