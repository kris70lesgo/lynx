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

    try:
        processor_reg = ida_hexrays.mreg2reg(micro_reg, width)
    except Exception:
        return None
    if processor_reg < 0:
        return None
    return ida_idp.get_reg_name(processor_reg, width) or None


def _collect_local_use_addresses(cfunc: Any) -> dict[int, tuple[int, ...]]:
    """Map each decompiler local index to EAs where its ctree is used."""
    uses: dict[int, set[int]] = {}

    class LocalUseVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expression: Any) -> int:
            if _value(expression, "op", -1) != ida_hexrays.cot_var:
                return 0

            variable_ref = _value(expression, "v")
            local_index = int(_value(variable_ref, "idx", -1))
            ea = int(_value(expression, "ea", ida_idaapi.BADADDR))
            if local_index >= 0 and ea != ida_idaapi.BADADDR:
                uses.setdefault(local_index, set()).add(ea)
            return 0

    body = _value(cfunc, "body")
    if body is not None:
        LocalUseVisitor().apply_to(body, None)
    return {index: tuple(sorted(addresses)) for index, addresses in uses.items()}


def _collect_locals(cfunc: Any) -> list[LocalVariable]:
    lvars = cfunc.get_lvars()
    count = lvars.size() if hasattr(lvars, "size") else len(lvars)
    locals_: list[LocalVariable] = []
    use_addresses = _collect_local_use_addresses(cfunc)

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
        locator = ida_hexrays.lvar_locator_t()
        locator.location = _value(lvar, "location")
        locator.defea = defea
        locals_.append(
            LocalVariable(
                name,
                register,
                defea,
                width,
                is_user_name,
                identity=locator,
                use_addresses=use_addresses.get(index, ()),
            )
        )

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

        if _rename_local(func_ea, match):
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


def _rename_local(func_ea: int, match: Any) -> bool:
    """Persist a rename using the exact decompiler-local location."""
    locator = match.local.identity
    if locator is None:
        return False

    info = ida_hexrays.lvar_saved_info_t()
    info.ll = locator
    info.name = match.debug_name
    return bool(
        ida_hexrays.modify_user_lvar_info(
            func_ea,
            ida_hexrays.MLI_NAME,
            info,
        )
    )


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
