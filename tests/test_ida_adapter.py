"""Exercise the IDA-facing data adapter with SDK-shaped test doubles."""

import importlib
import sys
import types
import unittest
from unittest.mock import patch

from lynx.matching import LocalVariable, Match, RegisterLiveRange


class FakeVector:
    def __init__(self, values=()):
        self.values = list(values)

    def size(self):
        return len(self.values)

    def at(self, index):
        return self.values[index]


class FakeLocation:
    def is_reg1(self):
        return True

    def reg1(self):
        return 7


class FakeLvar:
    name = "v3"
    location = FakeLocation()
    defea = 0x1010
    width = 4

    def has_user_name(self):
        return False


class IdaAdapterTests(unittest.TestCase):
    def setUp(self):
        self.regvar = types.SimpleNamespace(
            user="cchDest",
            canon="edx",
            start_ea=0x1000,
            end_ea=0x1020,
        )

        ida_frame = types.ModuleType("ida_frame")
        ida_frame.regvars_t = FakeVector

        def get_func_regvars(out, func_ea):
            out.values = [self.regvar] if func_ea == 0x1000 else []
            return bool(out.values)

        ida_frame.get_func_regvars = get_func_regvars

        ida_hexrays = types.ModuleType("ida_hexrays")
        ida_hexrays.mreg2reg = lambda micro_reg, width: micro_reg + 10
        ida_hexrays.init_hexrays_plugin = lambda: True
        ida_hexrays.MLI_NAME = 1
        ida_hexrays.CV_FAST = 1
        ida_hexrays.cot_var = 2

        class FakeCtreeVisitor:
            def __init__(self, flags):
                self.flags = flags

            def apply_to(self, body, parent):
                for expression in body:
                    self.visit_expr(expression)
                return 0

        ida_hexrays.ctree_visitor_t = FakeCtreeVisitor

        class FakeLocator:
            location = None
            defea = 0

        class FakeSavedInfo:
            ll = None
            name = ""

        self.saved_info_calls = []
        ida_hexrays.lvar_locator_t = FakeLocator
        ida_hexrays.lvar_saved_info_t = FakeSavedInfo
        ida_hexrays.modify_user_lvar_info = (
            lambda func_ea, flags, info: self.saved_info_calls.append(
                (func_ea, flags, info)
            ) or True
        )

        ida_idaapi = types.ModuleType("ida_idaapi")

        class PluginBase:
            pass

        ida_idaapi.plugin_t = PluginBase
        ida_idaapi.PLUGIN_UNL = 1
        ida_idaapi.PLUGIN_OK = 2
        ida_idaapi.PLUGIN_SKIP = 3
        ida_idaapi.BADADDR = (1 << 64) - 1

        ida_idp = types.ModuleType("ida_idp")
        ida_idp.get_reg_name = lambda processor_reg, width: "edx"

        ida_kernwin = types.ModuleType("ida_kernwin")

        class Choose:
            CH_MODAL = 1

            def __init__(self, *args, **kwargs):
                pass

        ida_kernwin.Choose = Choose

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: None

        self.ida_modules = {
            "ida_frame": ida_frame,
            "ida_funcs": ida_funcs,
            "ida_hexrays": ida_hexrays,
            "ida_idaapi": ida_idaapi,
            "ida_idp": ida_idp,
            "ida_kernwin": ida_kernwin,
        }
        sys.modules.pop("lynx_plugin", None)
        with patch.dict(sys.modules, self.ida_modules):
            self.plugin = importlib.import_module("lynx_plugin")
        sys.modules.pop("lynx_plugin", None)

    def test_reads_ida_register_variable_ranges(self):
        ranges = self.plugin._collect_register_ranges(0x1000)

        self.assertEqual(
            ranges,
            [RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020)],
        )

    def test_maps_hexrays_microregister_to_processor_register(self):
        name = self.plugin._current_register_name(FakeLvar())

        self.assertEqual(name, "edx")

    def test_converts_hexrays_locals_to_matcher_inputs(self):
        class FakeCfunc:
            body = [
                types.SimpleNamespace(
                    op=2, v=types.SimpleNamespace(idx=0), ea=0x1010
                ),
                types.SimpleNamespace(
                    op=2, v=types.SimpleNamespace(idx=0), ea=0x1018
                ),
                types.SimpleNamespace(
                    op=99, v=types.SimpleNamespace(idx=0), ea=0x101C
                ),
            ]

            def get_lvars(self):
                return [FakeLvar()]

        locals_ = self.plugin._collect_locals(FakeCfunc())

        self.assertEqual(locals_, [LocalVariable("v3", "edx", 0x1010, 4, False)])
        self.assertIs(locals_[0].identity.location, FakeLvar.location)
        self.assertEqual(locals_[0].identity.defea, FakeLvar.defea)
        self.assertEqual(locals_[0].use_addresses, (0x1010, 0x1018))

    def test_rename_is_saved_to_the_exact_local_locator(self):
        class FakeCfunc:
            body = [
                types.SimpleNamespace(
                    op=2, v=types.SimpleNamespace(idx=0), ea=0x1010
                )
            ]

            def get_lvars(self):
                return [FakeLvar()]

        local = self.plugin._collect_locals(FakeCfunc())[0]
        live_range = RegisterLiveRange("destination", "edx", 0x1000, 0x1020)
        match = Match(local, live_range)

        self.assertTrue(self.plugin._rename_local(0x1000, match))
        func_ea, flags, info = self.saved_info_calls[0]
        self.assertEqual(func_ea, 0x1000)
        self.assertEqual(flags, self.ida_modules["ida_hexrays"].MLI_NAME)
        self.assertIs(info.ll, local.identity)
        self.assertEqual(info.name, "destination")

    def test_rename_refuses_a_match_without_exact_identity(self):
        local = LocalVariable("v3", "edx", 0x1010, 4)
        match = Match(local, RegisterLiveRange("destination", "edx", 0x1000, 0x1020))

        self.assertFalse(self.plugin._rename_local(0x1000, match))
        self.assertEqual(self.saved_info_calls, [])

    def test_invalid_microregister_mapping_is_ignored(self):
        self.ida_modules["ida_hexrays"].mreg2reg = (
            lambda _micro_reg, _width: (_ for _ in ()).throw(ValueError("bad reg"))
        )

        self.assertIsNone(self.plugin._current_register_name(FakeLvar()))

    def test_plugin_skips_when_decompiler_is_unavailable(self):
        self.ida_modules["ida_hexrays"].init_hexrays_plugin = lambda: False

        self.assertEqual(
            self.plugin.LynxPlugin().init(),
            self.ida_modules["ida_idaapi"].PLUGIN_SKIP,
        )


if __name__ == "__main__":
    unittest.main()
