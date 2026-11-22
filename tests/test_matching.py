import unittest

from lynx.matching import LocalVariable, RegisterLiveRange, find_matches


class FindMatchesTests(unittest.TestCase):
    def test_matches_unique_register_alias_inside_range(self):
        local = LocalVariable("v3", "edx", 0x1010, 4, use_addresses=(0x1010,))
        live_range = RegisterLiveRange("cchDest", "rdx", 0x1000, 0x1020)

        matches, ambiguous = find_matches([local], [live_range])

        self.assertEqual(ambiguous, 0)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].local.name, "v3")
        self.assertEqual(matches[0].debug_name, "cchDest")

    def test_end_of_range_is_exclusive(self):
        local = LocalVariable("v3", "edx", 0x1020, 4, use_addresses=(0x1020,))
        live_range = RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020)

        matches, ambiguous = find_matches([local], [live_range])

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 0)

    def test_does_not_match_wrong_register_or_address(self):
        local = LocalVariable("v3", "ecx", 0x1050, 4, use_addresses=(0x1050,))
        live_range = RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020)

        matches, ambiguous = find_matches([local], [live_range])

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 0)

    def test_preserves_user_named_local_even_if_name_looks_generated(self):
        local = LocalVariable(
            "v3", "edx", 0x1010, 4, user_named=True, use_addresses=(0x1010,)
        )
        live_range = RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020)

        matches, _ = find_matches([local], [live_range])

        self.assertEqual(matches, [])

    def test_ignores_non_default_local_names(self):
        local = LocalVariable("count", "edx", 0x1010, 4, use_addresses=(0x1010,))
        live_range = RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020)

        matches, _ = find_matches([local], [live_range])

        self.assertEqual(matches, [])

    def test_skips_overlapping_ambiguous_ranges(self):
        local = LocalVariable("v3", "edx", 0x1010, 4, use_addresses=(0x1010,))
        ranges = [
            RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020),
            RegisterLiveRange("length", "rdx", 0x1008, 0x1018),
        ]

        matches, ambiguous = find_matches([local], ranges)

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 1)

    def test_skips_name_collision_with_another_local(self):
        locals_ = [
            LocalVariable("v3", "edx", 0x1010, 4, use_addresses=(0x1010,)),
            LocalVariable("cchDest", "ecx", 0x1020, 4),
        ]
        live_range = RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020)

        matches, ambiguous = find_matches(locals_, [live_range])

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 1)

    def test_skips_one_range_claimed_by_multiple_locals(self):
        locals_ = [
            LocalVariable("v3", "edx", 0x1010, 4, use_addresses=(0x1010,)),
            LocalVariable("v4", "rdx", 0x1010, 4, use_addresses=(0x1010,)),
        ]
        live_range = RegisterLiveRange("cchDest", "edx", 0x1000, 0x1020)

        matches, ambiguous = find_matches(locals_, [live_range])

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 2)

    def test_ignores_invalid_debug_names(self):
        local = LocalVariable("v3", "edx", 0x1010, 4, use_addresses=(0x1010,))
        live_range = RegisterLiveRange("$temp", "edx", 0x1000, 0x1020)

        matches, ambiguous = find_matches([local], [live_range])

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 0)

    def test_matches_fragmented_ranges_for_the_same_source_local(self):
        local = LocalVariable(
            "v3", "edx", 0x1005, 4, use_addresses=(0x1005, 0x1015, 0x1025)
        )
        ranges = [
            RegisterLiveRange("cchDest", "edx", 0x1000, 0x1010),
            RegisterLiveRange("cchDest", "edx", 0x1014, 0x1020),
            RegisterLiveRange("cchDest", "ecx", 0x1024, 0x1030),
        ]

        matches, ambiguous = find_matches([local], ranges)

        self.assertEqual(ambiguous, 0)
        self.assertEqual([match.debug_name for match in matches], ["cchDest"])

    def test_rejects_one_decompiler_local_reused_for_different_pdb_names(self):
        local = LocalVariable(
            "v3", "edx", 0x1005, 4, use_addresses=(0x1005, 0x1015)
        )
        ranges = [
            RegisterLiveRange("isValue", "edx", 0x1000, 0x1010),
            RegisterLiveRange("index", "edx", 0x1010, 0x1020),
        ]

        matches, ambiguous = find_matches([local], ranges)

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 1)

    def test_rejects_a_candidate_when_the_local_has_no_observed_uses(self):
        local = LocalVariable("v3", "edx", 0x1005, 4)
        live_range = RegisterLiveRange("cchDest", "edx", 0x1000, 0x1010)

        matches, ambiguous = find_matches([local], [live_range])

        self.assertEqual(matches, [])
        self.assertEqual(ambiguous, 1)


if __name__ == "__main__":
    unittest.main()
