import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PluginMetadataTests(unittest.TestCase):
    def test_plugin_metadata_points_to_existing_entrypoint(self):
        metadata = json.loads((ROOT / "ida-plugin.json").read_text())
        entry_point = metadata["plugin"]["entryPoint"]

        self.assertTrue((ROOT / entry_point).is_file())
        self.assertEqual(metadata["plugin"]["name"], "lynx")
        self.assertEqual(metadata["plugin"]["license"], "MIT")
        self.assertEqual(metadata["plugin"]["idaVersions"], ">=9.4")


if __name__ == "__main__":
    unittest.main()
