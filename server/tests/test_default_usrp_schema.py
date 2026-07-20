import os
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"


class DefaultUsrpSchemaTests(unittest.TestCase):
    def _run_fresh_server_import(
        self,
        script,
        *,
        custom_driver=None,
        managed_driver=None,
    ):
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            blocker = temp / "blocker"
            blocker.mkdir()
            (blocker / "uhd.py").write_text(
                "raise ImportError('UHD deliberately unavailable in test')\n",
                encoding="utf-8",
            )

            config_root = temp / "xdg"
            drivers_dir = config_root / "remoterf" / "drivers"
            if custom_driver is not None:
                drivers_dir.mkdir(parents=True)
                (drivers_dir / "custom_usrp.py").write_text(
                    custom_driver,
                    encoding="utf-8",
                )
            if managed_driver is not None:
                drivers_dir.mkdir(parents=True, exist_ok=True)
                target = drivers_dir / "usrp_schema.py"
                target.write_text(managed_driver, encoding="utf-8")
                marker = drivers_dir / ".usrp_schema.py.remoterf-managed"
                marker.write_text(
                    hashlib.sha256(managed_driver.encode("utf-8")).hexdigest() + "\n",
                    encoding="utf-8",
                )

            env = dict(os.environ)
            env["HOME"] = str(temp / "home")
            env["XDG_CONFIG_HOME"] = str(config_root)
            python_path = [str(blocker), str(SOURCE_ROOT)]
            if env.get("PYTHONPATH"):
                python_path.append(env["PYTHONPATH"])
            env["PYTHONPATH"] = os.pathsep.join(python_path)

            return subprocess.run(
                [sys.executable, "-c", textwrap.dedent(script)],
                cwd=PROJECT_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

    def test_fresh_server_seeds_full_usrp_schema_without_uhd(self):
        result = self._run_fresh_server_import(
            """
            from remoteRF_server.common.idl.schema import get_driver_class
            from remoteRF_server.common.utils import get_drivers_dir
            from remoteRF_server.server import device_manager

            seeded = get_drivers_dir() / "usrp_schema.py"
            assert seeded.is_file(), seeded
            assert (get_drivers_dir() / ".usrp_schema.py.remoterf-managed").is_file()

            schema = get_driver_class("usrp")()
            legacy = schema.get_idl()
            assert legacy["client_class"] == "MultiUSRP"
            assert "uhd" in legacy["client_objects"]

            dynamic = schema.get_idl_v2()
            assert dynamic["schema_version"] == "2.0"
            assert dynamic["device_type"] == "usrp"
            assert dynamic["native_api"]["version"] == "4.10.0.0"
            assert len(dynamic["methods"]) >= 140

            try:
                schema.open_native_device()
            except RuntimeError as exc:
                assert "UHD 4.10 Python module" in str(exc)
            else:
                raise AssertionError("opening a native USRP should require UHD")

            print("DEFAULT_USRP_SCHEMA_OK")
            """
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("DEFAULT_USRP_SCHEMA_OK", result.stdout)
        self.assertNotIn("Driver load usrp_schema.py: error", result.stdout)

    def test_existing_custom_usrp_driver_prevents_default_seed(self):
        custom_driver = textwrap.dedent(
            """
            from remoteRF_server.common.idl import DeviceSchema, idl_register

            @idl_register("usrp")
            class CustomUsrpSchema(DeviceSchema):
                device_type = "usrp"
                driver_version = "custom"

                @staticmethod
                def make_device(**kwargs):
                    return None
            """
        )
        result = self._run_fresh_server_import(
            """
            from remoteRF_server.common.idl.schema import get_driver_class
            from remoteRF_server.common.utils import get_drivers_dir
            from remoteRF_server.server import device_manager

            assert not (get_drivers_dir() / "usrp_schema.py").exists()
            assert get_driver_class("usrp").driver_version == "custom"
            print("CUSTOM_USRP_SCHEMA_OK")
            """,
            custom_driver=custom_driver,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("CUSTOM_USRP_SCHEMA_OK", result.stdout)

    def test_unmodified_managed_usrp_driver_is_refreshed_on_upgrade(self):
        stale_managed_driver = textwrap.dedent(
            """
            from remoteRF_server.common.idl import DeviceSchema, idl_register

            @idl_register("usrp")
            class StaleManagedUsrpSchema(DeviceSchema):
                device_type = "usrp"
                driver_version = "stale-managed"
            """
        )
        result = self._run_fresh_server_import(
            """
            from remoteRF_server.common.idl.schema import get_driver_class
            from remoteRF_server.common.utils import get_drivers_dir
            from remoteRF_server.server import device_manager

            schema_path = get_drivers_dir() / "usrp_schema.py"
            assert "stale-managed" not in schema_path.read_text(encoding="utf-8")
            assert get_driver_class("usrp").driver_version != "stale-managed"
            print("MANAGED_USRP_SCHEMA_REFRESHED")
            """,
            managed_driver=stale_managed_driver,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("MANAGED_USRP_SCHEMA_REFRESHED", result.stdout)


if __name__ == "__main__":
    unittest.main()
