from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from emudhra_mitm.hotspot_controller import HotspotController, HotspotError


class HotspotControllerTests(unittest.TestCase):
    def test_validates_access_point_credentials(self) -> None:
        with self.assertRaises(HotspotError):
            HotspotController._validate_access_point("x", "short", "wlan0")
        with self.assertRaises(HotspotError):
            HotspotController._validate_access_point(
                "hotspot",
                "password123",
                "bad interface",
            )

    def test_installs_linux_transparent_redirect(self) -> None:
        controller = HotspotController(
            runtime_platform="linux",
            administrator_checker=lambda: True,
        )
        captured_rules: list[str] = []

        def fake_privileged(command, **kwargs):
            if len(command) > 1 and command[1].startswith("add table"):
                captured_rules.append(command[1])
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch(
            "emudhra_mitm.hotspot_controller.shutil.which",
            return_value="/usr/sbin/nft",
        ), mock.patch.object(
            controller,
            "_run_privileged",
            side_effect=fake_privileged,
        ):
            controller.enable_transparent_redirect("wlan0", 28083)

        self.assertTrue(controller._redirect_enabled)
        self.assertEqual(len(captured_rules), 1)
        self.assertIn('iifname "wlan0"', captured_rules[0])
        self.assertIn("tcp dport { 80, 443 }", captured_rules[0])
        self.assertIn("redirect to :28083", captured_rules[0])
        self.assertIn("udp dport 443 reject", captured_rules[0])

    def test_windows_firewall_rules_scope_quic_block_to_client_network(
        self,
    ) -> None:
        controller = HotspotController(
            runtime_platform="win32",
            administrator_checker=lambda: True,
        )
        with mock.patch.object(
            controller,
            "_run_powershell_script",
            return_value={"ok": True},
        ) as run_script, mock.patch.object(
            controller,
            "_remove_windows_firewall_rules",
        ):
            controller.enable_transparent_redirect(
                "",
                28083,
                "192.168.137.0/24",
            )

        self.assertTrue(controller._redirect_enabled)
        arguments = run_script.call_args.args[1]
        self.assertIn("-HotspotClientNetwork", arguments)
        self.assertIn("192.168.137.0/24", arguments)

    def test_windows_firewall_rules_reject_invalid_client_network(self) -> None:
        controller = HotspotController(
            runtime_platform="win32",
            administrator_checker=lambda: True,
        )
        with mock.patch.object(
            controller,
            "_run_powershell_script",
            return_value={"ok": True},
        ) as run_script:
            with self.assertRaises(HotspotError):
                controller.enable_transparent_redirect("", 28083, "")

        # 校验失败必须发生在安装规则之前，只允许回滚性质的 disable 调用。
        for call in run_script.call_args_list:
            self.assertIn("disable", call.args[1])
        self.assertFalse(controller._redirect_enabled)

    def test_windows_start_uses_mobile_hotspot_ics(self) -> None:
        controller = HotspotController(
            runtime_platform="win32",
            administrator_checker=lambda: True,
        )
        windows_status = {
            "ok": True,
            "platform": "windows",
            "ready": True,
            "available": True,
            "error": "",
            "missing_dependencies": [],
            "install_steps": [],
            "requires_administrator": True,
            "administrator": True,
            "running": True,
            "ssid": "hotspot",
            "interface": "",
            "address": "192.168.137.1",
            "prefix_length": 24,
            "client_network": "192.168.137.0/24",
            "backend": "windows-mobile-hotspot",
            "clients": 0,
            "interfaces": [],
            "redirect_enabled": True,
        }

        with mock.patch.object(
            controller,
            "_windows_status",
            return_value=windows_status,
        ), mock.patch.object(
            controller,
            "_run_powershell_script",
            return_value={
                "ok": True,
                "state": "On",
                "ssid": "hotspot",
                "gateway": "192.168.137.1",
                "clients": 0,
            },
        ) as run_script:
            result = controller.start_access_point(
                "hotspot",
                "password123",
            )

        self.assertTrue(result["running"])
        self.assertEqual(run_script.call_count, 1)

    def test_windows_status_derives_hotspot_client_network(self) -> None:
        controller = HotspotController(
            runtime_platform="win32",
            administrator_checker=lambda: True,
        )

        with mock.patch.object(
            controller,
            "_run_powershell_script",
            return_value={
                "ok": True,
                "state": "On",
                "ssid": "hotspot",
                "clients": 1,
                "gateway": "192.168.137.1",
                "prefix_length": 24,
                "interface_name": "Local Area Connection* 12",
                "interface_guid": "{11111111-2222-3333-4444-555555555555}",
                "devices": [
                    {
                        "ip_address": "192.168.137.52",
                        "mac_address": "B2-85-03-72-C4-8E",
                        "state": "Reachable",
                    }
                ],
            },
        ):
            status = controller._windows_status()

        self.assertEqual(status["address"], "192.168.137.1")
        self.assertEqual(
            status["interface"],
            "Local Area Connection* 12",
        )
        self.assertEqual(
            status["interface_guid"],
            "{11111111-2222-3333-4444-555555555555}",
        )
        self.assertEqual(
            status["client_network"],
            "192.168.137.0/24",
        )
        self.assertEqual(
            status["client_devices"],
            [
                {
                    "ip_address": "192.168.137.52",
                    "mac_address": "b2:85:03:72:c4:8e",
                    "state": "Reachable",
                }
            ],
        )

    def test_windows_status_keeps_last_on_state_during_query_error(self) -> None:
        controller = HotspotController(
            runtime_platform="win32",
            administrator_checker=lambda: True,
        )
        controller._running = True

        with mock.patch.object(
            controller,
            "_run_powershell_script",
            return_value={
                "ok": False,
                "state": "Unknown",
                "message": "temporary query failure",
            },
        ):
            status = controller._windows_status()

        self.assertTrue(status["running"])
        self.assertTrue(status["available"])

    def test_windows_status_requires_two_off_results(self) -> None:
        controller = HotspotController(
            runtime_platform="win32",
            administrator_checker=lambda: True,
        )
        controller._running = True

        off_result = {
            "ok": True,
            "state": "Off",
            "ssid": "hotspot",
            "clients": 0,
        }
        with mock.patch.object(
            controller,
            "_run_powershell_script",
            return_value=off_result,
        ):
            first_status = controller._windows_status()
            second_status = controller._windows_status()

        self.assertTrue(first_status["running"])
        self.assertFalse(second_status["running"])

    def test_windows_firewall_rules_use_powershell_script(self) -> None:
        controller = HotspotController(
            runtime_platform="win32",
            administrator_checker=lambda: True,
        )

        with mock.patch.object(
            controller,
            "_run_powershell_script",
            return_value={"ok": True},
        ) as run_script:
            controller._enable_windows_firewall_rules(
                28083,
                "192.168.137.0/24",
            )

        enable_call = run_script.call_args_list[-1]
        self.assertEqual(
            enable_call.args[1],
            [
                "-Action",
                "enable",
                "-TransparentPort",
                "28083",
                "-HotspotClientNetwork",
                "192.168.137.0/24",
            ],
        )
        self.assertTrue(controller._windows_firewall_rules_enabled)

    def test_normalizes_and_sorts_client_devices(self) -> None:
        devices = HotspotController._normalize_client_devices(
            [
                {
                    "ip_address": "192.168.137.53",
                    "mac_address": "AA-BB-CC-DD-EE-02",
                    "state": "Reachable",
                },
                {
                    "ip_address": "invalid",
                    "mac_address": "AA-BB-CC-DD-EE-03",
                    "state": "Reachable",
                },
                {
                    "ip_address": "192.168.137.52",
                    "mac_address": "AA-BB-CC-DD-EE-01",
                    "state": "Stale",
                },
            ]
        )

        self.assertEqual(
            [device["ip_address"] for device in devices],
            ["192.168.137.52", "192.168.137.53"],
        )
        self.assertEqual(
            devices[0]["mac_address"],
            "aa:bb:cc:dd:ee:01",
        )

    def test_lists_linux_hotspot_clients(self) -> None:
        controller = HotspotController(
            runtime_platform="linux",
            administrator_checker=lambda: True,
        )

        def fake_run(command, **kwargs):
            if command[:3] == ["iw", "dev", "wlan0"]:
                output = (
                    "Station aa:bb:cc:dd:ee:01 (on wlan0)\n"
                    "\tinactive time:\t120 ms\n"
                )
            else:
                output = (
                    "192.168.137.52 dev wlan0 lladdr "
                    "aa:bb:cc:dd:ee:01 REACHABLE\n"
                )
            return subprocess.CompletedProcess(command, 0, output, "")

        with mock.patch(
            "emudhra_mitm.hotspot_controller.shutil.which",
            return_value="/usr/sbin/ip",
        ), mock.patch.object(
            controller,
            "_run",
            side_effect=fake_run,
        ):
            devices = controller._linux_client_devices("wlan0")

        self.assertEqual(
            devices,
            [
                {
                    "ip_address": "192.168.137.52",
                    "mac_address": "aa:bb:cc:dd:ee:01",
                    "state": "REACHABLE",
                }
            ],
        )

    def test_rejects_missing_linux_interface(self) -> None:
        controller = HotspotController(
            runtime_platform="linux",
            administrator_checker=lambda: True,
        )
        with mock.patch.object(controller, "preflight"):
            with self.assertRaises(HotspotError):
                controller.start_access_point(
                    "hotspot",
                    "password123",
                )

    def test_detects_create_ap_virtual_interface(self) -> None:
        controller = HotspotController(
            runtime_platform="linux",
            administrator_checker=lambda: True,
        )

        with mock.patch.object(
            controller,
            "_iw_interfaces",
            side_effect=[["wlan0"], ["wlan0", "ap0"]],
        ), mock.patch.object(
            controller,
            "_ipv4_address",
            side_effect=lambda interface: (
                "10.42.0.1" if interface == "ap0" else ""
            ),
        ), mock.patch(
            "emudhra_mitm.hotspot_controller.time.sleep",
        ):
            interface = controller._wait_for_create_ap_interface(
                "wlan0",
                {"wlan0"},
                "",
            )

        self.assertEqual(interface, "ap0")

    def test_builds_linux_package_install_plan(self) -> None:
        controller = HotspotController(
            runtime_platform="linux",
            administrator_checker=lambda: True,
        )
        with mock.patch.object(
            controller,
            "_privileged_command",
            side_effect=lambda name: (
                "/usr/bin/apt-get" if name == "apt-get" else None
            ),
        ):
            plan = controller._linux_install_plan(
                ["networkmanager", "nftables", "iproute2"]
            )

        self.assertIsNotNone(plan)
        self.assertEqual(plan.package_manager, "apt-get")
        self.assertEqual(
            plan.manual_steps,
            (
                "sudo /usr/bin/apt-get update",
                (
                    "sudo /usr/bin/apt-get install -y "
                    "network-manager nftables iproute2"
                ),
            ),
        )

    def test_preflight_installs_missing_linux_dependencies(self) -> None:
        controller = HotspotController(
            runtime_platform="linux",
            administrator_checker=lambda: True,
        )
        missing_status = {
            "ready": False,
            "available": True,
            "error": "",
            "install_steps": ["sudo apt-get install nftables"],
        }
        ready_status = {"ready": True, "available": True}

        with mock.patch.object(
            controller,
            "status",
            side_effect=[missing_status, ready_status],
        ), mock.patch.object(
            controller,
            "_install_linux_dependencies",
        ) as install_dependencies:
            controller.preflight()

        install_dependencies.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
