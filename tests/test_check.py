import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import sys
import tkinter as tk
from tkinter import ttk
from pathlib import Path
from datetime import datetime
import json

# Add the parent directory to sys.path to import automation
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from automation import run_command_sync, VolatilityGUI

class TestAutomation(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        # Mocking methods that interact with Volatility or the system during init
        with patch.object(VolatilityGUI, '_check_volatility'), \
             patch.object(VolatilityGUI, '_detect_os'):
            self.app = VolatilityGUI(self.root)

    def tearDown(self):
        self.root.destroy()

    @patch('subprocess.Popen')
    def test_run_command_sync_success(self, mock_popen):
        print("\n[TESTING] run_command_sync (Success case)...")
        # Setup mock
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("output", "error")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        ret, stdout, stderr = run_command_sync("test command")

        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "output")
        self.assertEqual(stderr, "error")
        print(" -> SUCCESS: run_command_sync correctly handled successful execution.")

    @patch('subprocess.Popen')
    def test_run_command_sync_timeout(self, mock_popen):
        print("\n[TESTING] run_command_sync (Timeout case)...")
        import subprocess
        # Setup mock
        mock_process = MagicMock()
        mock_process.communicate.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=1)
        mock_popen.return_value = mock_process

        ret, stdout, stderr = run_command_sync("test command", timeout=1)

        self.assertEqual(ret, 1)
        self.assertEqual(stdout, "")
        self.assertIn("timed out", stderr)
        mock_process.kill.assert_called_once()
        print(" -> SUCCESS: run_command_sync correctly handled timeout.")

    def test_get_vol_command_default(self):
        print("\n[TESTING] VolatilityGUI._get_vol_command (Default plugins)...")
        self.app.memory_image = "test.vmem"
        self.app.current_os = "Windows"
        
        # We need to mock self.os_override because it's a ttk.Combobox
        self.app.os_override = MagicMock()
        self.app.os_override.get.return_value = "Auto"
        
        cmd, v3_plugin, os_prefix = self.app._get_vol_command("pslist")
        
        self.assertIn("vol", cmd)
        self.assertIn("-f \"test.vmem\"", cmd)
        self.assertIn("windows.pslist.PsList", cmd)
        self.assertEqual(v3_plugin, "pslist.PsList")
        self.assertEqual(os_prefix, "windows")
        print(" -> SUCCESS: _get_vol_command generated correct command string for pslist.")

    def test_get_vol_command_with_pid(self):
        print("\n[TESTING] VolatilityGUI._get_vol_command (With PID)...")
        self.app.memory_image = "test.vmem"
        self.app.current_os = "Windows"
        self.app.os_override = MagicMock()
        self.app.os_override.get.return_value = "Auto"
        
        cmd, v3_plugin, os_prefix = self.app._get_vol_command("pslist", pid="1234")
        
        self.assertIn("--pid 1234", cmd)
        print(" -> SUCCESS: _get_vol_command correctly included PID in the command.")

    def test_get_vol_command_override_os(self):
        print("\n[TESTING] VolatilityGUI._get_vol_command (OS Override)...")
        self.app.memory_image = "test.vmem"
        self.app.current_os = "Windows"
        self.app.os_override = MagicMock()
        self.app.os_override.get.return_value = "linux"
        
        cmd, v3_plugin, os_prefix = self.app._get_vol_command("pslist")
        
        self.assertIn("linux.pslist", cmd)
        self.assertEqual(os_prefix, "linux")
        print(" -> SUCCESS: _get_vol_command respected OS override.")

    @patch('automation.datetime')
    def test_log(self, mock_datetime):
        print("\n[TESTING] VolatilityGUI.log...")
        mock_datetime.now.return_value.strftime.return_value = "12:00:00"
        self.app.output_text = MagicMock()
        
        self.app.log("Test message", "INFO")
        
        self.app.output_text.insert.assert_called_with(tk.END, "[12:00:00] [INFO] Test message\n")
        print(" -> SUCCESS: log() correctly updated the UI widget.")

    @patch('automation.Path.mkdir')
    def test_create_output_dir(self, mock_mkdir):
        print("\n[TESTING] VolatilityGUI._create_output_dir...")
        self.app.log = MagicMock()
        self.app._create_output_dir()
        
        self.assertIsNotNone(self.app.output_dir)
        self.assertTrue(str(self.app.output_dir).startswith("vol_gui_analysis_"))
        mock_mkdir.assert_called_once_with(exist_ok=True)
        print(" -> SUCCESS: _create_output_dir initialized correct output path.")

    @patch('automation.run_command_sync')
    def test_check_volatility(self, mock_run):
        print("\n[TESTING] VolatilityGUI._check_volatility...")
        mock_run.return_value = (0, "Volatility 3 Framework", "")
        self.app.log = MagicMock()
        
        self.app._check_volatility()
        
        self.app.log.assert_called_with("Volatility 3 detected and ready.", "SUCCESS")
        print(" -> SUCCESS: _check_volatility detected Volatility correctly.")

    def test_render_table(self):
        print("\n[TESTING] VolatilityGUI._render_table...")
        # Mock Treeview and its methods
        self.app.tree = MagicMock()
        self.app.tree.get_children.return_value = []
        
        test_json = json.dumps([{"PID": 123, "Name": "test.exe", "Threat": "None"}])
        
        self.app._render_table(test_json)
        
        # Verify columns were set
        self.app.tree.__setitem__.assert_called() 
        # Verify heading was set (at least one)
        self.app.tree.heading.assert_called()
        # Verify data was inserted
        self.app.tree.insert.assert_called()
        print(" -> SUCCESS: _render_table correctly parsed JSON and updated Treeview.")

    @patch('automation.run_command_sync')
    @patch('automation.open', new_callable=mock_open)
    def test_run_plugin_logic(self, mock_file, mock_run):
        print("\n[TESTING] VolatilityGUI._run_plugin_logic...")
        self.app.memory_image = "test.vmem"
        self.app.output_dir = Path("test_output")
        self.app.log = MagicMock()
        self.app._get_vol_command = MagicMock(return_value=("cmd", "plugin", "windows"))
        
        mock_run.return_value = (0, "dummy output", "")
        
        success, data = self.app._run_plugin_logic("pslist")
        
        self.assertTrue(success)
        self.assertEqual(data, "dummy output")
        mock_file.assert_called()
        print(" -> SUCCESS: _run_plugin_logic executed plugin and saved results.")

if __name__ == '__main__':
    unittest.main()
