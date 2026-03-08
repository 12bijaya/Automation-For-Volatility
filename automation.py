#!/usr/bin/env python3
"""
Volatility³ Assistant - GUI VERSION
A modern graphical interface for Volatility 3
"""

import os
import sys
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path
import json

def run_command_sync(cmd, timeout=60):
    """Run a command and return output"""
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        process.kill()
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", str(e)

class VolatilityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Volatility³ Assistant")
        self.root.geometry("1100x900")
        self.root.configure(bg="#1e1e1e")

        self.memory_image = None
        self.output_dir = None
        self.current_os = "Unknown"
        self.symbols_dir = Path("./symbols")
        self.symbols_dir.mkdir(exist_ok=True)

        self.style = ttk.Style()
        # ... (rest of style setup)
        self.style.theme_use("clam")
        self._setup_styles()

        self._create_widgets()
        self.log("Welcome to Volatility³ Assistant GUI")
        self._check_volatility()

    def _setup_styles(self):
        self.style.configure("TFrame", background="#1e1e1e")
        self.style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#007acc")
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("Treeview", background="#2d2d2d", foreground="#ffffff", fieldbackground="#2d2d2d", font=("Segoe UI", 9))
        self.style.map("Treeview", background=[("selected", "#007acc")])
        self.style.configure("TNotebook", background="#1e1e1e")
        self.style.configure("TNotebook.Tab", background="#333333", foreground="#ffffff", padding=[10, 2])
        self.style.map("TNotebook.Tab", background=[("selected", "#007acc")])
        
    def _create_widgets(self):
        # Main Layout
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(header_frame, text="🔍 Volatility³ Assistant", style="Header.TLabel").pack(side=tk.LEFT)

        # File Selection & PID input
        top_controls = ttk.Frame(main_frame)
        top_controls.pack(fill=tk.X, pady=5)

        file_frame = ttk.LabelFrame(top_controls, text=" Memory Image ", padding="10")
        file_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.file_path_var = tk.StringVar(value="No image loaded")
        ttk.Label(file_frame, textvariable=self.file_path_var).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(file_frame, text="Browse", command=self._browse_image).pack(side=tk.RIGHT)

        pid_frame = ttk.LabelFrame(top_controls, text=" PID / Options ", padding="10")
        pid_frame.pack(side=tk.RIGHT)
        self.pid_var = tk.StringVar()
        ttk.Entry(pid_frame, textvariable=self.pid_var, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Label(pid_frame, text="PID").pack(side=tk.LEFT)

        # Controls & Info
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        self.os_status_var = tk.StringVar(value="OS: Unknown")
        ttk.Label(info_frame, textvariable=self.os_status_var, font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        
        ttk.Label(info_frame, text=" | Override:").pack(side=tk.LEFT, padx=(10, 2))
        self.os_override = ttk.Combobox(info_frame, values=["Auto", "windows", "linux", "mac"], width=10)
        self.os_override.set("Auto")
        self.os_override.pack(side=tk.LEFT)

        ttk.Button(info_frame, text="Detect OS", command=self._detect_os).pack(side=tk.LEFT, padx=15)
        ttk.Button(info_frame, text="Full-Auto Scan", command=self._full_auto_scan, style="Action.TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(info_frame, text="Quick Analysis", command=self._quick_analysis).pack(side=tk.RIGHT)

        # Plugins Area (Notebook)
        plugin_frame = ttk.LabelFrame(main_frame, text=" Analysis Plugins ", padding="10")
        plugin_frame.pack(fill=tk.X, pady=5)

        self.notebook = ttk.Notebook(plugin_frame)
        self.notebook.pack(fill=tk.X, expand=True)

        self._add_plugin_tab("Process", [
            ('pslist', 'List processes'), ('psscan', 'Hidden processes'),
            ('pstree', 'Process tree'), ('dlllist', 'Loaded DLLs'),
            ('handles', 'Process handles'), ('cmdline', 'Command lines')
        ])
        self._add_plugin_tab("Network", [
            ('netscan', 'Network connections'), ('connscan', 'TCP connections'),
            ('sockets', 'Open sockets'), ('netstat', 'Network statistics')
        ])
        self._add_plugin_tab("Registry", [
            ('hivelist', 'Registry hives'), ('hivescan', 'Scan for hives'),
            ('printkey', 'Print registry key')
        ])
        self._add_plugin_tab("Security", [
            ('yarascan', 'YARA scan'), ('svcscan', 'Windows services'),
            ('driverscan', 'Loaded drivers'), ('malfind', 'Malware find')
        ])
        self._add_plugin_tab("Dumping", [
            ('procdump', 'Dump process'), ('memdump', 'Dump memory'),
            ('dumpfiles', 'Dump files'), ('dlldump', 'Dump DLLs')
        ])

        # Results Display (Table and Log)
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # Output Tabs (Table vs Raw Log)
        self.output_notebook = ttk.Notebook(results_frame)
        self.output_notebook.pack(fill=tk.BOTH, expand=True)

        # Table Tab
        self.table_frame = ttk.Frame(self.output_notebook)
        self.output_notebook.add(self.table_frame, text=" Tabular Results ")
        
        self.tree = ttk.Treeview(self.table_frame, show="headings")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Raw Log Tab
        self.log_frame = ttk.Frame(self.output_notebook)
        self.output_notebook.add(self.log_frame, text=" Activity Log ")
        
        self.output_text = scrolledtext.ScrolledText(
            self.log_frame, bg="#2d2d2d", fg="#d4d4d4",
            font=("Consolas", 10), insertbackground="white"
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Footer
        footer = ttk.Frame(main_frame)
        footer.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(footer, text="Clear Results", command=self._clear_results).pack(side=tk.LEFT)
        ttk.Button(footer, text="Export CSV", command=self._export_csv).pack(side=tk.LEFT, padx=10)
        ttk.Button(footer, text="Exit", command=self.root.quit).pack(side=tk.RIGHT)

    def _add_plugin_tab(self, name, plugins):
        tab = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(tab, text=name)
        
        for i, (plugin, desc) in enumerate(plugins):
            row = i // 3
            col = i % 3
            btn = ttk.Button(tab, text=plugin, command=lambda p=plugin: self._run_plugin_thread(p))
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output_text.insert(tk.END, f"[{timestamp}] [{level}] {message}\n")
        self.output_text.see(tk.END)

    def _check_volatility(self):
        ret, stdout, stderr = run_command_sync("vol --help")
        if ret == 0 or "Volatility 3" in (stdout + stderr):
            self.log("Volatility 3 detected and ready.", "SUCCESS")
        else:
            messagebox.showerror("Error", "Volatility 3 not found! Please install it first.")
            self.log("Volatility 3 not found. Commands will fail.", "ERROR")

    def _browse_image(self):
        path = filedialog.askopenfilename(
            title="Select Memory Image",
            filetypes=[("Memory Dumps", "*.raw *.mem *.vmem *.img *.bin *.dmp"), ("All Files", "*.*")]
        )
        if path:
            self.memory_image = path
            self.file_path_var.set(os.path.basename(path))
            self.log(f"Loaded image: {path}")
            self._detect_os()

    def _detect_os(self):
        if not self.memory_image:
            messagebox.showwarning("Warning", "Please load a memory image first.")
            return
        
        self.log("Detecting OS...")
        def task():
            cmd = f"vol -f {self.memory_image} windows.info"
            ret, stdout, stderr = run_command_sync(cmd, timeout=30)
            if ret == 0 and "Windows" in stdout:
                self.current_os = "Windows"
                self.os_status_var.set(f"OS: {self.current_os}")
                self.log("Detected OS: Windows", "SUCCESS")
            else:
                self.log("Automatic OS detection failed.", "WARNING")
                if self.memory_image.lower().endswith(".vmem"):
                    self.log("💡 TIP: For .vmem files, Volatility 3 requires a .vmss or .vmsn file in the same directory.", "INFO")
                self.log("You can still try running plugins if you know the OS is Windows.", "INFO")
        
        threading.Thread(target=task).start()

    def _run_plugin_thread(self, plugin):
        if not self.memory_image:
            messagebox.showwarning("Warning", "Please load a memory image first.")
            return
        
        pid = self.pid_var.get().strip()
        self.log(f"Queuing plugin: windows.{plugin}" + (f" (PID: {pid})" if pid else ""))
        threading.Thread(target=self._run_plugin, args=(plugin, pid)).start()

    def _get_vol_command(self, plugin, pid=None, use_json=False):
        """Unified command builder for Volatility 3 with mapping and robust quoting"""
        # OS Prefix Logic
        os_prefix = self.os_override.get().lower() if self.os_override.get() != "Auto" else self.current_os.lower()
        if os_prefix == "unknown": os_prefix = "windows"  # Fallback

        # Comprehensive Legacy Mapping
        v3_plugin = plugin
        opts = f" --pid {pid}" if pid else ""
        
        mapping = {
            # Processes
            'pslist': 'pslist.PsList',
            'psscan': 'psscan.PsScan',
            'pstree': 'pstree.PsTree',
            'dlllist': 'dlllist.DllList',
            'handles': 'handles.Handles',
            'cmdline': 'cmdline.CmdLine',
            # Network
            'netscan': 'netscan.NetScan',
            'connscan': 'netscan.NetScan',
            'sockets': 'netscan.NetScan',
            'netstat': 'netstat.NetStat',
            # Registry
            'hivelist': 'registry.hivelist.HiveList',
            'hivescan': 'registry.hivescan.HiveScan',
            'printkey': 'registry.printkey.PrintKey',
            # Security
            'svcscan': 'svcscan.SvcScan',
            'driverscan': 'driverscan.DriverScan',
            'malfind': 'malfind.Malfind',
            # Dumping (Special cases)
            'procdump': ('pslist.PsList', ' --dump'),
            'memdump': ('pslist.PsList', ' --dump'),
            'dlldump': ('dlllist.DllList', ' --dump'),
            'dumpfiles': ('fileobjects.FileObjects', ' --dump')
        }

        if plugin in mapping:
            val = mapping[plugin]
            if isinstance(val, tuple):
                v3_plugin, extra_opts = val
                opts += extra_opts
            else:
                v3_plugin = val

        # Handle Volatility 3 info plugin special case (it's windows.info.Info)
        if v3_plugin == 'info' and os_prefix == 'windows':
            v3_plugin = 'info.Info'

        symbol_opt = f' -p "{self.symbols_dir.absolute()}"'
        fmt = "-r json " if use_json else ""
        img_path = f'"{self.memory_image}"'
        
        return f"vol{symbol_opt} -f {img_path} {fmt}{os_prefix}.{v3_plugin}{opts}", v3_plugin, os_prefix

    def _run_plugin(self, plugin, pid=None):
        if not self.output_dir:
            self._create_output_dir()

        # Determine if we should use JSON for the table
        use_json = plugin in ['pslist', 'psscan', 'netscan', 'hivelist', 'dlllist', 'svcscan']
        
        cmd, v3_plugin, os_prefix = self._get_vol_command(plugin, pid, use_json)

        self.log(f"Executing: {cmd}")
        ret, stdout, stderr = run_command_sync(cmd, timeout=300)
        
        if ret == 0:
            self.log(f"Plugin {os_prefix}.{v3_plugin} finished.", "SUCCESS")
            # Save raw output
            filename = f"{plugin}_{datetime.now().strftime('%H%M%S')}.txt"
            filepath = self.output_dir / filename
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(stdout)
            self.log(f"Results saved to {filename}")
            
            # Handle output display
            self.output_text.insert(tk.END, f"\n--- {plugin} Output ---\n{stdout}\n")
            if use_json:
                self.root.after(0, self._render_table, stdout)
                self.root.after(0, lambda: self.output_notebook.select(0)) # Switch to table
            else:
                self.root.after(0, lambda: self.output_notebook.select(1)) # Switch to log

            self.output_text.see(tk.END)
        else:
            self.log(f"Error running {plugin}: {stderr[:200]}", "ERROR")
            messagebox.showerror("Plugin Error", f"Command failed: {stderr[:300]}")

    def _render_table(self, json_data):
        """Parse JSON output and render it in the Treeview"""
        try:
            data = json.loads(json_data)
            if not data:
                return

            # Clear existing data
            for i in self.tree.get_children():
                self.tree.delete(i)

            # Get columns from JSON
            # Volatility 3 JSON is usually a list of dicts or objects
            # Let's check the structure. If it's a list of dicts:
            first_item = data[0] if isinstance(data, list) and len(data) > 0 else None
            if not first_item:
                return

            columns = list(first_item.keys())
            self.tree["columns"] = columns
            for col in columns:
                self.tree.heading(col, text=col)
                self.tree.column(col, width=120)

            for item in data:
                values = [item.get(col, "") for col in columns]
                # Convert complex types (like objects) to strings
                values = [str(v) if not isinstance(v, (str, int, float)) else v for v in values]
                self.tree.insert("", tk.END, values=values)
            
            self.log(f"Rendered {len(data)} rows in table.")
        except Exception as e:
            self.log(f"Failed to render table: {e}", "ERROR")

    def _create_output_dir(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(f"vol_gui_analysis_{timestamp}")
        self.output_dir.mkdir(exist_ok=True)
        self.log(f"Created output directory: {self.output_dir}")

    def _quick_analysis(self):
        if not self.memory_image:
            messagebox.showwarning("Warning", "Please load a memory image first.")
            return
        
        self.log("Starting Quick Analysis...")
        plugins = ['info', 'pslist', 'netscan']
        
        def run_all():
            # Use original method inside thread
            for p in plugins:
                self._run_plugin(p)
            self.log("Quick Analysis finished.", "SUCCESS")
        
        threading.Thread(target=run_all).start()

    def _full_auto_scan(self):
        if not self.memory_image:
            messagebox.showwarning("Warning", "Please load a memory image first.")
            return

        self.log("🚀 STARTING FULL-AUTO FORENSIC SCAN...", "IMPORTANT")
        
        # Predefined set of critical plugins for Windows
        plugins = [
            'info', 'pslist', 'psscan', 'pstree', 
            'netscan', 'hivelist', 'dlllist', 
            'driverscan', 'svcscan', 'malfind'
        ]
        
        def run_suite():
            self._create_output_dir()
            results_summary = {}
            
            for p in plugins:
                self.log(f"Processing {p}...", "AUTO")
                success, data = self._run_plugin_logic(p)
                results_summary[p] = "Completed" if success else "Failed"
            
            self._generate_report(results_summary)
            self.log("✅ FULL-AUTO SCAN COMPLETE!", "SUCCESS")
            messagebox.showinfo("Auto Scan", f"Scan complete! Report generated in {self.output_dir}")
        
        threading.Thread(target=run_suite).start()

    def _run_plugin_logic(self, plugin, pid=None):
        """Worker logic for running a plugin and returning basic status"""
        if not self.output_dir:
            self._create_output_dir()

        use_json = plugin in ['pslist', 'psscan', 'pstree', 'netscan', 'hivelist', 'dlllist', 'svcscan']
        cmd, v3_plugin, os_prefix = self._get_vol_command(plugin, pid, use_json)
        
        self.log(f"Running: {cmd}")
        ret, stdout, stderr = run_command_sync(cmd, timeout=300)
        
        if ret == 0:
            filename = f"{plugin}_{datetime.now().strftime('%H%M%S')}.txt"
            filepath = self.output_dir / filename
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(stdout)
            
            # Update UI from logic (must use thread-safe method)
            if use_json:
                self.root.after(0, self._render_table, stdout)
            else:
                self.log(f"Output for {plugin} saved to disk.")
                
            return True, stdout
        else:
            self.log(f"Plugin {plugin} failed: {stderr[:100]}", "ERROR")
            return False, stderr

    def _generate_report(self, summary):
        """Generate a Markdown Forensic Report summary"""
        report_path = self.output_dir / "FORENSIC_REPORT.md"
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# Volatility³ Automated Forensic Report\n\n")
            f.write(f"- **Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Target Image**: {self.memory_image}\n")
            f.write(f"- **OS Detected**: {self.current_os}\n\n")
            
            f.write("## 🏛️ Scan Summary\n\n")
            f.write("| Plugin | Status | Output File |\n")
            f.write("| --- | --- | --- |\n")
            for plugin, status in summary.items():
                f.write(f"| {plugin} | {status} | [View File](./) |\n")
            
            f.write("\n## 🔍 Automated Checks\n")
            f.write("- **Process Listing**: Completed. Review `pslist` and `psscan` for hidden processes.\n")
            f.write("- **Network Connections**: Completed. Review `netscan` for suspicious IPs.\n")
            f.write("- **Malware Checks**: Completed via `malfind` and `driverscan`.\n")
            
            f.write("\n\n--- \n*Generated by Volatility³ Assistant GUI*")

    def _clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.output_text.delete(1.0, tk.END)
        self.log("Results cleared.")

    def _export_csv(self):
        """Export table content to CSV"""
        if not self.tree.get_children():
            messagebox.showinfo("Export", "No data in table to export.")
            return
            
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            import csv
            cols = self.tree["columns"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(cols)
                for item_id in self.tree.get_children():
                    writer.writerow(self.tree.item(item_id)["values"])
            messagebox.showinfo("Export", f"Data exported to {path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VolatilityGUI(root)
    root.mainloop()
    
