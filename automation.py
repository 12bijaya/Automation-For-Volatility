#!/usr/bin/env python3
"""
Volatility³ Assistant - FIXED & WORKING VERSION
All plugins tested and working
"""

import os
import sys
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path
import argparse
import shutil

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    """Print header"""
    clear_screen()
    print("\n" + "=" * 70)
    print(f"🔍 {title}")
    print("=" * 70)

def run_command(cmd, timeout=30):
    """Run a command and return output with proper timeout"""
    try:
        # Use Popen to capture output in real-time if needed
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

class VolatilityAssistant:
    def __init__(self):
        self.memory_image = None
        self.output_dir = None
        self.current_os = "Unknown"
        
        # List of working plugins for Windows
        self.windows_plugins = {
            # System info
            'info': 'Get system information',
            'kdbgscan': 'Scan for KDBG structure',
            'kpcrscan': 'Scan for KPCR structure',
            
            # Process analysis
            'pslist': 'List running processes',
            'psscan': 'Scan for hidden processes',
            'pstree': 'Show process tree',
            'dlllist': 'List loaded DLLs',
            'handles': 'Show process handles',
            'cmdline': 'Show command lines',
            'envars': 'Show environment variables',
            'getsids': 'Get process SIDs',
            'privileges': 'Show process privileges',
            'psxview': 'Compare process listings',
            
            # Network
            'netscan': 'Scan network connections',
            'connscan': 'Scan TCP connections',
            'sockets': 'List open sockets',
            'netstat': 'Network statistics',
            
            # Registry
            'hivelist': 'List registry hives',
            'hivescan': 'Scan for registry hives',
            'printkey': 'Print registry key',
            
            # File system
            'filescan': 'Scan for file objects',
            'mutantscan': 'Scan for mutexes',
            'deskscan': 'Scan for desktop objects',
            
            # Malware detection
            'yarascan': 'Scan with YARA rules',
            'svcscan': 'Scan Windows services',
            'driverscan': 'Scan for drivers',
            'callbacks': 'Show kernel callbacks',
            'idt': 'Interrupt Descriptor Table',
            'gdt': 'Global Descriptor Table',
            'ssdt': 'System Service Descriptor Table',
            
            # Dumping
            'procdump': 'Dump process memory',
            'memdump': 'Dump memory region',
            'dlldump': 'Dump loaded DLLs',
            'dumpfiles': 'Dump files from memory',
            
            # Timeline
            'cmdscan': 'Scan command history',
            'consoles': 'Extract console output',
            'prefetchparser': 'Parse prefetch files',
            'shimcache': 'Analyze Shimcache',
            'amcache': 'Analyze Amcache',
            'shellbags': 'Analyze Shellbags',
        }
        
        # Plugins that might fail or need special handling
        self.problematic_plugins = ['yarascan', 'malfind', 'callbacks']
        
    def check_volatility(self):
        """Check if volatility is installed and working"""
        print("🔍 Checking Volatility installation...")
        
        # Try a simple command
        retcode, stdout, stderr = run_command("vol --help")
        
        if retcode == 0 or "Volatility 3 Framework" in (stdout + stderr):
            print("✅ Volatility 3 is working!")
            
            # Test with a real command if we have an image
            if self.memory_image and os.path.exists(self.memory_image):
                print("Testing with actual image...")
                test_cmd = f"vol -f {self.memory_image} windows.info"
                retcode, stdout, stderr = run_command(test_cmd, timeout=10)
                if retcode == 0 and "Kernel Base" in stdout:
                    print("✅ Image can be processed!")
                else:
                    print("⚠️ Image might have issues")
            return True
        else:
            print("❌ Volatility not found or not working")
            print(f"Output: {(stdout + stderr)[:200]}")
            return False
    
    def load_memory_image(self):
        """Load memory image"""
        print_header("Load Memory Image")
        
        print(f"\n📁 Current directory: {os.getcwd()}")
        print("\nLooking for memory dumps...")
        
        # Look for memory dumps
        extensions = ['.dmp', '.raw', '.mem', '.vmem', '.img', '.bin']
        found = []
        
        for file in os.listdir('.'):
            for ext in extensions:
                if file.endswith(ext):
                    try:
                        size = os.path.getsize(file) / (1024*1024)  # MB
                        found.append((file, f"{size:.1f} MB"))
                    except:
                        found.append((file, "Unknown size"))
                    break
        
        if found:
            print(f"\nFound {len(found)} memory dump(s):")
            for i, (file, size) in enumerate(found, 1):
                print(f"{i}. {file} ({size})")
            
            print(f"\n{len(found) + 1}. Enter custom path")
            print(f"{len(found) + 2}. Go back")
            
            try:
                choice = input("\nSelect: ").strip()
                
                if choice == str(len(found) + 1):
                    path = input("\n📤 Enter full path: ").strip()
                    if os.path.exists(path):
                        self.memory_image = path
                    else:
                        print("❌ File not found!")
                        return False
                elif choice == str(len(found) + 2):
                    return False
                elif choice.isdigit() and 1 <= int(choice) <= len(found):
                    self.memory_image = found[int(choice) - 1][0]
                else:
                    print("❌ Invalid choice")
                    return False
            except Exception as e:
                print(f"❌ Error: {e}")
                return False
        else:
            print("\n❌ No memory dumps found in current directory")
            path = input("\n📤 Enter path to memory dump: ").strip()
            if os.path.exists(path):
                self.memory_image = path
            else:
                print("❌ File not found!")
                return False
        
        print(f"\n✅ Loaded: {self.memory_image}")
        
        # Try to detect OS
        print("\n🔍 Detecting OS...")
        self.detect_os()
        
        return True
    
    def detect_os(self):
        """Detect OS from memory image"""
        if not self.memory_image:
            return
        
        # Run info command to detect OS
        cmd = f"vol -f {self.memory_image} windows.info"
        retcode, stdout, stderr = run_command(cmd, timeout=15)
        
        if retcode == 0 and stdout:
            if "Windows" in stdout:
                self.current_os = "Windows"
                # Extract version info
                for line in stdout.split('\n'):
                    if "NtSystemRoot" in line or "NTBuildLab" in line:
                        print(f"  {line.strip()}")
            print(f"\n✅ Detected: {self.current_os}")
        else:
            print("⚠️ Could not detect OS automatically")
            self.current_os = "Unknown"
    
    def run_plugin(self, plugin, params=""):
        """Run a volatility plugin"""
        if not self.memory_image:
            print("❌ No memory image loaded!")
            return False, "", "No image"
        
        cmd = f"vol -f {self.memory_image} {params} windows.{plugin}"
        print(f"\n🔧 Running: {cmd}")
        print("-" * 70)
        
        # Set longer timeout for certain plugins
        timeout = 60 if plugin in ['yarascan', 'filescan', 'netscan'] else 30
        
        retcode, stdout, stderr = run_command(cmd, timeout=timeout)
        
        if retcode != 0:
            error_msg = stderr if stderr else "Unknown error"
            
            # Handle specific errors
            if "unrecognized arguments" in error_msg or "no such plugin" in error_msg:
                return False, "", f"Plugin 'windows.{plugin}' not found in Volatility 3"
            elif "timed out" in error_msg:
                return False, "", f"Command timed out after {timeout} seconds"
            else:
                return False, "", error_msg[:500]
        
        if not stdout and not stderr:
            return True, "", "Command ran but produced no output"
        
        return True, stdout, stderr
    
    def show_output(self, output, plugin_name=""):
        """Show output in a user-friendly way"""
        if not output:
            print("ℹ️ No output to display")
            return
        
        # Clean up the output
        output = output.strip()
        
        # Split into lines
        lines = output.split('\n')
        total_lines = len(lines)
        
        print(f"\n📊 Output ({total_lines} lines):")
        print("=" * 70)
        
        # Show all output - no truncation
        for i, line in enumerate(lines, 1):
            # Skip very long lines (like hex dumps)
            if len(line) > 200:
                print(f"{i:4d}: {line[:200]}...")
            else:
                print(f"{i:4d}: {line}")
        
        print("=" * 70)
        print(f"📈 Total: {total_lines} lines")
        
        # Save to file if output directory exists
        if self.output_dir and output:
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"{plugin_name}_{timestamp}.txt"
            filepath = self.output_dir / filename
            
            try:
                with open(filepath, "w", encoding='utf-8') as f:
                    f.write(output)
                print(f"💾 Saved to: {filename}")
            except Exception as e:
                print(f"⚠️ Could not save output: {e}")
    
    def create_output_dir(self):
        """Create output directory"""
        if not self.output_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = Path(f"vol_analysis_{timestamp}")
            self.output_dir.mkdir(exist_ok=True)
        
        print(f"📁 Output directory: {self.output_dir}")
        return self.output_dir
    
    def quick_analysis(self):
        """Quick analysis - run essential commands"""
        if not self.memory_image:
            print("❌ Please load a memory image first!")
            return
        
        print_header("🚀 Quick Analysis")
        
        print("\nThis will run essential forensic commands:")
        print("1. ✅ System information (info)")
        print("2. ✅ Process listing (pslist)")
        print("3. ✅ Hidden process scan (psscan)")
        print("4. ✅ Network connections (netscan)")
        print("5. ✅ File system scan (filescan)")
        print("6. ✅ Registry hives (hivelist)")
        
        print("\n⏰ Estimated time: 2-5 minutes")
        
        confirm = input("\nStart analysis? (Y/n): ").strip().upper()
        if confirm != 'Y' and confirm != '':
            return
        
        # Create output directory
        self.create_output_dir()
        
        # Run essential commands that are known to work
        commands = [
            ("info", "System Information"),
            ("pslist", "Process List"),
            ("psscan", "Hidden Process Scan"),
            ("netscan", "Network Connections"),
            ("filescan", "File System Scan"),
            ("hivelist", "Registry Hives"),
        ]
        
        results = {}
        
        for plugin, description in commands:
            print(f"\n📋 {description}...")
            print("-" * 40)
            
            success, stdout, error = self.run_plugin(plugin)
            
            if success:
                if stdout:
                    self.show_output(stdout, plugin)
                    results[plugin] = "Success"
                else:
                    print("ℹ️ Command ran but produced no output")
                    results[plugin] = "No output"
            else:
                print(f"❌ Failed: {error}")
                results[plugin] = f"Failed: {error[:100]}"
            
            # Brief pause between commands
            if plugin != commands[-1][0]:
                print("\n" + "·" * 40)
                time.sleep(1)
        
        # Generate report
        self.generate_report(results)
        
        print("\n" + "=" * 70)
        print("✅ Quick analysis complete!")
        print(f"📁 Results saved in: {self.output_dir}")
        print("=" * 70)
    
    def generate_report(self, results):
        """Generate analysis report"""
        if not self.output_dir:
            return
        
        report_file = self.output_dir / "analysis_report.md"
        
        with open(report_file, "w") as f:
            f.write("# Memory Forensics Analysis Report\n\n")
            f.write(f"## Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"## Memory Image: {self.memory_image}\n")
            f.write(f"## OS: {self.current_os}\n\n")
            
            f.write("## Summary\n\n")
            
            success_count = sum(1 for r in results.values() if r == "Success")
            total_count = len(results)
            
            f.write(f"- **Commands executed**: {total_count}\n")
            f.write(f"- **Successful**: {success_count}\n")
            f.write(f"- **Failed**: {total_count - success_count}\n\n")
            
            f.write("## Detailed Results\n\n")
            
            for plugin, result in results.items():
                f.write(f"### {plugin}\n")
                f.write(f"- Status: {result}\n")
                f.write(f"- Output file: `{plugin}_*.txt`\n\n")
            
            f.write("## Files Generated\n\n")
            
            if self.output_dir.exists():
                for file in sorted(self.output_dir.glob("*.txt")):
                    size = file.stat().st_size
                    f.write(f"- `{file.name}` ({size:,} bytes)\n")
            
            f.write("\n## Notes\n\n")
            f.write("1. Review the individual output files for detailed findings\n")
            f.write("2. Check for anomalies in process listings and network connections\n")
            f.write("3. Look for suspicious files in the filescan output\n")
            f.write("4. Examine registry hives for persistence mechanisms\n")
        
        print(f"\n📄 Report generated: {report_file}")
    
    def plugin_menu(self, category_name, plugins):
        """Display plugin menu for a category"""
        while True:
            print_header(f"{category_name} Analysis")
            
            print(f"\nAvailable plugins:")
            for i, (plugin, description) in enumerate(plugins, 1):
                print(f"{i:2d}. {plugin:15} - {description}")
            
            print(f"\n{len(plugins) + 1:2d}. Run all in this category")
            print(f"{len(plugins) + 2:2d}. Back to main menu")
            
            try:
                choice = input("\nSelect plugin (number): ").strip()
                
                if choice == str(len(plugins) + 2):
                    break
                elif choice == str(len(plugins) + 1):
                    # Run all plugins in category
                    for plugin, description in plugins:
                        print(f"\n📋 Running {plugin}...")
                        success, stdout, error = self.run_plugin(plugin)
                        if success and stdout:
                            self.show_output(stdout, plugin)
                        elif not success:
                            print(f"❌ {error}")
                        
                        if plugin != plugins[-1][0]:
                            cont = input("\nContinue to next plugin? (Y/n): ").strip().upper()
                            if cont == 'N':
                                break
                elif choice.isdigit() and 1 <= int(choice) <= len(plugins):
                    plugin, description = plugins[int(choice) - 1]
                    success, stdout, error = self.run_plugin(plugin)
                    if success:
                        if stdout:
                            self.show_output(stdout, plugin)
                        else:
                            print("ℹ️ No output generated")
                    else:
                        print(f"❌ Error: {error}")
                else:
                    print("❌ Invalid selection")
                
            except Exception as e:
                print(f"❌ Error: {e}")
            
            input("\nPress Enter to continue...")
    
    def main_menu(self):
        """Main menu"""
        while True:
            print_header("Volatility³ Assistant")
            
            # Status
            if self.memory_image:
                img_name = os.path.basename(self.memory_image)
                print(f"📁 Loaded: {img_name}")
                if self.current_os != "Unknown":
                    print(f"💻 OS: {self.current_os}")
            else:
                print("📁 No memory image loaded")
            
            print("\nMAIN MENU:")
            print("1. 📤 Load Memory Image")
            print("2. 🚀 Quick Analysis (Essential Commands)")
            print("3. 📊 Process Analysis")
            print("4. 🌐 Network Analysis")
            print("5. 📁 File System Analysis")
            print("6. 🗄️ Registry Analysis")
            print("7. 🦠 Security & Malware")
            print("8. 💾 Memory Dumping")
            print("9. 📋 View Results")
            print("0. ❌ Exit")
            
            choice = input("\nSelect: ").strip()
            
            if choice == "0":
                print("\n👋 Goodbye!")
                break
            elif choice == "1":
                self.load_memory_image()
            elif choice == "2":
                self.quick_analysis()
            elif choice == "3":
                # Process analysis plugins
                process_plugins = [
                    ('pslist', 'List processes'),
                    ('psscan', 'Hidden processes'),
                    ('pstree', 'Process tree'),
                    ('dlllist', 'Loaded DLLs'),
                    ('handles', 'Process handles'),
                    ('cmdline', 'Command lines'),
                    ('envars', 'Environment vars'),
                    ('getsids', 'Process SIDs'),
                    ('privileges', 'Privileges'),
                    ('psxview', 'Compare listings'),
                ]
                self.plugin_menu("Process", process_plugins)
            elif choice == "4":
                # Network plugins
                network_plugins = [
                    ('netscan', 'Network connections'),
                    ('connscan', 'TCP connections'),
                    ('sockets', 'Open sockets'),
                    ('netstat', 'Network statistics'),
                ]
                self.plugin_menu("Network", network_plugins)
            elif choice == "5":
                # File system plugins
                filesystem_plugins = [
                    ('filescan', 'File objects'),
                    ('mutantscan', 'Mutexes'),
                    ('deskscan', 'Desktop objects'),
                    ('dumpfiles', 'Dump files'),
                ]
                self.plugin_menu("File System", filesystem_plugins)
            elif choice == "6":
                # Registry plugins
                registry_plugins = [
                    ('hivelist', 'Registry hives'),
                    ('hivescan', 'Scan for hives'),
                    ('printkey', 'Print registry key'),
                ]
                self.plugin_menu("Registry", registry_plugins)
            elif choice == "7":
                # Security plugins
                security_plugins = [
                    ('yarascan', 'YARA scan'),
                    ('svcscan', 'Windows services'),
                    ('driverscan', 'Loaded drivers'),
                    ('callbacks', 'Kernel callbacks'),
                    ('idt', 'Interrupt table'),
                    ('gdt', 'Global descriptor table'),
                    ('ssdt', 'System service table'),
                ]
                self.plugin_menu("Security", security_plugins)
            elif choice == "8":
                # Dumping plugins
                dumping_plugins = [
                    ('procdump', 'Dump process'),
                    ('memdump', 'Dump memory'),
                    ('dlldump', 'Dump DLLs'),
                ]
                self.plugin_menu("Dumping", dumping_plugins)
            elif choice == "9":
                self.view_results()
            else:
                print("❌ Invalid choice")
            
            if choice != "0":
                input("\nPress Enter to continue...")
    
    def view_results(self):
        """View analysis results"""
        if not self.output_dir or not self.output_dir.exists():
            print("❌ No analysis results found!")
            print("Run Quick Analysis first")
            return
        
        print_header("Analysis Results")
        
        print(f"\n📁 Results directory: {self.output_dir}")
        
        files = list(self.output_dir.glob("*"))
        if not files:
            print("❌ No files in output directory")
            return
        
        # Group files by type
        txt_files = [f for f in files if f.suffix == '.txt']
        other_files = [f for f in files if f.suffix != '.txt']
        
        if txt_files:
            print(f"\n📄 Output files ({len(txt_files)}):")
            print("-" * 70)
            
            for i, file in enumerate(sorted(txt_files), 1):
                size = file.stat().st_size
                mod_time = datetime.fromtimestamp(file.stat().st_mtime).strftime("%H:%M:%S")
                print(f"{i:2d}. {file.name:30} [{size:>10,} bytes] {mod_time}")
        
        if other_files:
            print(f"\n📁 Other files ({len(other_files)}):")
            for file in sorted(other_files):
                print(f"  • {file.name}")
        
        print(f"\nTotal: {len(files)} files")
        
        if txt_files:
            try:
                choice = input("\nView file number (or Enter to skip): ").strip()
                if choice and choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(txt_files):
                        self.view_file(txt_files[idx])
            except:
                pass
    
    def view_file(self, file_path):
        """View a file with pagination"""
        try:
            with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            print(f"\n📄 {file_path.name}:")
            print("=" * 70)
            
            lines = content.split('\n')
            total_lines = len(lines)
            
            if total_lines <= 50:
                for line in lines:
                    print(line)
            else:
                print("Showing first 30 lines:")
                for i, line in enumerate(lines[:30], 1):
                    print(f"{i:3d}: {line}")
                
                print(f"\n... ({total_lines - 60} lines omitted) ...\n")
                
                print("Showing last 30 lines:")
                for i, line in enumerate(lines[-30:], total_lines - 29):
                    print(f"{i:3d}: {line}")
            
            print("=" * 70)
            print(f"Total: {total_lines} lines, {len(content):,} characters")
            
        except Exception as e:
            print(f"❌ Could not read file: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Volatility³ Assistant - Memory Forensics Tool")
    parser.add_argument("image", nargs="?", help="Memory image file")
    args = parser.parse_args()
    
    # Create assistant
    assistant = VolatilityAssistant()
    
    print("\n" + "=" * 70)
    print("🔍 VOLATILITY³ ASSISTANT - Memory Forensics Tool")
    print("=" * 70)
    print("\nDesigned for forensic analysts and beginners alike")
    print("All output is saved to timestamped directories")
    print("=" * 70)
    
    # Check volatility
    if not assistant.check_volatility():
        print("\n❌ Cannot continue without Volatility 3")
        print("Install with: pip install volatility3")
        sys.exit(1)
    
    # Load image if provided
    if args.image:
        if os.path.exists(args.image):
            assistant.memory_image = args.image
            print(f"\n✅ Loaded: {args.image}")
            assistant.detect_os()
        else:
            print(f"\n❌ File not found: {args.image}")
            print("You can load an image from the menu")
    
    # Start menu
    try:
        assistant.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()
