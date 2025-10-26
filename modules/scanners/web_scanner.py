#!/usr/bin/env python3

import requests
import threading
import time
from queue import Queue
import sys
import re
from pathlib import Path

# Suppress warnings
import warnings
warnings.filterwarnings("ignore")

try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    from rich.text import Text
    from rich.align import Align
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

MODULE_INFO = {
    "name": "vulnerability/web_scanner",
    "description": "🔥 VULNERABILITY SCANNER - SQLi, XSS, LFI, RCE + Custom Wordlist"
}

OPTIONS = {
    "TARGET": {
        "required": True,
        "default": "http://localhost",
        "description": "Target URL to scan"
    },
    "SCAN_TYPE": {
        "required": False,
        "default": "all",
        "description": "Scan type: all, sqli, xss, lfi, rce, custom"
    },
    "METHOD": {
        "required": False,
        "default": "both",
        "description": "HTTP Method: get, post, both"
    },
    "THREADS": {
        "required": False,
        "default": "10",
        "description": "Number of threads"
    },
    "TIMEOUT": {
        "required": False,
        "default": "10",
        "description": "Request timeout"
    },
    "CUSTOM_WORDLIST": {
        "required": False,
        "default": "",
        "description": "Path to custom wordlist file"
    }
}

class VulnerabilityScanner:
    def __init__(self, options):
        self.options = options
        self.results = []
        self.vulnerabilities = []
        self.stats = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'critical': 0,
            'high': 0,
            'medium': 0
        }
        self.lock = threading.Lock()
        self.completed = 0
        self.session = requests.Session()
        self.custom_payloads = []
        self.setup_session()
        
    def setup_session(self):
        """Setup scanning session"""
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        
        # Load custom wordlist if provided
        self.load_custom_wordlist()
    
    def load_custom_wordlist(self):
        """Load custom wordlist from file"""
        custom_wordlist_path = self.options.get('CUSTOM_WORDLIST', '').strip()
        
        if not custom_wordlist_path:
            return
            
        try:
            wordlist_file = Path(custom_wordlist_path)
            if wordlist_file.is_file():
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    self.custom_payloads = [line.strip() for line in f if line.strip()]
                
                if RICH_AVAILABLE:
                    console.print(f"[green]✅ Loaded {len(self.custom_payloads)} custom payloads[/green]")
            else:
                if RICH_AVAILABLE:
                    console.print(f"[yellow]⚠️ Custom wordlist file not found[/yellow]")
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[red]❌ Error loading custom wordlist[/red]")
    
    def display_banner(self):
        """Display banner"""
        if not RICH_AVAILABLE:
            return
            
        banner_text = """
╔════════════════════════════════════════════════════════════════╗
║                   VULNERABILITY SCANNER                       ║
║               SQLi • XSS • LFI • RCE • Custom                 ║
╚════════════════════════════════════════════════════════════════╝
        """
        
        console.print(Panel.fit(
            Align.center("[bold red]" + banner_text + "[/bold red]"),
            style="red"
        ))
    
    def generate_test_payloads(self):
        """Generate test payloads"""
        payloads = {
            'sqli': {
                'name': 'SQL Injection',
                'severity': 'CRITICAL',
                'payloads': [
                    "' OR '1'='1",
                    "' UNION SELECT 1,2,3--",
                    "' AND 1=1--",
                    "admin'--",
                    "1' ORDER BY 1--"
                ]
            },
            'xss': {
                'name': 'Cross-Site Scripting',
                'severity': 'HIGH',
                'payloads': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>"
                ]
            },
            'lfi': {
                'name': 'Local File Inclusion',
                'severity': 'HIGH',
                'payloads': [
                    "../../../../etc/passwd",
                    "../../../../windows/win.ini",
                    "....//....//etc/passwd"
                ]
            },
            'rce': {
                'name': 'Remote Code Execution',
                'severity': 'CRITICAL',
                'payloads': [
                    ";id",
                    "|id",
                    "`id`",
                    "$(id)"
                ]
            },
            'custom': {
                'name': 'Custom Payloads',
                'severity': 'UNKNOWN',
                'payloads': self.custom_payloads if self.custom_payloads else ["test"]
            }
        }
        
        return payloads
    
    def detect_vulnerability(self, vuln_type, payload, response, method):
        """Detect if vulnerability is present"""
        content = response.text.lower()
        
        if vuln_type == 'sqli':
            patterns = ["mysql_fetch", "ora-", "sql syntax", "warning.*mysql"]
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True, "SQL injection detected"
            if response.elapsed.total_seconds() > 5:
                return True, "Time-based SQL injection"
                
        elif vuln_type == 'xss':
            if payload in response.text:
                return True, "XSS payload reflected"
                
        elif vuln_type == 'lfi':
            if 'root:' in content or '[fonts]' in content:
                return True, "File inclusion successful"
                
        elif vuln_type == 'rce':
            if 'uid=' in content or 'total' in content:
                return True, "Command execution detected"
                
        elif vuln_type == 'custom':
            if payload in response.text:
                return True, "Custom payload reflected"
            
        return False, ""
    
    def test_vulnerability(self, test_data):
        """Test a single vulnerability"""
        try:
            url = test_data['url']
            payload = test_data['payload']
            param = test_data['param']
            method = test_data['method']
            vuln_type = test_data['type']
            vuln_info = test_data['vuln_info']
            
            if method.upper() == 'GET':
                params = {param: payload}
                response = self.session.get(
                    url,
                    params=params,
                    timeout=int(self.options.get('TIMEOUT', 10)),
                    allow_redirects=False
                )
            else:
                data = {param: payload}
                response = self.session.post(
                    url,
                    data=data,
                    timeout=int(self.options.get('TIMEOUT', 10)),
                    allow_redirects=False
                )
            
            is_vulnerable, description = self.detect_vulnerability(vuln_type, payload, response, method)
            
            result = {
                'url': url,
                'parameter': param,
                'payload': payload,
                'method': method,
                'type': vuln_type,
                'vulnerability_name': vuln_info['name'],
                'severity': vuln_info['severity'],
                'status_code': response.status_code,
                'is_vulnerable': is_vulnerable,
                'description': description,
                'response_time': response.elapsed.total_seconds()
            }
            
            return result
            
        except Exception:
            return None
    
    def worker(self, queue):
        """Worker thread for scanning"""
        while True:
            try:
                test_data = queue.get_nowait()
            except:
                break
            
            result = self.test_vulnerability(test_data)
            
            with self.lock:
                self.completed += 1
                self.stats['total_tests'] += 1
                
                if result:
                    self.results.append(result)
                    
                    if result['is_vulnerable']:
                        self.vulnerabilities.append(result)
                        self.stats['vulnerabilities_found'] += 1
                        
                        severity = result['severity']
                        if severity == 'CRITICAL':
                            self.stats['critical'] += 1
                        elif severity == 'HIGH':
                            self.stats['high'] += 1
                        else:
                            self.stats['medium'] += 1
                        
                        self.display_vulnerability(result)
                
                if self.completed % 10 == 0:
                    self.update_progress_display()
            
            queue.task_done()
    
    def update_progress_display(self):
        """Update the progress display"""
        if not RICH_AVAILABLE:
            return
            
        total = self.stats['total_tests']
        vulns = self.stats['vulnerabilities_found']
        console.print(f"\r🔍 Progress: {self.completed}/{total} | Vulnerabilities: {vulns}", end="")
    
    def display_vulnerability(self, result):
        """Display found vulnerability"""
        if not RICH_AVAILABLE:
            print(f"VULN: {result['type'].upper()} in {result['parameter']}")
            return
        
        severity_colors = {
            'CRITICAL': 'red',
            'HIGH': 'magenta',
            'UNKNOWN': 'yellow'
        }
        
        color = severity_colors.get(result['severity'], 'white')
        
        vuln_text = Text()
        vuln_text.append("🚨 ", style="bold red")
        vuln_text.append(f"{result['vulnerability_name']} ", style=f"bold {color}")
        vuln_text.append(f"({result['severity']})", style="bold white")
        
        details = Text()
        details.append(f"📍 URL: {result['url']}\n", style="cyan")
        details.append(f"🔧 Parameter: {result['parameter']}\n", style="green")
        details.append(f"💣 Payload: {result['payload']}\n", style="red")
        details.append(f"📝 {result['description']}", style="white")
        
        vuln_panel = Panel(
            details,
            title=vuln_text,
            border_style=color
        )
        
        console.print(vuln_panel)
    
    def run(self):
        """Main scanning execution"""
        self.display_banner()
        
        if RICH_AVAILABLE:
            console.print(Panel(
                f"[bold cyan]🎯 Target:[/bold cyan] {self.options.get('TARGET')}\n"
                f"[bold green]🔧 Scan Type:[/bold green] {self.options.get('SCAN_TYPE').upper()}\n"
                f"[bold yellow]⚡ Method:[/bold yellow] {self.options.get('METHOD').upper()}\n"
                f"[bold blue]👥 Threads:[/bold blue] {self.options.get('THREADS')}",
                title="Configuration",
                style="blue"
            ))
        
        # Generate test cases
        test_cases = self.generate_test_cases()
        
        if not test_cases:
            console.print("[red]❌ No test cases generated[/red]")
            return
        
        if RICH_AVAILABLE:
            console.print(f"[yellow]📋 Total Test Cases: {len(test_cases)}[/yellow]")
        
        console.print("[yellow]🚀 Starting vulnerability scan...[/yellow]")
        
        # Setup queue
        queue = Queue()
        for test_case in test_cases:
            queue.put(test_case)
        
        start_time = time.time()
        
        # Start threads
        threads = []
        for i in range(int(self.options.get('THREADS', 10))):
            thread = threading.Thread(target=self.worker, args=(queue,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        queue.join()
        
        # Wait for threads
        for thread in threads:
            thread.join(timeout=1)
        
        # Clear progress
        if RICH_AVAILABLE:
            console.print("\r" + " " * 50 + "\r", end="")
        
        elapsed_time = time.time() - start_time
        
        # Display final results
        self.display_final_results(elapsed_time)
    
    def generate_test_cases(self):
        """Generate test cases"""
        target = self.options.get('TARGET', '')
        scan_type = self.options.get('SCAN_TYPE', 'all')
        method = self.options.get('METHOD', 'both')
        
        test_cases = []
        payloads = self.generate_test_payloads()
        
        parameters = ['id', 'user', 'search', 'query', 'file', 'page']
        
        if scan_type == 'all':
            types_to_scan = list(payloads.keys())
        else:
            types_to_scan = [scan_type]
        
        methods_to_use = []
        if method in ['get', 'both']:
            methods_to_use.append('GET')
        if method in ['post', 'both']:
            methods_to_use.append('POST')
        
        for vuln_type in types_to_scan:
            if vuln_type in payloads:
                vuln_info = payloads[vuln_type]
                
                if vuln_type == 'custom' and not self.custom_payloads:
                    continue
                    
                for payload in vuln_info['payloads']:
                    for param in parameters:
                        for method in methods_to_use:
                            test_cases.append({
                                'url': target,
                                'param': param,
                                'payload': payload,
                                'method': method,
                                'type': vuln_type,
                                'vuln_info': vuln_info
                            })
        
        return test_cases
    
    def display_final_results(self, elapsed_time):
        """Display final results"""
        if not RICH_AVAILABLE:
            print(f"Scan completed in {elapsed_time:.2f}s")
            print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
            return
        
        console.print(Panel(
            f"[bold green]✅ Scan Completed: {elapsed_time:.2f}s[/bold green]\n"
            f"[bold red]🚨 Vulnerabilities: {self.stats['vulnerabilities_found']}[/bold red]\n"
            f"[bold magenta]🔴 Critical: {self.stats['critical']}[/bold magenta]\n"
            f"[bold yellow]🟡 High: {self.stats['high']}[/bold yellow]\n"
            f"[bold cyan]📊 Total Tests: {self.stats['total_tests']}[/bold cyan]",
            title="Results",
            style="green"
        ))
        
        if self.vulnerabilities:
            console.print(Panel("[bold red]🚨 VULNERABILITIES FOUND[/bold red]", style="red"))
            
            table = Table(show_header=True)
            table.add_column("Type", style="cyan")
            table.add_column("Parameter", style="green")
            table.add_column("Payload", style="red")
            table.add_column("Description", style="white")
            
            for vuln in self.vulnerabilities:
                payload = vuln['payload']
                if len(payload) > 20:
                    payload = payload[:17] + "..."
                
                table.add_row(
                    vuln['type'].upper(),
                    vuln['parameter'],
                    payload,
                    vuln['description']
                )
            
            console.print(table)

def run(session, options):
    """Main function"""
    scanner = VulnerabilityScanner(options)
    scanner.run()
