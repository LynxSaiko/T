#!/usr/bin/python3

MODULE_INFO = {
    "name": "Router Network Scanner",
    "description": "Advanced network scanning for router discovery and service detection",
    "author": "Lazy Framework",
    "license": "MIT",
    "dependencies": ["requests"],
    "platform": "Multi",
    "rank": "Normal",
}

OPTIONS = {
    "target": {
        "description": "Target IP, range or subnet (e.g., 192.168.1.0/24, 192.168.1.1-100)",
        "required": True,
        "default": "192.168.1.0/24"
    },
    "ports": {
        "description": "Ports to scan (common, http, https, all, or custom: 80,443,8080)",
        "required": False,
        "default": "router"
    },
    "timeout": {
        "description": "Scan timeout per host in seconds",
        "required": False,
        "default": "2"
    },
    "threads": {
        "description": "Number of concurrent threads",
        "required": False,
        "default": "20"
    },
    "ping_check": {
        "description": "Enable ping check before port scanning",
        "required": False,
        "default": "true"
    }
}

class NetworkScanner:
    """Advanced network scanner with OOP design"""
    
    PORT_PROFILES = {
        "common": [21, 22, 23, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443],
        "http": [80, 443, 8080, 8443, 8000, 8888],
        "https": [443, 8443],
        "router": [23, 80, 443, 7547, 8080, 8291, 8443],
        "all": list(range(1, 1001))
    }
    
    ROUTER_BRANDS = {
        "cisco": ["cisco", "ios", "catalyst"],
        "tplink": ["tp-link", "tplink", "tp link"],
        "mikrotik": ["mikrotik", "routeros"],
        "dlink": ["d-link", "dlink"],
        "netgear": ["netgear"],
        "asus": ["asus", "asuswrt"],
        "linksys": ["linksys"],
        "huawei": ["huawei"],
        "zyxel": ["zyxel"],
        "ubiquiti": ["ubiquiti", "unifi"]
    }
    
    SERVICE_DB = {
        21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 
        110: "pop3", 135: "rpc", 139: "netbios", 143: "imap", 
        443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 7547: "tr-069", 8080: "http-proxy", 8291: "winbox",
        8443: "https-alt"
    }
    
    def __init__(self, console, target, ports="router", timeout=2, max_threads=20, ping_check=True):
        self.console = console
        self.target = target
        self.ports = self._resolve_port_profile(ports)
        self.timeout = timeout
        self.max_threads = max_threads
        self.ping_check = ping_check
        self.discovered_hosts = []
        self.scan_stats = {
            'total_hosts': 0,
            'active_hosts': 0,
            'open_ports': 0,
            'scan_duration': 0,
            'routers_found': 0
        }
    
    def _resolve_port_profile(self, ports_config):
        """Resolve port configuration to actual port list"""
        if ports_config in self.PORT_PROFILES:
            return self.PORT_PROFILES[ports_config]
        else:
            try:
                ports = []
                for part in ports_config.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(part))
                return ports
            except:
                return self.PORT_PROFILES["common"]
    
    def generate_ip_list(self):
        """Generate list of IP addresses from target specification"""
        import ipaddress
        
        ip_list = []
        
        try:
            if '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            elif '-' in self.target:
                start_ip, end_ip = self.target.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                
                if '.' in end_ip:
                    end = ipaddress.ip_address(end_ip.strip())
                else:
                    base = '.'.join(start_ip.split('.')[:-1])
                    end = ipaddress.ip_address(f"{base}.{end_ip.strip()}")
                
                current = start
                while current <= end:
                    ip_list.append(str(current))
                    current += 1
            else:
                ip_list = [self.target]
                
        except Exception as e:
            raise Exception(f"Invalid target format: {e}")
        
        self.scan_stats['total_hosts'] = len(ip_list)
        return ip_list
    
    def ping_host(self, ip):
        """Check if host is reachable using ICMP ping"""
        import os
        import platform
        
        try:
            param = "-n 1 -w 1000" if platform.system().lower() == "windows" else "-c 1 -W 1"
            response = os.system(f"ping {param} {ip} > /dev/null 2>&1")
            return response == 0
        except:
            return False
    
    def scan_port(self, ip, port):
        """Scan single port on host"""
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_service_info(self, ip, port):
        """Get service information by attempting banner grabbing"""
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                banner = ""
            
            sock.close()
            
            service_name = self.SERVICE_DB.get(port, "unknown")
            return service_name, banner[:100] if banner else ""
            
        except:
            service_name = self.SERVICE_DB.get(port, "unknown")
            return service_name, ""
    
    def detect_router_brand(self, banners):
        """Detect router brand from banners"""
        all_banners = " ".join(banners).lower()
        
        for brand, keywords in self.ROUTER_BRANDS.items():
            if any(keyword in all_banners for keyword in keywords):
                return brand.title()
        
        return "Unknown"
    
    def scan_host(self, ip):
        """Scan a single host for open ports and services"""
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        if self.ping_check and not self.ping_host(ip):
            return None
        
        open_ports = []
        banners = []
        
        with ThreadPoolExecutor(max_workers=min(10, len(self.ports))) as executor:
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in self.ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        service, banner = self.get_service_info(ip, port)
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'banner': banner,
                            'product': self._guess_product(service, banner)
                        })
                        if banner:
                            banners.append(banner)
                except Exception:
                    pass
        
        if open_ports or not self.ping_check:
            hostname = self._get_hostname(ip)
            router_brand = self.detect_router_brand(banners) if banners else "Unknown"
            is_router = self._is_router_like(open_ports)
            
            if is_router and router_brand != "Unknown":
                self.scan_stats['routers_found'] += 1
            
            return {
                'ip': ip,
                'hostname': hostname,
                'open_ports': open_ports,
                'os': self._guess_os(open_ports),
                'is_router': is_router,
                'router_brand': router_brand if is_router else "",
                'banners': banners
            }
        
        return None
    
    def _get_hostname(self, ip):
        """Attempt to resolve hostname"""
        import socket
        
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""
    
    def _guess_os(self, open_ports):
        """Guess operating system based on open ports"""
        port_services = {port_info['service'] for port_info in open_ports}
        
        if 135 in {p['port'] for p in open_ports} or 445 in {p['port'] for p in open_ports}:
            return "Windows"
        elif 111 in {p['port'] for p in open_ports}:
            return "Linux/Unix"
        elif 22 in {p['port'] for p in open_ports} and 25 not in {p['port'] for p in open_ports}:
            return "Linux"
        else:
            return "Unknown"
    
    def _guess_product(self, service, banner):
        """Guess product based on service and banner"""
        banner_lower = banner.lower()
        
        if service == "http" or service == "https":
            if "apache" in banner_lower:
                return "Apache"
            elif "nginx" in banner_lower:
                return "nginx"
            elif "iis" in banner_lower:
                return "IIS"
            elif "tomcat" in banner_lower:
                return "Tomcat"
            elif any(brand in banner_lower for brand in ["router", "wireless", "admin", "login"]):
                return "Router Web Interface"
            else:
                return "Web Server"
        
        elif service == "telnet":
            if any(brand in banner_lower for brand in ["router", "cisco", "mikrotik"]):
                return "Router Telnet"
            else:
                return "Telnet Service"
        
        elif service == "ssh":
            if "openbsd" in banner_lower:
                return "OpenSSH"
            elif "dropbear" in banner_lower:
                return "Dropbear SSH"
            else:
                return "SSH Server"
        
        return ""
    
    def _is_router_like(self, open_ports):
        """Determine if host appears to be a router based on open ports"""
        router_ports = {23, 80, 443, 7547, 8080, 8291, 8443}
        router_services = {'telnet', 'http', 'https'}
        
        port_numbers = {port_info['port'] for port_info in open_ports}
        services = {port_info['service'] for port_info in open_ports}
        
        return (any(port in router_ports for port in port_numbers) or 
                any(service in router_services for service in services))
    
    def run_scan(self):
        """Execute the network scan with simple progress visualization"""
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
        import time
        
        try:
            ip_list = self.generate_ip_list()
            self.console.print(f"[green]Targets: {len(ip_list)} IPs | Ports: {len(self.ports)}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
            return
        
        start_time = time.time()
        
        # Simple progress setup without spinner
        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        )
        
        with progress:
            main_task = progress.add_task(
                f"Scanning network", 
                total=len(ip_list)
            )
            
            lock = threading.Lock()
            
            def scan_with_progress(ip):
                """Scan host and update progress"""
                host_data = self.scan_host(ip)
                
                with lock:
                    if host_data:
                        self.discovered_hosts.append(host_data)
                        self.scan_stats['active_hosts'] += 1
                        self.scan_stats['open_ports'] += len(host_data['open_ports'])
                    
                    progress.advance(main_task)
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(scan_with_progress, ip) for ip in ip_list]
                for future in futures:
                    future.result()
        
        self.scan_stats['scan_duration'] = time.time() - start_time
    
    def display_results(self):
        """Display scanning results in clean format"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        
        if not self.discovered_hosts:
            self.console.print(Panel.fit(
                "No active hosts found",
                border_style="yellow"
            ))
            return
        
        self.discovered_hosts.sort(key=lambda x: (x['is_router'], len(x['open_ports'])), reverse=True)
        
        self.console.print(f"\n[bold green]Scan Complete: {len(self.discovered_hosts)} active hosts[/bold green]")
        
        for host in self.discovered_hosts:
            self._display_host_panel(host)
        
        self._display_summary_panel()
    
    def _display_host_panel(self, host):
        """Display individual host information panel"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        
        if host['is_router']:
            host_color = "red"
        elif len(host['open_ports']) > 0:
            host_color = "cyan"
        else:
            host_color = "yellow"
        
        host_info = f"[bold {host_color}]{host['ip']}[/bold {host_color}]"
        if host['hostname']:
            host_info += f" • {host['hostname']}"
        if host['os'] != 'Unknown':
            host_info += f" • {host['os']}"
        if host['is_router'] and host['router_brand']:
            host_info += f" • [bold]{host['router_brand']} Router[/bold]"
        elif host['is_router']:
            host_info += " • [bold]Router[/bold]"
        
        if host['open_ports']:
            ports_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            ports_table.add_column("Port", style="cyan", width=8)
            ports_table.add_column("Service", style="green", width=12)
            ports_table.add_column("Banner", style="yellow", width=25)
            ports_table.add_column("Product", style="white", width=20)
            
            for port_info in host['open_ports']:
                port_style = "red" if port_info['port'] in [23, 80, 443, 7547, 8080] else "cyan"
                service_style = "red" if any(x in port_info['service'] for x in ['http', 'telnet', 'ssh']) else "green"
                
                banner = port_info['banner']
                if len(banner) > 22:
                    banner = banner[:19] + "..."
                
                ports_table.add_row(
                    f"[{port_style}]{port_info['port']}[/{port_style}]",
                    f"[{service_style}]{port_info['service']}[/{service_style}]",
                    banner,
                    port_info['product']
                )
            
            self.console.print(Panel(ports_table, title=host_info, border_style=host_color))
        else:
            self.console.print(Panel.fit(
                f"{host_info} • No open ports found",
                border_style="dim"
            ))
    
    def _display_summary_panel(self):
        """Display scan summary panel"""
        from rich.panel import Panel
        
        router_count = sum(1 for host in self.discovered_hosts if host['is_router'])
        routers_with_brands = [h for h in self.discovered_hosts if h['is_router'] and h['router_brand'] != "Unknown"]
        
        summary_text = (
            f"Active Hosts: [cyan]{self.scan_stats['active_hosts']}/{self.scan_stats['total_hosts']}[/cyan]\n"
            f"Open Ports: [green]{self.scan_stats['open_ports']}[/green]\n"
            f"Routers Found: [red]{router_count}[/red]\n"
            f"Scan Duration: [yellow]{self.scan_stats['scan_duration']:.1f} seconds[/yellow]"
        )
        
        if routers_with_brands:
            brands = ", ".join(set(h['router_brand'] for h in routers_with_brands))
            summary_text += f"\nRouter Brands: [white]{brands}[/white]"
        
        self.console.print(Panel.fit(summary_text, title="Scan Summary", border_style="blue"))

def run(session, options):
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    
    target = options.get("target", "192.168.1.0/24")
    ports_config = options.get("ports", "router")
    timeout = float(options.get("timeout", 2))
    max_threads = int(options.get("threads", 20))
    ping_check = options.get("ping_check", "true").lower() == "true"
    
    console.print(Panel.fit(
        f"Network Scanner\n"
        f"Target: [cyan]{target}[/cyan]\n"
        f"Ports: [yellow]{ports_config}[/yellow]\n"
        f"Threads: [green]{max_threads}[/green]\n"
        f"Timeout: [magenta]{timeout}s[/magenta]",
        border_style="blue"
    ))
    
    scanner = NetworkScanner(
        console=console,
        target=target,
        ports=ports_config,
        timeout=timeout,
        max_threads=max_threads,
        ping_check=ping_check
    )
    
    try:
        scanner.run_scan()
        scanner.display_results()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
