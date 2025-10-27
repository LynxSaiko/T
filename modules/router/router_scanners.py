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
    
    # ROUTER BRANDS DATABASE
    ROUTER_BRANDS = {
        "TP-Link": {"keywords": ["tp-link", "tplink"], "banners": ["TP-Link", "Archer"], "ports": [23, 80, 443]},
        "D-Link": {"keywords": ["d-link", "dlink"], "banners": ["D-Link", "DIR-"], "ports": [23, 80, 443]},
        "Mikrotik": {"keywords": ["mikrotik", "routeros"], "banners": ["MikroTik", "RouterOS"], "ports": [22, 80, 8291]},
        "Tenda": {"keywords": ["tenda"], "banners": ["Tenda", "AC"], "ports": [23, 80, 443]},
        "Asus": {"keywords": ["asus"], "banners": ["ASUS", "RT-"], "ports": [23, 80, 443]},
        "Huawei": {"keywords": ["huawei"], "banners": ["Huawei", "HG"], "ports": [23, 80, 443, 7547]},
        "ZTE": {"keywords": ["zte"], "banners": ["ZTE", "F6"], "ports": [23, 80, 443, 7547]},
        "Cisco": {"keywords": ["cisco"], "banners": ["Cisco", "IOS"], "ports": [23, 80, 443]},
        "Netgear": {"keywords": ["netgear"], "banners": ["Netgear", "R7000"], "ports": [23, 80, 443]},
        "Ubiquiti": {"keywords": ["ubiquiti"], "banners": ["Ubiquiti", "UniFi"], "ports": [22, 80, 443]},
        # Merek tambahan dari Indonesia
        "Indihome": {"keywords": ["indihome"], "banners": ["IndiHome", "Modem"], "ports": [80, 443, 8080]},
        "Bolt": {"keywords": ["bolt"], "banners": ["Bolt", "Modem"], "ports": [80, 443, 8080]},
        "Biznet": {"keywords": ["biznet"], "banners": ["Biznet", "Router"], "ports": [80, 443, 8080]},
        "First Media": {"keywords": ["first media"], "banners": ["First Media", "Modem"], "ports": [80, 443, 8080]},
        "MyRepublic": {"keywords": ["my republic"], "banners": ["MyRepublic", "Router"], "ports": [80, 443, 8080]},
        "Citraweb": {"keywords": ["citraweb"], "banners": ["CitraWeb", "Router"], "ports": [80, 443, 8080]},
        "XL Home": {"keywords": ["xl home"], "banners": ["XL Home", "Modem"], "ports": [80, 443, 8080]},
        "Smartfren": {"keywords": ["smartfren"], "banners": ["Smartfren", "Router"], "ports": [80, 443, 8080]}
    }
    
    SERVICE_DB = {
        21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 
        443: "https", 7547: "tr-069", 8080: "http-proxy", 8291: "winbox",
        8443: "https-alt", 2000: "cisco-sccp"
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
        import os
        import platform
        
        try:
            param = "-n 1 -w 1000" if platform.system().lower() == "windows" else "-c 1 -W 1"
            response = os.system(f"ping {param} {ip} > /dev/null 2>&1")
            return response == 0
        except:
            return False
    
    def scan_port(self, ip, port):
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_router_banner(self, ip, port):
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((ip, port))
            
            banner = ""
            
            try:
                sock.settimeout(1.0)
                initial_data = sock.recv(256).decode('utf-8', errors='ignore').strip()
                if initial_data:
                    banner = initial_data
            except:
                pass
            
            sock.close()
            return banner[:80] if banner else ""
            
        except:
            return ""
    
    def detect_router_brand(self, banners, open_ports):
        if not banners:
            return self._detect_by_ports(open_ports)
        
        all_banners = " ".join(banners).lower()
        
        for brand, data in self.ROUTER_BRANDS.items():
            for keyword in data["keywords"]:
                if keyword.lower() in all_banners:
                    return brand
        
        return ""
    
    def _detect_by_ports(self, open_ports):
        port_numbers = {port_info['port'] for port_info in open_ports}
        
        for brand, data in self.ROUTER_BRANDS.items():
            brand_ports = set(data["ports"])
            common_ports = brand_ports.intersection(port_numbers)
            if len(common_ports) >= 2:
                return brand
        
        if 8291 in port_numbers:
            return "Mikrotik"
        elif 7547 in port_numbers:
            return "ISP Router"
        
        return ""
    
    def scan_host(self, ip):
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
                        banner = self.get_router_banner(ip, port)
                        service_name = self.SERVICE_DB.get(port, "unknown")
                        
                        open_ports.append({
                            'port': port,
                            'service': service_name,
                            'banner': banner
                        })
                        if banner:
                            banners.append(banner)
                except Exception:
                    pass
        
        if open_ports or not self.ping_check:
            hostname = self._get_hostname(ip)
            router_brand = self.detect_router_brand(banners, open_ports)
            is_router = self._is_router_like(open_ports)
            
            if is_router and router_brand:
                self.scan_stats['routers_found'] += 1
            
            return {
                'ip': ip,
                'hostname': hostname,
                'open_ports': open_ports,
                'is_router': is_router,
                'router_brand': router_brand if is_router else ""
            }
        
        return None
    
    def _get_hostname(self, ip):
        import socket
        
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""
    
    def _is_router_like(self, open_ports):
        port_numbers = {port_info['port'] for port_info in open_ports}
        router_ports = {23, 80, 443, 7547, 8080, 8291}
        return any(port in router_ports for port in port_numbers)

    def run_scan(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from tqdm import tqdm  # we use tqdm only for the spinner / progress
        import time
        
        try:
            ip_list = self.generate_ip_list()
        except Exception as e:
            # Keep existing rich console style for errors
            self.console.print(f"[bold red]✗ Error: {e}[/bold red]")
            return
        
        start_time = time.time()
        lock = threading.Lock()
        
        # Use tqdm to show progress per-host (spinner replacement). UI/tables unchanged.
        with tqdm(total=len(ip_list), desc="[Scanning network]", unit="host", dynamic_ncols=True, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in ip_list}
                
                for future in as_completed(future_to_ip):
                    host_data = None
                    try:
                        host_data = future.result()
                    except Exception:
                        # ignore per-host exceptions, continue scanning
                        host_data = None
                    with lock:
                        if host_data:
                            self.discovered_hosts.append(host_data)
                            self.scan_stats['active_hosts'] += 1
                            self.scan_stats['open_ports'] += len(host_data['open_ports'])
                        # update tqdm postfix & advance
                        pbar.set_postfix({"hosts_found": self.scan_stats['active_hosts']})
                        pbar.update(1)
        
        self.scan_stats['scan_duration'] = time.time() - start_time
    
    def display_results(self):
        """Display results dengan Rich table yang proper"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        
        if not self.discovered_hosts:
            self.console.print(Panel(
                "[yellow]ⓘ No active hosts discovered[/yellow]",
                border_style="yellow",
                box=box.ROUNDED
            ))
            return
        
        self.discovered_hosts.sort(key=lambda x: (x['is_router'], len(x['open_ports'])), reverse=True)
        
        # HEADER PANEL
        self.console.print(Panel(
            "[bold cyan]🌐 NETWORK DISCOVERY RESULTS[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
            #width=160
        ))
        
        # HOSTS TABLE DENGAN RICH
        hosts_table = Table(
            border_style="cyan",
            show_header=True,
            header_style="bold white",
            box=box.HEAVY,
            show_lines=False
        )
        
        hosts_table.add_column("#", style="cyan", width=4, justify="center")
        hosts_table.add_column("IP Address", style="bold white", width=30, overflow="fold")
        hosts_table.add_column("Hostname", style="white", width=30, overflow="fold")
        hosts_table.add_column("Status", style="white", width=30, justify="center", overflow="fold")
        hosts_table.add_column("Brand", style="yellow", width=30, overflow="fold")
        hosts_table.add_column("Open Ports", style="green", width=30, overflow="fold")
        
        # ADD HOSTS TO TABLE
        for i, host in enumerate(self.discovered_hosts, 1):
            if host['is_router']:
                status = "[bold red]ROUTER[/bold red]"
            else:
                status = "[bold cyan]HOST[/bold cyan]"
            
            # Format ports
            if host['open_ports']:
                ports_text = ", ".join([f"{p['port']}/{p['service']}" for p in host['open_ports'][:3]])
                if len(host['open_ports']) > 3:
                    ports_text += f" [+{len(host['open_ports'])-3}]"
            else:
                ports_text = "[dim]none[/dim]"
            
            hosts_table.add_row(
                str(i),
                host['ip'],
                host['hostname'] or "[dim]-[/dim]",
                status,
                host['router_brand'] or "[dim]-[/dim]",
                ports_text
            )
        
        self.console.print(hosts_table)
        self.console.print("")
        
        # SUMMARY TABLE
        router_count = sum(1 for host in self.discovered_hosts if host['is_router'])
        router_brands = set(h['router_brand'] for h in self.discovered_hosts if h['is_router'] and h['router_brand'])
        
        summary_table = Table(
            show_header=True,
            header_style="bold green",
            box=box.SIMPLE,
            show_lines=False
            #width=50
        )
        
        summary_table.add_column("Metric", style="bold white", width=20)
        summary_table.add_column("Output", style="white", width=30)
        
        summary_table.add_row("Hosts Discovered", 
                            f"[cyan]{self.scan_stats['active_hosts']}[/cyan]/[dim]{self.scan_stats['total_hosts']}[/dim]")
        summary_table.add_row("Open Ports", f"[green]{self.scan_stats['open_ports']}[/green]")
        summary_table.add_row("Routers Found", f"[red]{router_count}[/red]")
        summary_table.add_row("Scan Duration", f"[yellow]{self.scan_stats['scan_duration']:.1f}s[/yellow]")
        
        if router_brands:
            brands_text = ", ".join(router_brands)
            summary_table.add_row("Router Brands", f"[magenta]{brands_text}[/magenta]")
        
        self.console.print(Panel(
            summary_table,
            title="[bold green][*] SCAN COMPLETE [*][/bold green]",
            border_style="green",
            box=box.DOUBLE
        ))

def run(session, options):
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    
    console = Console()
    
    target = options.get("target", "192.168.1.0/24")
    ports_config = options.get("ports", "router")
    timeout = float(options.get("timeout", 2))
    max_threads = int(options.get("threads", 20))
    ping_check = options.get("ping_check", "true").lower() == "true"
    
    # HEADER PANEL
    console.print(Panel(
        "[bold cyan]⚡ ROUTER NETWORK SCANNER[/bold cyan]\n"
        "[white]Advanced Network Discovery Tool[/white]",
        border_style="cyan",
        box=box.DOUBLE,
        #width=160
    ))
    
    # CONFIG TABLE
    config_table = Table(
        show_header=True,
        header_style="bold blue",
        box=box.SIMPLE,
        show_lines=False,
        width=50
    )
    
    config_table.add_column("Setting", style="bold white", width=15)
    config_table.add_column("Output", style="white", width=35)
    
    config_table.add_row("Target", f"[cyan]{target}[/cyan]")
    config_table.add_row("Ports", f"[yellow]{ports_config}[/yellow]")
    config_table.add_row("Threads", f"[green]{max_threads}[/green]")
    config_table.add_row("Timeout", f"[magenta]{timeout}s[/magenta]")
    
    console.print(Panel(
        config_table,
        title="[bold blue][*] SCAN CONFIGURATION[/bold blue]",
        border_style="blue",
        box=box.ROUNDED
    ))
    
    console.print("")
    
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
        console.print("")
        scanner.display_results()
    except KeyboardInterrupt:
        console.print(Panel(
            "[yellow]⚠ Scan interrupted by user[/yellow]",
            border_style="yellow",
            box=box.ROUNDED
        ))
    except Exception as e:
        console.print(Panel(
            f"[red]✗ Error: {e}[/red]",
            border_style="red",
            box=box.ROUNDED
        ))
