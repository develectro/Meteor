"""
CLI entrypoint for Meteor.
"""

import argparse
import sys
import json
import getpass
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from .providers.ubuntu import UbuntuProvider
from .providers.privilege import PrivilegeProvider
from .providers.hardware import HardwareAudit
from .core.scanner import ScannerEngine, DeepScanner
from .core.process import ProcessManager
from .core.logs import LogAnalyzer
from .core.heuristic import HeuristicEngine
from .core.vault import EncryptedVault
from .core.identity import IdentityGuard
from .core.killchain import KillChainAnalyzer
from .core.password import PasswordAnalyzer
from .core.shield import HardeningEngine
from .external.shodan import ShodanClient
from .external.virustotal import VirusTotalClient
from .external.abuseipdb import AbuseIPDBClient
from .external.otx import OTXClient
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.align import Align

console = Console()

def get_provider():
    """
    Returns the appropriate requested provider. 
    Can be expanded to determine OS at runtime.
    """
    # Focusing on Ubuntu provider initially
    return UbuntuProvider()

def cmd_scan(args):
    """
    Perform local port and process audit.
    """
    provider = get_provider()
    root_mode = PrivilegeProvider.is_root()
    
    scanner = ScannerEngine(provider)
    pm = ProcessManager(provider)
    
    if root_mode:
        console.print("[bold red]COMBAT MODE DETECTED: Initializing DeepScanner...[/bold red]")
        deep_scanner = DeepScanner(provider)
    else:
        deep_scanner = None

    heuristic = HeuristicEngine(scanner, pm)
    console.print("[bold cyan]Starting local port and process scan...[/bold cyan]")
    results = heuristic.evaluate_system_risk()
    
    table = Table(title="Local Open Ports & Process Scan")
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Protocol", style="magenta")
    table.add_column("Process Name", style="green")
    table.add_column("Executable Path")
    table.add_column("Risk Level", justify="center")

    for res in results:
        risk = res['risk_level']
        style = "green" if risk == "Green" else "yellow" if risk == "Yellow" else "red"
        
        proc = res.get('process', {})
        pid = proc.get('pid')
        integrity_warning = ""
        
        if root_mode and deep_scanner and pid:
            if not deep_scanner.check_process_integrity(pid):
                integrity_warning = " ❌ [bold red]INJECTED/DELETED[/bold red]"
                
        table.add_row(
            str(res.get('port')),
            res.get('protocol'),
            str(proc.get('name', 'N/A')) + integrity_warning,
            str(proc.get('exe_path', 'N/A')),
            f"[{style}]{risk}[/{style}]"
        )
        
    console.print(table)

def cmd_logs(args):
    """
    Perform quick anomaly detection in system logs.
    """
    provider = get_provider()
    analyzer = LogAnalyzer(provider)
    
    console.print("[bold cyan]Analyzing security logs...[/bold cyan]")
    anomalies = analyzer.analyze()
    
    if not anomalies:
        console.print("[bold green]No suspicious log entries found.[/bold green]")
        return
        
    table = Table(title="Suspicious Log Entries")
    table.add_column("Pattern Triggered", style="yellow")
    table.add_column("Log Entry", style="red")
    
    for anom in anomalies:
        table.add_row(anom.get('pattern'), anom.get('log'))
        
    console.print(table)

def cmd_shodan(args):
    """
    Perform external exposure check via Shodan API.
    """
    if not args.key:
        console.print("[bold red]Please provide a Shodan API key using --key.[/bold red]")
        sys.exit(1)
        
    client = ShodanClient(args.key)
    
    if not args.ip:
        console.print("[bold red]Need an IP address to check Shodan. Provide --ip <IP>.[/bold red]")
        sys.exit(1)

    console.print(f"[bold cyan]Checking Shodan exposure for {args.ip}...[/bold cyan]")
    result = client.check_exposure(args.ip)
    
    if "error" in result:
        console.print(f"[bold red]{result['error']}[/bold red]")
        sys.exit(1)
        
    # Pretty print the shodan result
    console.print(json.dumps(result, indent=2))

def cmd_full(args):
    """
    Perform a comprehensive report using the 'Nebula' dashboard layout.
    """
    provider = get_provider()
    root_mode = PrivilegeProvider.is_root()
    
    console.print("[bold blue]== Initializing Nebula Dashboard Analytics ==[/bold blue]")
    
    # 1. Gather Port Data
    scanner = ScannerEngine(provider)
    pm = ProcessManager(provider)
    heuristic = HeuristicEngine(scanner, pm)
    risks = heuristic.evaluate_system_risk()
    
    # 2. Gather Log Data
    log_analyzer = LogAnalyzer(provider)
    anomalies = log_analyzer.analyze()
    
    # 3. Gather Hardware Data
    hw_audit = HardwareAudit.check_vulnerabilities()
    
    # 4. Gather Shield Data
    shield = HardeningEngine()
    hardening = shield.audit_system()
    
    # 5. Gather Threat Intel (if keys exist in vault)
    console.print("[yellow]Unlocking Threat Intel Vault...[/yellow]")
    # We'll use a dummy/quick pass if no vault input is provided in this non-interactive dashboard
    # For now, we'll try to get it from vault if possible, or skip
    threat_intel = {}
    
    # Dashboard Layout Construction
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=3)
    )
    layout["main"].split_row(
        Layout(name="left"),
        Layout(name="right"),
    )
    
    # Header Panel
    layout["header"].update(Panel(Align.center("[bold red]METEOR NEBULA DASHBOARD[/bold red] - Cosmic System Analysis", vertical="middle")))
    
    # Port Scan Table
    port_table = Table(title="Local Exposure", box=None)
    port_table.add_column("Port", style="cyan")
    port_table.add_column("Process", style="green")
    port_table.add_column("Risk", justify="center")
    
    for r in risks:
        risk_style = "green" if r['risk_level'] == "Green" else "yellow" if r['risk_level'] == "Yellow" else "red"
        port_table.add_row(str(r['port']), r['process'].get('name', 'N/A'), f"[{risk_style}]{r['risk_level']}[/{risk_style}]")
    
    layout["left"].update(Panel(port_table, title="[bold cyan]Network & Processes[/bold cyan]"))
    
    # Logs & Hardware Panel
    log_content = "\n".join([f"[red]![/red] {a['pattern']}" for a in anomalies]) if anomalies else "[green]Clean[/green]"
    hw_content = "\n".join([f"[yellow]*[/yellow] {k}: {v['Status']}" for k, v in hw_audit.items() if v['Status'] != 'Safe']) or "[green]All Safe[/green]"
    
    right_panel = f"[bold red]Security Anomalies:[/bold red]\n{log_content}\n\n[bold yellow]Hardware Risks:[/bold yellow]\n{hw_content}"
    layout["right"].update(Panel(right_panel, title="[bold magenta]System & Hardware[/bold magenta]"))
    
    # Footer - Hardening Score
    h_score = hardening['score']
    h_style = "green" if h_score > 80 else "yellow" if h_score > 50 else "red"
    layout["footer"].update(Panel(Align.center(f"System Hardening Score: [{h_style}]{h_score}%[/{h_style}] | Root Mode: {'[red]Enabled[/red]' if root_mode else 'Disabled'}")))
    
    console.print(layout)

def cmd_shield(args):
    """
    Perform system hardening audit and suggest mitigations.
    """
    console.print("[bold cyan]🛡️ Initializing Meteor Shield: Hardening Audit...[/bold cyan]")
    engine = HardeningEngine()
    result = engine.audit_system()
    
    score = result['score']
    style = "green" if score > 80 else "yellow" if score > 50 else "red"
    
    console.print(f"\n[bold]System Hardening Score:[/bold] [{style}]{score}%[/{style}]")
    
    if not result['recommendations']:
        console.print("[bold green]Excellent! System is well-hardened.[/bold green]")
        return
        
    table = Table(title="Hardening Recommendations")
    table.add_column("Severity", justify="center")
    table.add_column("Issue", style="yellow")
    table.add_column("Fix Suggestion", style="green")
    
    for rec in result['recommendations']:
        sev = rec['severity']
        sev_style = "red" if sev == "Critical" else "yellow" if sev == "High" else "cyan"
        table.add_row(f"[{sev_style}]{sev}[/{sev_style}]", rec['issue'], rec['fix'])
        
    console.print(table)
    console.print("\n[italic white]Use 'sudo' to apply manual fixes or check kernel parameters.[/italic white]")

def cmd_hardware(args):
    """
    Audit hardware vulnerabilities (Spectre/Meltdown).
    """
    console.print("[bold cyan]Auditing Hardware Vulnerabilities...[/bold cyan]")
    audit = HardwareAudit.check_vulnerabilities()
    
    table = Table(title="Hardware Vulnerabilities")
    table.add_column("Vulnerability", style="cyan")
    table.add_column("Status")
    table.add_column("Mitigation", style="green")
    
    for vuln, data in audit.items():
        status = data['Status']
        status_style = "green" if status == "Safe" else "red" if status == "Vulnerable" else "yellow"
        
        table.add_row(
            vuln,
            f"[{status_style}]{status}[/{status_style}]",
            data['Mitigation']
        )
    console.print(table)

def cmd_vault(args):
    """
    Manage encrypted API vault.
    """
    console.print("[yellow]Enter Master Password:[/yellow]")
    password = getpass.getpass("> ")
    vault = EncryptedVault(password)
    
    if args.vault_cmd == "add":
        console.print(f"Adding key for {args.service}...")
        api_key = getpass.getpass("API Key: ")
        try:
            vault.add_key(args.service, api_key)
            console.print(f"[green]Successfully added key for {args.service}[/green]")
        except ValueError as e:
            console.print(f"[red]{str(e)}[/red]")
            
    elif args.vault_cmd == "status":
        providers = vault.get_configured_providers()
        if not providers:
            console.print("[yellow]Vault is empty.[/yellow]")
        else:
            table = Table(title="Vault Status")
            table.add_column("Service")
            table.add_column("Configured")
            for p in providers:
                table.add_row(p, "[green]Yes[/green]")
            console.print(table)
    else:
        console.print("[red]Invalid vault command. Use 'add' or 'status'.[/red]")

def cmd_check_email(args):
    """
    Check for email breaches using Vault keys.
    """
    console.print("[yellow]Enter Master Password to unlock Vault:[/yellow]")
    password = getpass.getpass("> ")
    vault = EncryptedVault(password)
    guard = IdentityGuard(vault)
    
    console.print(f"[cyan]Checking breaches for {args.email}...[/cyan]")
    providers = vault.get_configured_providers()
    if not providers:
        console.print("[red]No providers configured. Please run 'meteor vault add <service>' first.[/red]")
        sys.exit(1)
        
    result = guard.check_email_breach(args.email)
    
    if result.get("status") == "failed":
        console.print(f"[red]Error: {result.get('error')}[/red]")
    else:
        console.print(f"[green]{result.get('message')}[/green]")

def cmd_killchain(args):
    """
    Analyze the full kill chain and correlate risks, including external intel.
    """
    provider = get_provider()
    root_mode = PrivilegeProvider.is_root()
    
    console.print("[yellow]Enter Master Password to gather full intelligence:[/yellow]")
    password = getpass.getpass("> ")
    vault = EncryptedVault(password)
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Gathering local port and process metrics...", total=None)
        scanner = ScannerEngine(provider)
        pm = ProcessManager(provider)
        heuristic = HeuristicEngine(scanner, pm)
        scanner_results = heuristic.evaluate_system_risk()
        
        progress.add_task(description="Analyzing system logs...", total=None)
        analyzer = LogAnalyzer(provider)
        log_anomalies = analyzer.analyze()
        
        progress.add_task(description="Auditing hardware vulnerabilities...", total=None)
        hardware_audit = HardwareAudit.check_vulnerabilities()
        
        # External Threat Intel
        threat_intel = {}
        pub_ip = "8.8.8.8" # Mock/Fallback or fetch real public IP
        
        abuse_key = vault.get_key("abuseipdb")
        if abuse_key:
            progress.add_task(description="Checking IP reputation (AbuseIPDB)...", total=None)
            aic = AbuseIPDBClient(abuse_key)
            ip_res = aic.check_ip(pub_ip)
            if "data" in ip_res:
                threat_intel['abuse_score'] = ip_res['data'].get('abuseConfidenceScore', 0)
        
    console.print("[bold green]Analysis complete.[/bold green]")
    kc = KillChainAnalyzer(provider, scanner_results, log_anomalies, hardware_audit, threat_intel, root_mode)
    result = kc.analyze()
    
    score = result['score']
    style = "green" if score < 30 else "yellow" if score < 70 else "red"
    console.print(f"\n[bold]Global Risk Score:[/bold] [{style}]{score}%[/{style}]")
    if result.get("reasons"):
        console.print("[bold]Risk Factors (correlated):[/bold]")
        for reason in result['reasons']:
            console.print(f" - {reason}")

def cmd_threat(args):
    """
    Check an indicator (IP, Hash, URL) across VT, AbuseIPDB, and OTX.
    """
    console.print("[yellow]Unlocking Intelligence Vault...[/yellow]")
    password = getpass.getpass("> ")
    vault = EncryptedVault(password)
    
    indicator = args.indicator
    console.print(f"[bold cyan]Checking Indicator: {indicator}[/bold cyan]")
    
    # 1. VirusTotal
    vt_key = vault.get_key("virustotal")
    if vt_key:
        vt = VirusTotalClient(vt_key)
        res = vt.check_file_hash(indicator) if len(indicator) in [32, 40, 64] else vt.check_url(indicator)
        if "data" in res:
            stats = res['data']['attributes']['last_analysis_stats']
            console.print(f"VirusTotal: [red]{stats['malicious']}[/red] malicious, [green]{stats['harmless']}[/green] harmless.")
            
    # 2. AbuseIPDB
    abuse_key = vault.get_key("abuseipdb")
    if abuse_key:
        aic = AbuseIPDBClient(abuse_key)
        res = aic.check_ip(indicator)
        if "data" in res:
            score = res['data']['abuseConfidenceScore']
            console.print(f"AbuseIPDB Score: [bold]{score}%[/bold]")
            
    # 3. OTX
    otx_key = vault.get_key("otx")
    if otx_key:
        otx = OTXClient(otx_key)
        res = otx.check_indicator("IPv4" if "." in indicator else "file", indicator)
        if "pulse_info" in res:
            count = res['pulse_info']['count']
            console.print(f"AlienVault OTX: Found in {count} threat pulses.")

def cmd_password(args):
    """
    Interactive password strength and breach analyzer.
    """
    console.print("\n[bold cyan]-- Meteor Password Analyzer --[/bold cyan]")
    password = getpass.getpass("Enter password to analyze (input hidden): ")
    
    analyzer = PasswordAnalyzer(password)
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Evaluating entropy and HIBP K-Anonymity dictionaries...", total=None)
        result = analyzer.analyze()
        
    color = result['color']
    
    console.print("\n[bold]Analysis Results:[/bold]")
    
    # Render Progress Bar
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(style="bright_black", complete_style=color, finished_style=color),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as pbar:
        pbar.add_task(f"[{color}]Strength Metric", total=100, completed=result['score_percent'])
    
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    
    table.add_row("Strength", f"[{color}][bold]{result['strength']}[/bold][/{color}]")
    table.add_row("Entropy", f"{result['entropy']} bits")
    
    pwned_text = f"[red]Found in {result['pwned_count']} breaches![/red]" if result['pwned'] else "[green]Not found in known dictionaries/breaches.[/green]"
    table.add_row("Dictionary/Breach", pwned_text)
    
    table.add_row("Crack Time (Normal CPU - 100MH/s)", f"[yellow]{result['time_normal']}[/yellow]")
    table.add_row("Crack Time (Super GPU - 100GH/s)", f"[red]{result['time_super']}[/red]")
    
    console.print(table)
    
    console.print("\n[bold]Recommendations:[/bold]")
    for rec in result['recommendations']:
        console.print(f" 💡 {rec}")

def print_banner():
    """
    Prints a colorful ASCII banner for Meteor (red/orange gradient, slanted/italic text only).
    """
    banner = r"""
[bold #ffb300]    __  ___     __                 [/bold #ffb300]
[bold #ff8400]   /  |/  /__  / /____  ____  _____[/bold #ff8400]
[bold #ff5500]  / /|_/ / _ \/ __/ _ \/ __ \/ ___/[/bold #ff5500]
[bold #ff2600] / /  / /  __/ /_/  __/ /_/ / /    [/bold #ff2600]
[bold #ff0000]/_/  /_/\___/\__/\___/\____/_/     [/bold #ff0000]
    [bold white]Meteor Security CLI - Advanced Diagnostic Tool[/bold white]
    """
    console.print(banner)
    combat_mode = PrivilegeProvider.is_root()
    if combat_mode:
        console.print("         [bold red]*** COMBAT MODE (ROOT) ***[/bold red]\n")
    else:
        console.print("            [bold green]--- USER MODE ---[/bold green]\n")

def main():
    """
    Main entry point for CLI.
    """
    parser = argparse.ArgumentParser(description="Meteor Security CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'scan' command setup
    scan_parser = subparsers.add_parser("scan", help="Local port and process audit")
    scan_parser.set_defaults(func=cmd_scan)

    # 'logs' command setup
    logs_parser = subparsers.add_parser("logs", help="Quick anomaly detection in system logs")
    logs_parser.set_defaults(func=cmd_logs)

    # 'shodan' command setup
    shodan_parser = subparsers.add_parser("shodan", help="External exposure check")
    shodan_parser.add_argument("--key", required=True, help="Shodan API Key")
    shodan_parser.add_argument("--ip", required=True, help="IP address to scan")
    shodan_parser.set_defaults(func=cmd_shodan)
    
    # 'full' command setup
    full_parser = subparsers.add_parser("full", help="Comprehensive report combining all modules")
    full_parser.add_argument("--key", required=False, help="Shodan API Key (optional)")
    full_parser.add_argument("--ip", required=False, help="IP address to scan (optional)")
    full_parser.set_defaults(func=cmd_full)

    # 'hardware' command setup
    hw_parser = subparsers.add_parser("hardware", help="Hardware vulnerability audit")
    hw_parser.set_defaults(func=cmd_hardware)

    # 'vault' command setup
    vault_parser = subparsers.add_parser("vault", help="Manage Encrypted API Vault")
    vault_subs = vault_parser.add_subparsers(dest="vault_cmd", help="Vault Actions")
    
    vault_add = vault_subs.add_parser("add", help="Add a service key")
    vault_add.add_argument("service", help="Service name (e.g., shodan, hibp, breachdirectory)")
    
    vault_status = vault_subs.add_parser("status", help="Show configured keys")
    vault_parser.set_defaults(func=cmd_vault)

    # 'check-email' command setup
    email_parser = subparsers.add_parser("check-email", help="Check for email breaches using Vault keys")
    email_parser.add_argument("email", help="Email to check (e.g., user@example.com)")
    email_parser.set_defaults(func=cmd_check_email)

    # 'killchain' command setup
    kc_parser = subparsers.add_parser("killchain", help="Run full Kill Chain correlation analysis")
    kc_parser.set_defaults(func=cmd_killchain)

    # 'password' command setup
    password_parser = subparsers.add_parser("password", help="Analyze password strength and breach lookup")
    password_parser.set_defaults(func=cmd_password)

    # 'shield' command setup
    shield_parser = subparsers.add_parser("shield", help="Audit and suggest system hardening")
    shield_parser.set_defaults(func=cmd_shield)

    # 'threat' command setup
    threat_parser = subparsers.add_parser("threat", help="Check IP/Hash/URL against multiple threat intel sources")
    threat_parser.add_argument("indicator", help="IP, File Hash, or URL")
    threat_parser.set_defaults(func=cmd_threat)

    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(1)
        
    args.func(args)

if __name__ == "__main__":
    main()
