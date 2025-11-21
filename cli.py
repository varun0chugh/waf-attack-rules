import argparse
import sys
import os
from rich.console import Console
from rich.table import Table
from wafprobe.engine.parser import AttackParser
from wafprobe.engine.scanner import WAFScanner

def main():
    parser = argparse.ArgumentParser(description="WAFProbe: WAF Efficacy Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--attacks", default="attacks", help="Path to attack definitions")
    args = parser.parse_args()

    console = Console()
    console.print(f"[bold blue]Starting WAFProbe scan against: {args.url}[/bold blue]")

    # Load Tests
    parser_obj = AttackParser(os.path.join(os.getcwd(), "wafprobe", args.attacks))
    tests = parser_obj.load_tests()
    console.print(f"Loaded [bold green]{len(tests)}[/bold green] tests.")

    # Run Scan
    scanner = WAFScanner(args.url)
    results = scanner.scan(tests)

    # Display Results
    table = Table(title="Scan Results")
    table.add_column("ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Description")
    table.add_column("Status", justify="right")

    passed_count = 0
    for res in results:
        status = "[green]BLOCKED[/green]" if res['passed'] else "[red]BYPASSED[/red]"
        if res['passed']:
            passed_count += 1
        table.add_row(str(res['test_id']), res['category'], res['desc'], status)

    console.print(table)
    
    score = (passed_count / len(tests)) * 100 if tests else 0
    console.print(f"\n[bold]WAF Health Score: {score:.2f}%[/bold]")
    console.print(f"Blocked: {passed_count}/{len(tests)}")

if __name__ == "__main__":
    main()
