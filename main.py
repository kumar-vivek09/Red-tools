import asyncio
from core.orchestrator import Orchestrator


def show_banner():
    print("""
=====================================================
        ARCHAI PRO SCANNER
 AI-Orchestrated Recon Intelligence Framework
=====================================================
""")

    print(r"""
 █████╗ ██████╗  ██████╗██╗  ██╗ █████╗ ██╗
██╔══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗██║
███████║██████╔╝██║     ███████║███████║██║
██╔══██║██╔══██╗██║     ██╔══██║██╔══██║██║
██║  ██║██║  ██║╚██████╗██║  ██║██║  ██║██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
""")

    print("AI-Orchestrated Recon Intelligence Framework\n")


def show_menu():
    print("Select Scan Mode\n")
    print("[1] Light Scan ")
    print("[2] Balanced Scan ")
    print("[3] Aggressive Scan")
    print("[4] Intelligent Adaptive Scan")
    print("[5] Exit\n")


async def run_scan():

    show_banner()
    show_menu()

    choice = input("Select Scan Mode: ").strip()

    if choice == "5":
        print("Exiting ARCHAI...")
        return

    if choice not in ["1", "2", "3", "4"]:
        print("Invalid option.")
        return

    scan_level = int(choice)

    target = input("\nEnter Target Domain: ").strip()

    orchestrator = Orchestrator(scan_level=scan_level)

    print(f"\n[+] Starting ARCHAI scan for: {target}")
    print(f"[+] Scan Level: {scan_level}\n")

    result = await orchestrator.run(target)

    print("\n========== ARCHAI INTELLIGENCE REPORT ==========\n")

    for key, value in result.items():
        print(f"{key} : {value}")

    print("\n================================================\n")


if __name__ == "__main__":
    asyncio.run(run_scan())