import asyncio
import subprocess
from firewall import Firewall
from rule_engine import Rule
from config_loader import load_config

def init_iptables():
    # Flush existing rules
    subprocess.run(["sudo", "iptables", "-F"], check=True)
    # Set default policies
    subprocess.run(["sudo", "iptables", "-P", "INPUT", "ACCEPT"], check=True)
    subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], check=True)
    subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], check=True)

async def main():
    init_iptables()
    config = load_config('firewall_config.yaml')
    firewall = Firewall(config['db_path'])

    for rule_config in config['rules']:
        firewall.add_rule(Rule(**rule_config))

    cleanup_task = asyncio.create_task(firewall.periodic_cleanup())
    try:
        await firewall.start()
    finally:
        cleanup_task.cancel()

if __name__ == "__main__":
    asyncio.run(main())
