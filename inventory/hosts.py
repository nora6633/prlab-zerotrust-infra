#!/usr/bin/env python3
"""
Dynamic Ansible inventory — reads host IPs from environment variables.

Required env vars:
  EXTERNAL_HOST_IP   IP of the external host (Juice Shop + Wazuh agent)
  SOC_HOST_IP        IP of the SOC host (Wazuh server + Shuffle + DFIR-IRIS)
  LAN_HOST_IP        IP of the LAN host (FreeIPA + Nextcloud + Mailcow + Wazuh agent)

Optional env vars:
  ANSIBLE_USER       SSH user (default: ubuntu)
  ANSIBLE_SSH_KEY    Path to SSH private key (default: ~/.ssh/id_rsa)
"""
import json
import os
import sys


def env(key, default=None):
    val = os.environ.get(key, default)
    if val is None:
        print(f"ERROR: required environment variable {key} is not set.", file=sys.stderr)
        sys.exit(1)
    return val


def build_inventory():
    user = os.environ.get("ANSIBLE_USER", "ubuntu")
    key  = os.environ.get("ANSIBLE_SSH_KEY", "~/.ssh/id_rsa")

    common = {
        "ansible_user": user,
        "ansible_ssh_private_key_file": key,
        "ansible_python_interpreter": "/usr/bin/python3",
        "ansible_ssh_common_args": "-o StrictHostKeyChecking=no",
    }

    return {
        "all": {
            "children": ["external", "soc", "lan"],
        },
        "external": {"hosts": ["external-host"]},
        "soc":      {"hosts": ["soc-host"]},
        "lan":      {"hosts": ["lan-host"]},
        "_meta": {
            "hostvars": {
                "external-host": {"ansible_host": env("EXTERNAL_HOST_IP"), **common},
                "soc-host":      {"ansible_host": env("SOC_HOST_IP"),      **common},
                "lan-host":      {"ansible_host": env("LAN_HOST_IP"),      **common},
            }
        },
    }


if __name__ == "__main__":
    inventory = build_inventory()
    if "--host" in sys.argv:
        host = sys.argv[sys.argv.index("--host") + 1]
        print(json.dumps(inventory["_meta"]["hostvars"].get(host, {})))
    else:
        print(json.dumps(inventory))
