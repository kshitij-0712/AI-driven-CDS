import json
import subprocess
import os


def run_discovery(target="127.0.0.1"):
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", target],
            check=False,
            capture_output=True,
            text=True,
        )
        return {
            "target": target,
            "scan_output": result.stdout,
            "error_output": result.stderr,
        }
    except FileNotFoundError:
        return {
            "target": target,
            "scan_output": "nmap not installed",
            "error_output": "",
        }


def write_report(report, output_path):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, 'w') as f:       
         json.dump(report, f, indent=2)
