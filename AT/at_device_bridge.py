#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
 PhoenixGSM - Standalone Samsung AT RIL Tool Bridge & Telemetry Collector
 Target Binary: C:\\Users\\pc5\\Documents\\GitHub\\PhoenixGSM\\AT\\AT
 Device Target: /data/local/tmp/AT
 Description:
   - Uploads (adb push) the native Samsung AT Ril binary to connected device.
   - Sets execution permissions (chmod 777).
   - Executes the binary to acquire device info (Product, Model, Carrier, IMEI, Build,
     Android Ver, Security Patch, Token AuthKey).
   - Saves all acquired telemetry to the computer (JSON, TXT, and raw output).
   - Supports interactive authentication & RIL command pass-through.
========================================================================================
"""

import os
import sys
import time
import json
import re
import hashlib
import argparse
import subprocess
from datetime import datetime

# Configure UTF-8 for console output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_PATH = os.path.join(SCRIPT_DIR, "AT")
REMOTE_PATH = "/data/local/tmp/AT"

OUTPUT_JSON_PATH = os.path.join(SCRIPT_DIR, "at_device_info.json")
OUTPUT_TXT_PATH = os.path.join(SCRIPT_DIR, "at_device_info.txt")
OUTPUT_RAW_PATH = os.path.join(SCRIPT_DIR, "at_raw_output.log")


class Colors:
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def strip(cls, text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)


def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix_map = {
        "INFO": f"{Colors.CYAN}[INFO]{Colors.RESET}",
        "SUCCESS": f"{Colors.GREEN}[SUCCESS]{Colors.RESET}",
        "WARN": f"{Colors.YELLOW}[WARN]{Colors.RESET}",
        "ERROR": f"{Colors.RED}[ERROR]{Colors.RESET}",
        "DATA": f"{Colors.BOLD}{Colors.GREEN}[DATA]{Colors.RESET}",
    }
    prefix = prefix_map.get(level, f"[{level}]")
    print(f"[{ts}] {prefix} {msg}")


def check_adb() -> bool:
    """Verifies that adb is available in PATH or local directory."""
    try:
        res = subprocess.run(["adb", "version"], capture_output=True, text=True, check=True)
        first_line = res.stdout.strip().splitlines()[0] if res.stdout else "ADB Available"
        log(f"ADB detected: {first_line}", "INFO")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        log("ADB was not found in system PATH. Please ensure ADB is installed and added to PATH.", "ERROR")
        return False


def get_connected_device() -> dict:
    """Retrieves the currently connected ADB device."""
    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, check=True)
        lines = [line.strip() for line in res.stdout.splitlines() if line.strip() and not line.startswith("List")]
        
        devices = []
        for line in lines:
            if "device" in line and not "offline" in line and not "unauthorized" in line:
                parts = line.split()
                serial = parts[0]
                props = {}
                for part in parts[1:]:
                    if ":" in part:
                        k, v = part.split(":", 1)
                        props[k] = v
                devices.append({"serial": serial, "raw": line, **props})
        
        if not devices:
            log("No active/authorized ADB devices found. Ensure device is plugged in and USB debugging is enabled.", "ERROR")
            return {}
        
        target = devices[0]
        log(f"Connected Device: {target.get('serial')} (Model: {target.get('model', 'Unknown')}, Product: {target.get('product', 'Unknown')})", "SUCCESS")
        return target
    except Exception as e:
        log(f"Failed to query ADB devices: {e}", "ERROR")
        return {}


def calculate_file_hashes(filepath: str) -> tuple[str, str, int]:
    """Calculates MD5 and SHA256 of the binary."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest(), size


def push_binary_to_device(local_binary: str, remote_target: str) -> bool:
    """Pushes the AT binary to /data/local/tmp/AT and grants execute permissions."""
    if not os.path.isfile(local_binary):
        log(f"Target binary not found at: {local_binary}", "ERROR")
        return False

    md5_hash, sha256_hash, file_size = calculate_file_hashes(local_binary)
    log(f"Local binary verified: {local_binary} ({file_size:,} bytes | MD5: {md5_hash})", "INFO")

    log(f"Pushing binary to device: {remote_target} ...", "INFO")
    try:
        push_res = subprocess.run(
            ["adb", "push", local_binary, remote_target],
            capture_output=True,
            text=True,
            check=True
        )
        log(f"Push successful: {push_res.stdout.strip() or 'OK'}", "SUCCESS")
    except subprocess.CalledProcessError as e:
        log(f"Failed to push binary to device: {e.stderr}", "ERROR")
        return False

    log(f"Applying execution permissions (chmod 777 {remote_target}) ...", "INFO")
    try:
        subprocess.run(
            ["adb", "shell", f"chmod 777 {remote_target}"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Verify remote presence and file size
        verify_res = subprocess.run(
            ["adb", "shell", f"ls -l {remote_target}"],
            capture_output=True,
            text=True,
            check=True
        )
        log(f"Remote binary permissions verified: {verify_res.stdout.strip()}", "SUCCESS")
        return True
    except subprocess.CalledProcessError as e:
        log(f"Failed to set permissions on device: {e.stderr}", "ERROR")
        return False


def execute_at_and_collect_telemetry(
    remote_target: str,
    mode_arg: str = "",
    timeout_sec: float = 8.0,
    authkey_input: str = ""
) -> tuple[dict, str]:
    """
    Executes the AT binary on the phone via adb shell, streams output,
    extracts all phone parameters & Token AuthKey, and gracefully handles stdin.
    """
    exec_cmd = remote_target
    if mode_arg:
        exec_cmd = f"{remote_target} {mode_arg}".strip()

    log(f"Executing binary on phone: {exec_cmd} ...", "INFO")

    cmd = ["adb", "shell", exec_cmd]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    raw_bytes = bytearray()
    start_time = time.time()
    token_captured = False

    while (time.time() - start_time) < timeout_sec:
        # Read 1 byte at a time to prevent buffering deadlocks on non-newline prompts
        try:
            b = proc.stdout.read(1)
        except Exception:
            break

        if not b:
            break

        raw_bytes.extend(b)

        # Check if Token AuthKey & Enter AuthKey prompt reached
        if b"Enter AuthKey:" in raw_bytes:
            token_captured = True
            break

    # If user provided an AuthKey, write it; otherwise send newline to exit cleanly
    try:
        if authkey_input:
            log("Sending provided AuthKey to AT tool...", "INFO")
            proc.stdin.write(f"{authkey_input}\n".encode("utf-8"))
            proc.stdin.flush()
            time.sleep(1.0)
            # Read response
            while (time.time() - start_time) < (timeout_sec + 3.0):
                b = proc.stdout.read(1)
                if not b:
                    break
                raw_bytes.extend(b)
                if b"OK | #" in raw_bytes or b"Error AuthKey" in raw_bytes:
                    break
        else:
            proc.stdin.write(b"\n")
            proc.stdin.flush()
    except Exception:
        pass

    try:
        proc.kill()
    except Exception:
        pass

    raw_text = raw_bytes.decode("utf-8", errors="replace")

    # Parse parameters
    data = {}
    for line in raw_text.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("*") or clean.startswith("-"):
            continue

        if ":" in clean:
            parts = clean.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            if key and val and not key.lower().startswith("enter"):
                data[key] = val

    return data, raw_text


def save_telemetry_files(data: dict, raw_text: str, device_meta: dict, binary_hashes: dict):
    """Saves the extracted device information to JSON, TXT, and RAW files."""
    timestamp_str = datetime.now().isoformat()

    full_record = {
        "timestamp": timestamp_str,
        "device_metadata": device_meta,
        "binary_info": {
            "local_path": BINARY_PATH,
            "remote_path": REMOTE_PATH,
            **binary_hashes
        },
        "extracted_device_info": data,
        "raw_banner": raw_text.strip()
    }

    # 1. Save JSON
    try:
        with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(full_record, f, indent=2, ensure_ascii=False)
        log(f"Telemetry saved to JSON: {OUTPUT_JSON_PATH}", "SUCCESS")
    except Exception as e:
        log(f"Failed to write JSON: {e}", "ERROR")

    # 2. Save TXT Summary Report
    try:
        with open(OUTPUT_TXT_PATH, "w", encoding="utf-8") as f:
            f.write("========================================================================\n")
            f.write(f" SAMSUNG AT RIL TOOL - ACQUIRED DEVICE TELEMETRY REPORT\n")
            f.write(f" Timestamp: {timestamp_str}\n")
            f.write(f" Device Serial: {device_meta.get('serial', 'Unknown')}\n")
            f.write("========================================================================\n\n")

            f.write("[1] PARSED PHONE ATTRIBUTES:\n")
            for k, v in data.items():
                f.write(f"  - {k:<20}: {v}\n")
            f.write("\n")

            f.write("[2] BINARY FORENSICS:\n")
            f.write(f"  - Local File        : {BINARY_PATH}\n")
            f.write(f"  - Remote Destination: {REMOTE_PATH}\n")
            f.write(f"  - File Size Bytes   : {binary_hashes.get('size_bytes', 0):,}\n")
            f.write(f"  - MD5 Checksum      : {binary_hashes.get('md5', 'N/A')}\n")
            f.write(f"  - SHA-256 Checksum  : {binary_hashes.get('sha256', 'N/A')}\n\n")

            f.write("[3] RAW TOOL BANNER & OUTPUT:\n")
            f.write(raw_text)
            f.write("\n")
        log(f"Summary report saved to TXT: {OUTPUT_TXT_PATH}", "SUCCESS")
    except Exception as e:
        log(f"Failed to write TXT: {e}", "ERROR")

    # 3. Save Raw Output
    try:
        with open(OUTPUT_RAW_PATH, "w", encoding="utf-8") as f:
            f.write(raw_text)
        log(f"Raw output log saved to: {OUTPUT_RAW_PATH}", "SUCCESS")
    except Exception as e:
        log(f"Failed to write RAW: {e}", "ERROR")


def display_results_table(data: dict):
    """Prints a styled summary table in console."""
    print("\n" + "=" * 76)
    print(f"{Colors.BOLD}{Colors.GREEN}       ACQUIRED SAMSUNG DEVICE TELEMETRY VIA AT RIL BRIDGE{Colors.RESET}")
    print("=" * 76)

    display_keys = [
        ("Product Name", "Product Name"),
        ("Product Model", "Product Model"),
        ("Device Carrier", "Device Carrier"),
        ("Serial Number", "Serial Number"),
        ("Device IMEI", "Device IMEI"),
        ("Build  Number", "Build Number"),
        ("Build Number", "Build Number"),
        ("Android Ver", "Android Version"),
        ("Security Patch", "Security Patch"),
        ("Token AuthKey", "Token AuthKey (Challenge)")
    ]

    seen = set()
    for raw_k, label in display_keys:
        if raw_k in data and label not in seen:
            val = data[raw_k]
            if raw_k == "Token AuthKey":
                print(f" {Colors.YELLOW}{label:<26}:{Colors.RESET} {Colors.BOLD}{val}{Colors.RESET}")
            else:
                print(f" {Colors.CYAN}{label:<26}:{Colors.RESET} {val}")
            seen.add(label)

    # Any other keys
    for k, v in data.items():
        if k not in [x[0] for x in display_keys]:
            print(f" {Colors.CYAN}{k:<26}:{Colors.RESET} {v}")

    print("=" * 76 + "\n")


def cleanup_remote(remote_target: str):
    """Deletes the temporary binary from /data/local/tmp/."""
    log(f"Cleaning up {remote_target} on device...", "INFO")
    try:
        subprocess.run(["adb", "shell", f"rm -f {remote_target}"], capture_output=True, text=True)
        log("Device cleanup completed.", "SUCCESS")
    except Exception as e:
        log(f"Cleanup failed: {e}", "WARN")


def main():
    parser = argparse.ArgumentParser(
        description="PhoenixGSM Standalone Samsung AT RIL Device Info Collector & Bridge Runner"
    )
    parser.add_argument("--mode", default="", help="Execution argument for AT (e.g. 'R2' for extended IMEI/Serial acquisition)")
    parser.add_argument("--no-push", action="store_true", help="Skip uploading the binary if already present on device")
    parser.add_argument("--cleanup", action="store_true", help="Remove binary from device after execution")
    parser.add_argument("--authkey", default="", help="AuthKey hex response if available to unlock RIL command mode")
    parser.add_argument("--timeout", type=float, default=8.0, help="Acquisition timeout in seconds (default: 8.0)")

    args = parser.parse_args()

    print("\n" + "#" * 76)
    print(" PhoenixGSM Standalone Samsung AT Bridge & Telemetry Acquisition")
    print(f" Target Folder: {SCRIPT_DIR}")
    print("#" * 76 + "\n")

    # 1. Verify ADB
    if not check_adb():
        sys.exit(1)

    # 2. Check Device
    device = get_connected_device()
    if not device:
        sys.exit(1)

    # 3. Check Local Binary
    if not os.path.isfile(BINARY_PATH):
        log(f"Error: AT binary not found at expected path: {BINARY_PATH}", "ERROR")
        sys.exit(1)

    md5_h, sha256_h, fsize = calculate_file_hashes(BINARY_PATH)
    binary_hashes = {
        "md5": md5_h,
        "sha256": sha256_h,
        "size_bytes": fsize
    }

    # 4. Push Binary
    if not args.no_push:
        if not push_binary_to_device(BINARY_PATH, REMOTE_PATH):
            sys.exit(1)
    else:
        log("Skipping upload (--no-push specified). Using existing file on phone.", "INFO")

    # 5. Execute and Collect
    # If mode is not specified, run first with R2 then standard if needed
    target_mode = args.mode
    data, raw_out = execute_at_and_collect_telemetry(
        remote_target=REMOTE_PATH,
        mode_arg=target_mode,
        timeout_sec=args.timeout,
        authkey_input=args.authkey
    )

    # If first attempt didn't yield data and mode was empty, retry with 'R2'
    if not data and not target_mode:
        log("Standard run produced empty data, retrying with mode 'R2' ...", "WARN")
        target_mode = "R2"
        data, raw_out = execute_at_and_collect_telemetry(
            remote_target=REMOTE_PATH,
            mode_arg=target_mode,
            timeout_sec=args.timeout,
            authkey_input=args.authkey
        )

    # 6. Display Results
    if data:
        display_results_table(data)
    else:
        log("No structured data could be extracted. Check raw output below:", "WARN")
        print("\n--- RAW OUTPUT ---")
        print(raw_out)
        print("------------------\n")

    # 7. Save Files
    save_telemetry_files(data, raw_out, device, binary_hashes)

    # 8. Cleanup if requested
    if args.cleanup:
        cleanup_remote(REMOTE_PATH)

    log("Operation completed successfully.", "SUCCESS")


if __name__ == "__main__":
    main()
