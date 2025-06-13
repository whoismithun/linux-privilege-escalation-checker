#!/usr/bin/env python3
import os
import subprocess
import re
import platform

def run_command(command):
    try:
        return subprocess.check_output(command, shell=True, text=True).strip()
    except subprocess.CalledProcessError:
        return ""

def check_sudo_permissions():
    print("[+] Checking for sudo permissions...")
    result = run_command("sudo -l")
    if "NOPASSWD" in result:
        print("    [!] NOPASSWD found! You might run commands as root without a password.")
    elif "may run the following commands" in result:
        print("    [!] You have sudo access to specific commands.")
    else:
        print("    [-] No sudo permissions found.")
    print(result)

def check_world_writable_files():
    print("[+] Checking for world-writable files (excluding /proc and /sys)...")
    result = run_command("find / -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null")
    if result:
        print("    [!] World-writable files found:\n", result)
    else:
        print("    [-] No world-writable files found.")

def check_suid_binaries():
    print("[+] Checking for SUID binaries...")
    result = run_command("find / -perm -4000 -type f 2>/dev/null")
    if result:
        print("    [!] SUID binaries found:\n", result)
    else:
        print("    [-] No SUID binaries found.")

def check_cron_jobs():
    print("[+] Checking for cron jobs...")
    print(run_command("cat /etc/crontab"))
    print(run_command("ls -la /etc/cron.*"))

def check_docker_socket():
    print("[+] Checking for Docker privilege escalation vector.....")
    result = run_command("groups")
    docker_socket_path = "/var/run/docker.sock"
    has_read_access = os.access(docker_socket_path, os.R_OK)
    has_write_access = os.access(docker_socket_path, os.W_OK)

    if "docker" in result:
        print("[!] Our user is part of the docker group!, Privilege escalation is possible through container escape.")
    elif has_read_access and has_write_access:
        print("    [!] Docker socket found! You might gain root access via container escape.")
    else:
        print("    [-] Privilege escalation using docker not possible.")

def check_kernel_version():
    print("[+] Checking kernel version and known exploit potential...")
    kernel = platform.uname().release
    print("    Kernel Version:", kernel)
    major_version = kernel.split("-")[0]
    print("    [!] Search for exploits related to this version on https://www.exploit-db.com/")
    print("    e.g., `searchsploit Linux Kernel", major_version, "`\n")

def check_environment_variables():
    print("[+] Checking for suspicious environment variables...")
    suspicious_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "HOME", "SHELL"]
    for var in suspicious_vars:
        val = os.environ.get(var)
        if val:
            print(f"    {var} = {val}")
            if var == "PATH":
                paths = val.split(":")
                for p in paths:
                    if p == "":
                        print("        [!] Empty path entry – PATH hijack risk!")
                    elif not os.path.exists(p):
                        print(f"        [!] Nonexistent path: {p} – PATH hijack risk!")
        else:
            print(f"    {var} not set.")

def check_path_hijacking():
    print("[+] Checking for PATH hijacking opportunities...")
    path = os.environ.get("PATH", "")
    dangerous_bins = ["cp", "mv", "nano", "vim", "python", "less"]
    path_dirs = path.split(":")

    # Check for writable directories in PATH
    for dir_path in path_dirs:
        if os.path.isdir(dir_path) and os.access(dir_path, os.W_OK):
            print(f"    [!] Writable directory in PATH: {dir_path} – could be hijacked!")

    # Check if any command in sudoers path is missing and could be hijacked
    sudo_output = run_command("sudo -l")
    for bin_name in dangerous_bins:
        if bin_name in sudo_output and not shutil.which(bin_name):
            print(f"    [!] {bin_name} appears in sudo list but not found – PATH hijack possible!")

def main():
    print("==== Linux Privilege Escalation Checks (Python) ====\n")
    check_kernel_version()
    check_sudo_permissions()
    check_environment_variables()
    check_path_hijacking()
    check_world_writable_files()
    check_suid_binaries()
    check_cron_jobs()
    check_docker_socket()
    print("\n[+] Scan complete. Use results to investigate potential privilege escalation paths.")

if __name__ == "__main__":
    import shutil
    main()
