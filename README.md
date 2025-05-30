# Linux Privilege Escalation Checker (Python)

This Python script performs a series of common checks to assist in identifying potential privilege escalation vectors on a Linux system. It is designed for penetration testers and security auditors to quickly assess the local system for misconfigurations, insecure permissions, and exploitable components.

## Features

- Checks for:
  - Kernel version and potential public exploits
  - Sudo permissions and NOPASSWD configurations
  - World-writable files
  - SUID binaries
  - Cron jobs and misconfigurations
  - Docker socket exposure
  - Suspicious or hijackable environment variables
  - PATH hijacking risks

## Requirements

- Python 3.x
- Linux operating system
- Must be run as a regular user (not root)

## Usage

```bash
git clone https://github.com/yourusername/linux-privesc-checker.git
cd linux-privesc-checker
chmod +x privesc_checker_linux.py
./privesc_checker_linux.py
```

## Author
Mithun Kailash
