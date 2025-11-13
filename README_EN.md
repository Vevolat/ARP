# NetAttack Tool

**Disclaimer: This tool is for educational purposes and authorized security testing only. Unauthorized use for attacks is illegal.**

## Overview

NetAttack is a network scanning and attack simulation tool designed for security professionals and students to understand network vulnerabilities. It supports multiple languages and can run on both Windows and Linux systems.

## System Requirements

- Python 3.6+
- Windows or Linux operating system
- Required Python libraries:
  - scapy
  - colorama (optional, for colored output)

## Installation

1. Clone or download this repository
2. Install the required dependencies:
```bash
pip install scapy
```

For enhanced output with colors (optional):
```bash
pip install colorama
```

## Usage

Run the program with:
```bash
python main.py
```

### Features

1. **Multilingual Support**: Switch between Chinese and English interfaces
2. **Two Attack Modes**:
   - Network Scanning Mode: Scan and identify live hosts in your network segment
   - Direct Attack Mode: Target a specific IP or domain
3. **Safety Mechanisms**:
   - Global "exit" command available at any input point
   - Confirmation required before launching attacks
4. **Cross-platform Compatibility**: Works on both Windows and Linux systems

### Operating Instructions

1. Select your preferred language (Chinese/English)
2. Choose operation mode:
   - Mode 1: Network scanning (automatically detects network segment)
   - Mode 2: Direct attack (enter target IP/domain)
3. Follow on-screen instructions

### Safety Notes

- This tool is intended for educational purposes and authorized penetration testing only
- Never use this tool against networks or systems without explicit permission
- Always comply with applicable laws and regulations
- The developers are not responsible for any misuse of this tool

## Technical Principles

The tool works by:
1. Detecting network interfaces and determining the local network segment
2. Performing ICMP scans to identify live hosts
3. Simulating network stress through packet generation (educational purposes only)

## Legal Statement

This software is provided "as is", without warranty of any kind. The authors are not responsible for any damages or legal issues arising from the use of this tool. Users must ensure compliance with all applicable laws and regulations.

By using this software, you agree to use it responsibly and legally.
