# FriendlyDNSReporter (Python Edition)
> *Because it is always DNS. Or not. But mostly yes.*

[![Python](https://img.shields.io/badge/Language-Python-3776AB.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Stable_(v2.9.7)-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

Does your boss ask for "evidence" that the DNS is broken? 
Do you enjoy typing `dig` 5,000 times a day? 
Do you like staring at raw text output until your eyes bleed?

**No?** Then `FriendlyDNSReporter` is for you.

This tool has been completely rewritten in Python to ensure native compatibility between **Windows** and **Linux**, providing fast, parallel diagnostics and modern visual reports.

## 🚀 Features (Buzzwords)

*   **3-Phase Diagnostics**: Optimized workflow covering Server (Infra), Zone (Sync/AXFR), and Records (Consistency).
*   **True Parallelism**: Multithreaded execution to test hundreds of records in seconds.
*   **Premium Dashboard**: Modern visual reports (HTML) with detailed metrics and mobile responsiveness.
*   **Security & Compliance**: AXFR vulnerability testing, BIND version audit, DNSSEC validation, DoH/DoT, and EDNS0 (NSID).
*   **Dynamic Configuration**: Full `settings.ini` integration (Respecting toggles, timeouts, and consistency modes).
*   **Friendly Interface**: Color-coded terminal logs with phase-based grouping.

## 📦 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/flashbsb/FriendlyDNSReporter.git
    cd FriendlyDNSReporter
    ```

2.  Dependencies are now installed **automatically** during the first run. Just execute the script:
    ```bash
    python friendly_dns_reporter.py
    ```

## 🎮 Usage

### Basic Execution
The script uses files in the `config/` directory by default:
```bash
python friendly_dns_reporter.py
```

### Advanced Examples
```bash
# Using custom datasets and 20 parallel threads
python friendly_dns_reporter.py -n my_dataset.csv -t 20

# Running a consistency loop (repeats each test 3 times)
python friendly_dns_reporter.py -c 3
```

### Command Flags

| Flag | Description |
|------|-------------|
| `-n` | **Domains CSV**. Path to domains file (Default: `config/domains.csv`). |
| `-g` | **Groups CSV**. Path to server groups file (Default: `config/groups.csv`). |
| `-o` | **Output**. Directory to save reports (Default: `logs`). |
| `-t` | **Threads**. Parallel execution count (Default: 10 or from `.ini`). |
| `-c` | **Consistency**. Number of repetitions per test to detect divergence. |
| `-h` | **Help**. Show available options. |

## ⚙️ Configuration (`config/settings.ini`)

The `settings.ini` file centralizes script behavior:
- `ENABLE_PHASE_*`: Toggle Infrastructure, Zone, or Record phases independently.
- `MAX_THREADS`: Parallelism limit.
- `TIMEOUT` / `DIG_TIMEOUT`: Global and engine timeouts.
- `LOG_DIR`: Directory where reports are saved.
- `STRICT_*_CHECK`: Define tolerance for record consistency (IP, TTL, Order).

## 📄 Input Files

Data files must be in CSV format (using `;` delimiter):

### `config/groups.csv`
```csv
# NAME;DESCRIPTION;TYPE;TIMEOUT;SERVERS
GOOGLE;Google Public DNS;recursive;2;8.8.8.8,8.8.4.4
OPENDNS;Cisco OpenDNS;recursive;3;208.67.222.222,208.67.220.220
```

### `config/domains.csv`
```csv
# DOMAIN;GROUPS;STRATEGY;RECORDS;EXTRA
google.com;GOOGLE,CLOUDFLARE;recursive;A,AAAA,TXT;www,mail
wikipedia.org;QUAD9,OPENDNS;recursive;A,SOA;
```

## 🤝 Contributing

Found a bug? Have a cool feature to add?
Please open a Pull Request. We appreciate any help maintaining this "mostly DNS" diagnostic tool.

## 📜 License

MIT. Use it as you wish, just don't blame us if it breaks your DNS.
