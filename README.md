# FriendlyDNSReporter
> *Because it is always DNS. Or not. But mostly yes.*

[![Python](https://img.shields.io/badge/Language-Python-3776AB.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Stable_(v5.2.0)-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

Does your boss ask for "evidence" that the DNS is broken? 
Do you enjoy typing `dig` 5,000 times a day? 
Do you like staring at raw text output until your eyes bleed?

**No?** Then `FriendlyDNSReporter` is for you.

This tool has been completely rewritten in Python to ensure native compatibility between **Windows** and **Linux**, providing fast, parallel diagnostics and modern visual reports.

## 🚀 Features (Buzzwords)

*   **Interactive Terminal Legends (v5.2.0)**: Automatic legends after each diagnostic phase explaining columns, colors, and statuses. Toggled via `.ini`.
*   **UI Transparency & Colorization (v5.1.0)**: Phase 2 reports exact DNS error codes (e.g., TIMEOUT). Phase 3 sync statuses are fully colorized.
*   **Deep Service Validation (v5.0.0)**: Differentiates between Port status (socket) and Service status (real DNS response) for UDP, TCP, DoT, and DoH.
*   **Smart Loader (v5.0.0)**: Automatic detection of CSV delimiters (`,` or `;`) and Type-aware queries (Recursive vs. Authoritative).
*   **Selective Diagnostics**: Run only the phases you need using CLI flags (`-p 1,3`).
*   **3-Phase Circuit Breaker**: Phase 1 acts as a gatekeeper; if a service is truly down, the script skips subsequent phases to save time.
*   **Semantic DNS Audit (v4.0.0)**: SPF/DMARC validation, Dangling DNS detection, MX reachability, and Wildcard mapping.
*   **Performance Tracking (v4.1.0)**: Configurable latency thresholds (WARN/CRIT) across all phases.
*   **Premium Dashboard**: Modern responsive HTML reports with charts and detailed findings.

## 📊 Logic Flow

```mermaid
graph TD
    Start((Start)) --> LoadConfig[Load settings.ini & Data]
    LoadConfig --> SmartLoad[Smart CSV Loader: Delimiter & Type Detection]
    SmartLoad --> PhaseSelect{Phase Selection?}
    
    PhaseSelect -- Selective --> Phase1
    PhaseSelect -- Default All --> Phase1

    subgraph "Phase 1: Deep Infrastructure"
        Phase1 --> Ping[Ping & Latency SLA]
        Phase1 --> PortCheck[Port Socket Check]
        PortCheck --> ServiceCheck[Deep Service Validation: UDP, TCP, DoT, DoH]
        ServiceCheck --> CircuitBreaker{Service Functional?}
        CircuitBreaker -- YES --> Legend1[UI Legend Phase 1]
    end

    Legend1 --> Phase2

    CircuitBreaker -- NO --> Skip[Skip Phase 2 & 3 for this Server]
    CircuitBreaker -- YES --> Phase2

    subgraph "Phase 2: Zone Integrity"
        Phase2 --> Recursion[Type-Aware Recursion & Smart Fallback]
        Recursion --> Sync[SOA Serial Sync]
        Sync --> AA[Lame Delegation AA Flag]
        AA --> Advanced[Audit: RFC 1912 & NS Consistency]
        Advanced --> Legend2[UI Legend Phase 2]
    end

    Phase2 --> Phase3

    subgraph "Phase 3: Semantic Audit"
        Phase3 --> Parallel[Type-Aware Queries: RD bit based on Group Type]
        Phase3 --> Semantic[SPF/DMARC Syntax & Security]
        Phase3 --> Chain[Dangling DNS & MX Target Test]
    end

    Phase3 --> Legend3[UI Legend Phase 3]
    Legend3 --> Reports[Generate HTML / JSON / CSV / Terminal]
    Reports --> End((End))
    Skip --> Reports
```

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
# Run only Phase 1 (Infrastructure) and Phase 3 (Records)
python friendly_dns_reporter.py -p 1,3

# Using custom datasets and 20 parallel threads
python friendly_dns_reporter.py -n my_dataset.csv -t 20

# Running a consistency loop (repeats each test 3 times)
python friendly_dns_reporter.py -c 3
```

### Command Flags

| Flag | Description |
|------|-------------|
| `-p` | **Phases**. Select phases to run (e.g., `1`, `1,3`, `2`). Default: All. |
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
- `DNS_TIMEOUT` / `DNS_RETRIES`: Native engine execution parameters.
- `LOG_DIR`: Directory where reports are saved.
- `STRICT_*_CHECK`: Define tolerance for record consistency (IP, TTL, Order).

## 📄 Input Files

The script now features a **Smart Loader (v5.0.0)** that automatically detects the delimiter (`;` or `,`).

### `config/groups.csv`
```csv
# NAME;DESCRIPTION;TYPE;TIMEOUT;SERVERS
GOOGLE;Google Public DNS;recursive;2;8.8.8.8,8.8.4.4
OPENDNS;Cisco OpenDNS;recursive;3;208.67.222.222,208.67.220.220
```
> [!NOTE]
> The `TYPE` column (recursive/iterative) is used to automatically set the recursion bit in DNS queries.

### `config/domains.csv`
```csv
# DOMAIN;GROUPS;RECORDS;EXTRA
google.com;GOOGLE,CLOUDFLARE;A,AAAA,TXT;www,mail
wikipedia.org;QUAD9,OPENDNS;A,SOA;
```

## 🤝 Contributing

Found a bug? Have a cool feature to add?
Please open a Pull Request. We appreciate any help maintaining this "mostly DNS" diagnostic tool.

## 📜 License

MIT. Use it as you wish, just don't blame us if it breaks your DNS.
