# Changelog

All notable changes to this project will be documented in this file.

## [2.9.7] - 2026-03-13
### Added
- **Contextual AXFR Policy Audit**: Introduced `AXFR_ALLOWED_GROUPS` in `settings.ini`.
- **Objective AXFR Labeling**: Replaced "SAFE/VULN" with technical labels (`REFUSED`, `XFR-OK (n nodes)`, `TIMEOUT`).
- **Policy Compliance Check**: Phase 2 now color-codes AXFR status based on intent: `REFUSED` is Green for general servers but Yellow/Red for expected secondaries. `XFR-OK` is Green for secondaries but Red for unauthorized servers.

## [2.9.6] - 2026-03-13
### Added
- **SOA Sync Visualization**: The `SOA Serial` column now displays `OK(SERIAL)` in green if the zone is synchronized across all servers, or `FAIL(SERIAL)` in red if discrepancies are found.

## [2.9.4] - 2026-03-13
### Added
- **Enhanced Zone Audit (Phase 2)**: 
    - Integrated **Lame Delegation** detection by monitoring the Authoritative Answer (`AA`) flag.
    - Added **SOA Query Latency** tracking to identify slow authoritative servers.
    - Implemented **NS Record Consistency** checks across all servers in a group, alerting if a server returns a different set of name servers.
    - Extracted and prepared detailed SOA metadata (MNAME, RNAME) for reporting.

## [2.9.2] - 2026-03-13
### Added
- **Real-time Progress Indicators**: Integrated a dynamic status bar that tracks the completion percentage of parallel threads across all diagnostic phases.
- **Group-based Sorting**: Phase 1 infrastructure results are now automatically sorted alphabetically by Group name.

## [2.9.1] - 2026-03-13
### Optimized
- **OpenResolver Clarity**: Updated status strings (`REFUSED`, `SERVFAIL`, `OPEN`) to avoid false positives.
- **Phase 1 Layout**: Re-introduced the Server `Group` column.
- **Timestamped Reports**: Report filenames now include execution timestamps.

## [2.9.0] - 2026-03-13
### Added
- **Global Latency UI**: Display latency `(xxms)` for all Phase 1 checks.
- **Advanced Infrastructure Checks**: Root DNSSEC, EDNS0, and Amplification testing.
- **Connectivity Dropping Metrics**: Upgraded PING column with packet loss `%`.

## [2.8.2] - 2026-03-13
### Fixed
- **NSID Attribute Support**: Implemented robust attribute access for extracting the NSID in dnspython (checking for both `.nsid` and `.data`), resolving a script-breaking crash `AttributeError: 'NSIDOption' object has no attribute 'data'` on newer dnspython versions.

## [2.8.1] - 2026-03-13
### Added
- **Recursion Query Latency**: Phase 1 now measures and displays the specific response time for UDP Recursion queries directly in the terminal output, mirroring the TCP and ICMP latency visualizations.

## [2.8.0] - 2026-03-13
### Added
- **Auto-dependency resolution**: The script now automatically detects if required Python packages (`urllib3`, `dnspython`, `requests`, `Jinja2`, `icmplib`) are missing and uses `sys.executable` with `pip` to install them silently on both Windows and Linux, eliminating `ModuleNotFoundError` completely.

## [2.7.0] - 2026-03-13
### Added
- **Granular Latency Tracking**: Phase 1 now measures and displays the specific response time for every successful probe (Port 53 TCP, Port 443 TCP, and DNS UDP).
- **Performance Insight**: Both the terminal output and HTML dashboard now show exactly how long each infrastructure component took to respond, rather than just a single ping latency.

## [2.6.1] - 2026-03-13
### Added
- **Group Tracking**: Phase 1 now displays which groups each server belongs to in the terminal and HTML report.

## [2.6.0] - 2026-03-13
### Optimized
- **Scoped Diagnostics**: The script now automatically identifies which DNS groups are being used in `domains.csv`.
- **Performance**: Phase 1 now only tests servers that are actually required for the current run, ignoring unrelated infrastructure in `groups.csv`.

## [2.5.1] - 2026-03-13
### Fixed
- **Terminal UI Headers**: Added clear headers for each diagnostic phase (Infrastructure, Zones, Records) for better readability.
- **Liveness Logic (Bug Fix)**: Fixed issue where disabled DNS checks could result in a false "ALIVE" status for dead servers.
- **UI Alignment**: Fine-tuned column widths in terminal output for a perfect table layout.

## [2.5.0] - 2026-03-13
### Added
- **Infrastructure Expansion**: Added connectivity testing for Port 443 (HTTPS/DoH).
- **Protocol Separation**: Distinguished between Port 53 TCP and Port 53 UDP in terminal and reports.
- **Robust Circuit Breaker**: Refined the "is_dead" logic to include Port 443 results, ensuring maximum diagnostic coverage before skipping a server.

## [2.4.1] - 2026-03-13
### Added
- **Circuit Breaker Logic**: Automatically detect "dead" servers in Phase 1 and skip redundant tests in subsequent phases.
- **Granular Error States**: Now distinguishes between `OPEN`, `CLOSED`, `TIMEOUT`, and `UNREACHABLE` (instead of masking all failures as "closed").
- **Visual Feedback**: Improved UI and Dashboard with specific badges and coloring for network-related failures.

## [2.4.0] - 2026-03-13
### Added
- **3-Phase Diagnostic Logic**: Refactored the core engine to follow the Server-Infrastructure, Zone-Integrity, and Record-Consistency workflow.
- **Enhanced Configuration**: Full support for `settings.ini` variables, including phase toggles and consistency strictness.
- **Advanced Security Checks**: Added AXFR (Zone Transfer) vulnerability testing and EDNS0 (NSID/Cookies) support.
- **Legacy DIG Mapping**: Translated DIG parameters (`TIMEOUT`, `TRIES`) to native Python logic for backward compatibility.
- **Premium Reporting**: Updated HTML dashboard with detailed phase metrics and modern aesthetics.

## [2.3.0] - 2026-03-13
### Added
- **Full Feature Parity**: Restored logic for `SLEEP` (rate-limiting) and diagnostic toggles from the original Bash version.
- **Configurable Connectivity**: `PING_COUNT` and various `ENABLE_*_CHECK` flags now fully control the diagnostic engine.
- **Improved Reliability**: Better protection against firewall rate-limiting and redundant query filtering.

## [2.2.1] - 2026-03-13
### Fixed
- **Sync Logic**: Resolved issue where synchronization was reported as [OK] even when all queries failed.

## [2.2.0] - 2026-03-13
### Added
- **Architectural Refinement**: Decoupled script into specialized modules (`core/ui.py`, `core/config_loader.py`).
- **Professional Logging**: Integrated structured logging infrastructure.
- **Clean Code Improvements**: Improved modularity and typed settings access.
