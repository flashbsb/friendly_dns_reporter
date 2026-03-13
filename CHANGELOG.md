# Changelog

All notable changes to this project will be documented in this file.

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
