# IoT CyberShield: Secure IoT Device Monitoring, Cyberattack Detection, Forensics, and OTA Verification Platform

**IoT CyberShield** is a full-stack IoT cybersecurity platform built for real cryptographic integrity verification, Ed25519 digital signature validation, anti-rollback version policy enforcement, anti-replay protection, attack detection, and detailed incident investigations across software-emulated IoT nodes.

---

## 1. Exactly Four Supported Reference Device Models

The platform supports exclusively these four IoT device reference models:

| Device ID | Device Name & Model | Category | Static Image Asset | Security Controls & Emulation Scope |
| :--- | :--- | :--- | :--- | :--- |
| `DEV-CAM-01` | **TP-Link Tapo C200** | Smart Camera | `/images/tapo-c200.png` | RTSP stream authentication, web admin interface, configuration changes, privacy mode toggle, firmware verification. |
| `DEV-LCK-02` | **ESP32 Smart Locker DevKit** | Smart Access Control | `/images/smart-locker-esp32.png` | DIY ESP32 DevKit, 4×4 tactile keypad, and 12V solenoid lock. Interactive PIN entry (valid master PIN `1234`), 5s auto-relock, brute-force lockout, anti-replay token ledger. Plaintext PINs are never logged. |
| `DEV-ENV-03` | **DHT22 / AM2302** | Environmental Sensor | `/images/dht22-am2302.png` | Digital capacitive temperature and humidity telemetry (-10°C to 45°C, 15% to 85% RH bounds). Detects out-of-bounds readings, missing sensor heartbeats, and implausible thermal jumps (> 25°C in < 10s). Classified honestly as health incidents, not attacks. |
| `DEV-RTR-04` | **TP-Link Archer C6** | Network Router | `/images/archer-c6.png` | AC1200 MU-MIMO Gigabit Router. Web admin session authentication (HTTPS 443), stateful firewall level management, DNS server configuration, WAN connectivity stats. |

*Note: All four image assets are stored locally in `public/images/` and reused consistently across dashboards, device cards, detail consoles, incident forensics, and reports.*

---

## 2. Core Architecture & Technology Stack

- **Frontend**: Responsive, modern cybersecurity console with zero-pill visual discipline, custom styling, interactive hardware consoles (including interactive ESP32 4×4 keypad, sensor sliders, and RTSP stream testing), and 22-field forensic dossier views.
- **Backend**: Node.js 22, Express.js REST APIs with robust error handling and input validation.
- **Database**: Persistent SQLite (`cybershield.db`) with automatic table migrations and relational schema across devices, security events, 22-dimension incidents, trusted keys, replay cache, anomaly rules, anomaly alerts, audit logs, benchmark runs, and threat records.
- **Cryptography**:
  - **SHA-256**: Cryptographic digest calculation over firmware bytes and manifests.
  - **Ed25519**: Asymmetric digital signature generation and verification. Private signing keys are stored exclusively on the backend (`data/dev_keys.json`) and never exposed to the frontend bundle or client browser.
- **Emulation & Docker**:
  - `docker-compose.yml` defining isolated, non-root micro-containers for each emulator with memory quotas (128M–256M), CPU limits (0.25–0.50), dropped capabilities (`cap_drop: ALL`), and private bridge networking.
  - Runtime environment autodetection: when Docker daemon is not available (e.g. cloud containers), the platform honestly reports `Docker unavailable` and operates in software emulation mode.

---

## 3. Attack Detection Engine (10 Supported Scenarios)

The detection engine evaluates incoming firmware updates and telemetry through identical rules regardless of whether they originate from emulator services, user uploads, or the Attack Simulator:

1. **Firmware Binary Tampering (`RULE-TAMPER-001`)**: Calculates SHA-256 over raw firmware bytes and compares against manifest hash. Bit-flip or hash mismatches are rejected.
2. **Invalid / Forged Digital Signature (`RULE-SIG-002`)**: Cryptographically validates Ed25519 signatures against the device's configured public key. Rejects invalid signatures.
3. **Unknown / Rogue Signing Key (`RULE-KEY-003`)**: Validates signing key ID against the platform's trusted root keystore (`trusted_keys`). Packages signed by untrusted or revoked keys are rejected.
4. **Unauthorized Firmware Downgrade (`RULE-DWN-004`)**: Compares proposed version against device anti-rollback threshold. Old versions with unpatched CVEs are blocked.
5. **Replay Attack / Transaction Reuse (`RULE-RPL-005`)**: Enforces single-use nonce tokens using the persistent `accepted_replay_tokens` SQLite ledger. Duplicate request IDs are discarded.
6. **Repeated Authentication Failures (`RULE-AUTH-001` & `RULE-LCK-010`)**: Tracks failed PIN attempts and login attempts in sliding 60-second windows. Tripping the threshold triggers temporary simulated lockout and generates high-severity alerts.
7. **Malformed Package Container (`RULE-MAL-008`)**: Rejects missing manifest headers, invalid schemas, traversal paths, or non-binary plain-text uploads (e.g. `safe_firmware_test.txt`).
8. **Unauthorized Configuration Changes (`RULE-CFG-008`)**: Intercepts unauthenticated administrative writes attempting to disable firewall policies or modify router DNS servers.
9. **Missed Heartbeat / Availability Outage (`RULE-HBT-006`)**: Flags nodes that miss keepalive intervals. Correctly classified as **Device health incidents**, not cyberattacks.
10. **Container Health & Process Outages**: Detects container exit events and updates device status to `Offline`.

---

## 4. Complete Attack Forensics: 22 Required Dimensions

Every detected incident generates a dedicated, persistent forensic dossier containing all 22 required fields:

1. `id` — Unique incident identifier (e.g. `INC-2026-004`).
2. `title` — Human-readable descriptive title.
3. `classification` — Validated classification (`Confirmed simulated attack`, `Suspicious activity`, `Security policy violation`, `Device health incident`, `Unverified event`, or `Benign event`).
4. `severity` & `severity_justification` — Risk severity rating and technical rationale.
5. `device_id` & `device_model` — Target node and hardware reference model.
6. `timestamp_utc` & `timestamp_local` — Dual timestamps for synchronized investigation.
7. `summary` — "What happened" explained in plain, beginner-friendly cybersecurity language.
8. `attack_category` — Specific attack taxonomy (e.g., *Firmware Tampering / Bit Modification*).
9. `occurred_location` — Exact service, pipeline stage, or authentication interface.
10. `source_metadata` — Observed IP or `Internal simulator` (never fabricated external geo).
11. `destination_metadata` — Specific device daemon receiving the transaction.
12. `entry_point` — Exact REST API route or physical interface tested.
13. `detection_rule_id` — Unique rule trigger code.
14. `trigger_reason` & `evidence` — Hash diffs, signature verify outputs, and raw metadata.
15. `correlated_events` — Chronological sequence of related telemetry events.
16. `observed_impact` — Actual system behavior observed during the event.
17. `response_action` — Technical countermeasure executed by the platform.
18. `response_success` — Verification that the defense succeeded.
19. `recovery_status` — Platform recovery state (e.g., *Recovered (Normal Operation)*).
20. `confidence_level` & `evidence_limitations` — Honest assessment of emulation boundaries.
21. `recommended_action` — Actionable next steps for security analysts.
22. `investigation_notes` & `resolution_history` — Auditable log of analyst notes and status changes.

---

## 5. Performance Overhead Benchmarks & Threat Modeling

- **High-Resolution BigInt Timers**: Measures nanosecond execution deltas (`process.hrtime.bigint()`) for SHA-256 hashing, Ed25519 signature checks, manifest parsing, version policy checks, and replay lookups.
- **Process Resource Usage**: Captures Node.js PID CPU user time, system kernel time, process RSS memory, and V8 heap utilization.
- **Fleet Scaling Curves**: Measures latency scaling across fleet sizes (1, 5, 10, 20 nodes).
- **ISO/SAE 21434 & NIST Threat Model**: Complete register of 9 protected assets, 7 attacker profiles, 7 trust boundaries, 12 threats with Likelihood × Impact risk scores, and 8 hardware reality constraints.

---

## 6. Installation & Execution Guide

### Prerequisites
- Node.js 18.x or 22.x
- npm 9.x+
- *(Optional)* Docker and Docker Compose (for local containerized emulation)

### Setup & Run Commands

```bash
# 1. Clone or extract repository
git clone <repo-url>
cd iot-cybershield

# 2. Install dependencies
npm install

# 3. Run automated tests (verifies all 36 test cases and 22 acceptance criteria)
npm test

# 4. Start the application
npm start
# Server listens on http://localhost:3000
```

### Running with Docker Compose (Local & Windows / Mac)

```bash
# Build and start all 4 device emulator containers and the platform backend:
docker compose up --build -d

# Check running container status:
docker compose ps

# View backend logs:
docker compose logs -f cybershield-backend

# Stop containers:
docker compose down
```

---

## 7. Operational Features vs Physical Hardware Limitations

| Feature | Operational in Emulation Prototype | Requires Real Physical Hardware / Authorized Integration |
| :--- | :---: | :---: |
| SHA-256 Firmware Ingestion & Hashing | **YES (Real)** | — |
| Ed25519 Asymmetric Signature Validation | **YES (Real)** | — |
| Monotonic Anti-Rollback Version Enforcement | **YES (Real)** | Hardware eFuses / OTP memory counters |
| Anti-Replay Nonce Ledger | **YES (Real)** | — |
| 10 Attack Simulation Scenarios | **YES (Real)** | Real RF jamming or physical JTAG hardware probes |
| 22-Field Incident Forensics & Dossiers | **YES (Real)** | — |
| Interactive 4x4 Keypad PIN & Lock Simulation | **YES (Real)** | Physical 12V relay & physical solenoid deadbolt |
| DHT22 Thermal & Humidity Telemetry Bounds | **YES (Real)** | Physical DHT22/AM2302 sensor probe & ambient air |
| TP-Link Tapo C200 Access & Config Simulation | **YES (Real)** | Real ONVIF video stream & manufacturer cloud account |
| TP-Link Archer C6 Admin & Firewall Simulation | **YES (Real)** | Real gigabit packet routing & physical WAN port |
| Docker Container Fleet (CPU/RAM limits, non-root) | **YES (Real)** | Requires local Docker daemon when running in cloud |
| High-Resolution BigInt Benchmarking & CSV Export | **YES (Real)** | — |
| Threat Model & HTML Report Generator | **YES (Real)** | — |

---

## 8. Troubleshooting

- **Docker Status displays "Docker unavailable"**:
  - The application is running in an environment without access to a local Docker daemon (e.g. cloud container sandbox). The platform automatically switches to Node.js software emulation and all 4 device models, attack detection rules, and interactive consoles operate normally. To enable containerized Docker emulation, run `docker compose up` on a host running Docker Desktop.
- **Port 3000 in use**:
  - Set an alternate port in `.env` (e.g. `PORT=3001`) and restart with `npm start`.
- **Database Reset**:
  - Navigate to **Settings & Thresholds** in the sidebar and click **Reset Transient Simulation & Test Data**, or remove `data/cybershield.db` to trigger automatic re-seeding on server start.