ADGuard – Active Directory Security Posture Assessment Tool

ADGuard is a read-only Active Directory security posture assessment tool designed to identify common and high-impact AD misconfigurations caused by insecure defaults, weak delegation, and operational drift.

The tool is intended for blue teams, security engineers, and researchers to quickly understand the health and risk exposure of an Active Directory environment without performing any exploitation.

⚠️ ADGuard is not an attack tool. It does not modify Active Directory objects or credentials.

✨ Key Features

🔍 Detects common Active Directory misconfigurations

🛡️ Tier-0 aware (AdminSDHolder / adminCount=1 suppression)

🧾 Read-only data collection (safe for production)

📊 Generates a styled HTML security report

📈 Visual severity distribution (pie chart + percentages)

📂 Works offline (no external dependencies at runtime)

🔐 Supports least-privilege audit accounts

🧠 What ADGuard Checks

ADGuard currently identifies the following classes of issues:

Active Directory & Identity

Kerberoast exposure (user/service accounts with SPNs)

PasswordNeverExpires accounts

Stale / risky service account configurations

krbtgt password age checks

Privilege & Delegation

Dangerous ACLs on:

Domain root

Domain Controllers OU

DCSync-capable permissions

Unauthorized write / control delegation

MachineAccountQuota misconfiguration

Group Policy

Weak or risky GPO settings

GPO posture inconsistencies

Reporting

Severity-based findings (CRITICAL / HIGH / MEDIUM / LOW / INFO)

Collapsible findings for readability

Right-aligned severity distribution chart with percentages

🖥️ Supported Environment

Windows 10 / 11 (client OS is sufficient)

Domain-joined system

PowerShell 5.1+

Python 3.10+

❌ A Windows Server OS is not required

📋 Prerequisites
1️⃣ PowerShell Modules (built-in)

The following Windows modules are required:

ActiveDirectory

GroupPolicy

They are available by default on domain-joined Windows systems with RSAT installed.

2️⃣ Python

Install Python 3.10 or newer and ensure it is added to PATH.

Verify:

python --version

3️⃣ Chart.js (offline report support)

For offline reports, download Chart.js once:

Invoke-WebRequest https://cdn.jsdelivr.net/npm/chart.js -OutFile C:\adguard\engine\chart.min.js

🔐 Audit Account Model (Recommended)

ADGuard is designed to run using a dedicated audit account with read-only permissions.

The tool includes a bootstrap process that:

Creates a domain audit user

Creates an audit group

Applies minimal read-only delegation

Ensures consistent permissions across environments

This avoids:

Running as Domain Admin

Using personal admin accounts

Permission-related scan failures

🚀 Installation

Clone the repository:

git clone https://github.com/<your-username>/adguard.git
cd adguard


Ensure execution policy allows script execution:

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

▶️ Usage

ADGuard is controlled via a single launcher script: adguard.ps1

1️⃣ Bootstrap (run once per domain)

Creates the audit user and applies required read-only permissions.

.\adguard.ps1 -Command bootstrap


Optional parameters:

Custom audit user name

Custom OU placement

Enable Event Log Readers GPO (optional)

2️⃣ Collect Data

Collects AD configuration data (read-only).

Run as:

The audit user or

Any account with equivalent read permissions

.\adguard.ps1 -Command collect


Or explicitly prompt for audit credentials:

.\adguard.ps1 -Command collect -UseAuditCredential


Collected data is stored in:

C:\adguard\out\raw\

3️⃣ Analyze & Generate Report

Runs all analysis rules and generates:

scan.json (machine-readable)

report.html (human-readable)

.\adguard.ps1 -Command analyze


Open the report:

Start-Process C:\adguard\out\reports\report.html

📊 Report Output

The HTML report includes:

Executive summary

Severity-based findings

Collapsible finding details

Evidence, impact, and remediation

Pie chart with percentage breakdown

Fully offline support

🧪 Safe to Run in Production?

✔ Yes — ADGuard is read-only
✔ No exploitation
✔ No password dumping
✔ No object modification
✔ No persistence mechanisms

It is designed to be defensive, auditable, and non-intrusive.

🎓 Research Context

This tool was developed as part of an academic research project focused on:

Evaluating the security impact of Active Directory misconfigurations and delegation weaknesses in enterprise environments

The project draws inspiration from tools such as:

PingCastle

BloodHound (analysis concepts only)

…but focuses on:

Blue-team usage

Least-privilege scanning

Human-readable reporting

🚧 Current Limitations

No live event log correlation (planned)

No exploitation simulation

Designed for single-forest domains

Azure AD / Entra ID not covered

🛣️ Future Work

Planned enhancements include:

Event log-based detection

Azure AD / hybrid support

Baseline comparison between scans

JSON export for SIEM ingestion

Automated remediation guidance

⚠️ Disclaimer

This tool is provided for defensive and educational purposes only.
The author assumes no liability for misuse.
