<h1>ADGuard – Active Directory Security Posture Assessment Tool</h1>

<p>
ADGuard is a <strong>read-only Active Directory security posture assessment tool</strong>
designed to identify common and high-impact AD misconfigurations caused by insecure defaults,
weak delegation, and operational drift.
</p>

<p>
The tool is intended for <strong>blue teams, security engineers, and researchers</strong>
to quickly understand the health and risk exposure of an Active Directory environment
<strong>without performing any exploitation</strong>.
</p>

<p><strong>⚠️ ADGuard is NOT an attack tool.</strong><br>
It does not modify Active Directory objects or credentials.</p>

<hr>

<h2>✨ Key Features</h2>

<ul>
  <li>🔍 Detects common Active Directory misconfigurations</li>
  <li>🛡️ Tier-0 aware (AdminSDHolder / adminCount=1 suppression)</li>
  <li>🧾 Read-only data collection (safe for production)</li>
  <li>📊 Generates a styled HTML security report</li>
  <li>📈 Visual severity distribution (pie chart with percentages)</li>
  <li>📂 Works fully offline (no external dependencies at runtime)</li>
  <li>🔐 Supports least-privilege audit accounts</li>
</ul>

<hr>

<h2>🧠 What ADGuard Checks</h2>

<h3>Active Directory &amp; Identity</h3>
<ul>
  <li>Kerberoast exposure (user / service accounts with SPNs)</li>
  <li>PasswordNeverExpires accounts</li>
  <li>Stale or risky service account configurations</li>
  <li>krbtgt password age checks</li>
</ul>

<h3>Privilege &amp; Delegation</h3>
<ul>
  <li>Dangerous ACLs on:
    <ul>
      <li>Domain root</li>
      <li>Domain Controllers OU</li>
    </ul>
  </li>
  <li>DCSync-capable permissions</li>
  <li>Unauthorized write / control delegation</li>
  <li>MachineAccountQuota misconfiguration</li>
</ul>

<h3>Group Policy</h3>
<ul>
  <li>Weak or risky GPO settings</li>
  <li>GPO posture inconsistencies</li>
</ul>

<h3>Reporting</h3>
<ul>
  <li>Severity-based findings (CRITICAL, HIGH, MEDIUM, LOW, INFO)</li>
  <li>Collapsible findings for readability</li>
  <li>Right-aligned severity distribution chart with percentages</li>
</ul>

<hr>

<h2>🖥️ Supported Environment</h2>

<ul>
  <li>Windows 10 / 11</li>
  <li>Domain-joined system</li>
  <li>PowerShell 5.1+</li>
  <li>Python 3.10+</li>
</ul>

<p><strong>❌ A Windows Server OS is NOT required</strong></p>

<hr>

<h2>📋 Prerequisites</h2>

<h3>PowerShell Modules</h3>
<ul>
  <li>ActiveDirectory</li>
  <li>GroupPolicy</li>
</ul>

<h3>Python</h3>
<pre><code>python --version</code></pre>

<h3>Chart.js (Offline Reports)</h3>
<pre><code>
Invoke-WebRequest https://cdn.jsdelivr.net/npm/chart.js `
  -OutFile C:\adguard\engine\chart.min.js
</code></pre>

<hr>

<h2>🚀 Usage</h2>

<pre><code>
.\adguard.ps1 -Command bootstrap
.\adguard.ps1 -Command collect
.\adguard.ps1 -Command analyze
</code></pre>

<hr>

<h2>🧪 Safe to Run in Production?</h2>

<ul>
  <li>✔ Read-only</li>
  <li>✔ No exploitation</li>
  <li>✔ No password dumping</li>
  <li>✔ No object modification</li>
  <li>✔ No persistence mechanisms</li>
</ul>

<hr>
  
<h2>You can view a example reoprt at https://deucalion77.github.io/AD-Guard/ 
<hr>
<h2>⚠️ Disclaimer</h2>

<p>
This tool is provided for <strong>defensive and educational purposes only</strong>.
The author assumes <strong>no liability for misuse</strong>.
</p>
