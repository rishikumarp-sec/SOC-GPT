import { useState } from "react";
import "./App.css";

const SYSTEM_PROMPT = `You are an expert SOC analyst and cybersecurity incident responder with 10+ years of experience in threat detection, incident response, and security operations.

When given a security log entry, analyze it deeply and respond ONLY with a valid JSON object in this exact format with no markdown, no code blocks, no explanation:

{
  "log_type": "one of: Linux SSH, AWS CloudTrail, Apache Web, Windows Event, Nmap Scan, Generic",
  "attack_type": "specific attack name",
  "severity": number between 1 and 10,
  "severity_label": "LOW or MEDIUM or HIGH or CRITICAL",
  "verdict": "TRUE_POSITIVE or FALSE_POSITIVE or NEEDS_INVESTIGATION",
  "false_positive_likelihood": "LOW or MEDIUM or HIGH",
  "explanation": "2-3 sentence plain English explanation of exactly what happened",
  "attacker_ip": "IP address string or null",
  "target": "what was targeted",
  "risk_factors": [
    {"factor": "description of risk factor", "score": number between 0.5 and 4.0}
  ],
  "iocs": ["indicator1", "indicator2"],
  "mitre_techniques": [
    {"id": "TXXXX.XXX", "name": "technique name", "description": "one line description"}
  ],
  "remediation": {
    "contain": ["step1", "step2", "step3"],
    "investigate": ["step1", "step2", "step3"],
    "remediate": ["step1", "step2", "step3"]
  },
  "prevention": {
    "root_cause": "one sentence explaining the root misconfiguration",
    "config_fixes": ["specific config change 1", "specific config change 2"],
    "tools_to_deploy": ["tool 1 with reason", "tool 2 with reason"],
    "policy_changes": ["policy recommendation 1", "policy recommendation 2"],
    "detection_rules": ["SIEM rule or alert to create 1", "SIEM rule or alert to create 2"]
  }
}`;

const LOG_EXAMPLES = {
  "Linux SSH": `May 26 07:36:22 ubuntu sshd[47140]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.64.14 user=user01
May 26 07:36:25 ubuntu sshd[47140]: Failed password for user01 from 192.168.64.14 port 45036 ssh2
May 26 07:36:50 ubuntu sshd[47140]: Accepted password for user01 from 192.168.64.14 port 45036 ssh2
May 26 07:42:05 ubuntu useradd[57660]: new user: name=hacker, UID=1001, GID=1002, home=/home/hacker, shell=/bin/sh`,
  "AWS CloudTrail": `{"eventName":"CreatePolicyVersion","userIdentity":{"userName":"lab-lowpriv-user"},"sourceIPAddress":"106.192.69.191","requestParameters":{"policyDocument":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}","setAsDefault":true}}`,
  "Nmap Scan": `May 21 11:12:54 ubuntu sshd[100941]: banner exchange: Connection from 192.168.64.14 port 49088: could not read protocol version
May 21 11:12:55 ubuntu sshd[100945]: Unable to negotiate with 192.168.64.14 port 49110: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1`,
  "Apache Web": `192.168.64.14 - - [20/Jun/2026:12:00:01 +0000] "GET /wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php HTTP/1.1" 200 3042
192.168.64.14 - - [20/Jun/2026:12:00:02 +0000] "GET /?id=1' OR '1'='1 HTTP/1.1" 200 5123`
};

const SEVERITY_COLORS = {
  LOW: { color: "#1D9E75", bg: "#0a1f17" },
  MEDIUM: { color: "#BA7517", bg: "#1f150a" },
  HIGH: { color: "#E24B4A", bg: "#1f0a0a" },
  CRITICAL: { color: "#7F77DD", bg: "#12101f" }
};

const VERDICT_COLORS = {
  TRUE_POSITIVE: "#E24B4A",
  FALSE_POSITIVE: "#1D9E75",
  NEEDS_INVESTIGATION: "#BA7517"
};

const LOG_TYPE_COLORS = {
  "Linux SSH": "#378ADD",
  "AWS CloudTrail": "#BA7517",
  "Apache Web": "#E24B4A",
  "Windows Event": "#7F77DD",
  "Nmap Scan": "#1D9E75",
  "Generic": "#888780"
};
export default function App() {
  const [log, setLog] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeHistory, setActiveHistory] = useState(null);
  const [activeTab, setActiveTab] = useState("analysis");

  const detectLogType = (text) => {
    if (text.includes("sshd") || text.includes("pam_unix") || text.includes("useradd")) return "Linux SSH";
    if (text.includes("eventName") || text.includes("CloudTrail") || text.includes("userIdentity")) return "AWS CloudTrail";
    if (text.includes("banner exchange") || text.includes("negotiate") || text.includes("nmap")) return "Nmap Scan";
    if (text.includes("HTTP/1") || text.includes("GET /") || text.includes("POST /")) return "Apache Web";
    if (text.includes("EventID") || text.includes("Windows") || text.includes("Security")) return "Windows Event";
    return "Generic";
  };

  const detectedType = log ? detectLogType(log) : null;

  const analyzeLog = async () => {
    if (!log.trim()) return;
    setLoading(true);
    setError(null);
    setAnalysis(null);
    setActiveTab("analysis");

    try {
      const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.REACT_APP_GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          max_tokens: 2000,
          temperature: 0.1,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: `Analyze this security log:\n\n${log}` }
          ]
        })
      });

      const data = await response.json();
      let text = data.choices[0].message.content;
      text = text.replace(/```json|```/g, "").trim();
      const parsed = JSON.parse(text);
      setAnalysis(parsed);
      setHistory(prev => [{
        id: Date.now(),
        log: log.slice(0, 80) + "...",
        attack_type: parsed.attack_type,
        severity: parsed.severity,
        severity_label: parsed.severity_label,
        verdict: parsed.verdict,
        full: parsed
      }, ...prev].slice(0, 10));
    } catch (err) {
      setError("Analysis failed. Check your API key or try again.");
    } finally {
      setLoading(false);
    }
  };

  const generateReport = (data, rawLog) => {
    if (!data) return;
    const report = `# SOC Incident Report
Generated: ${new Date().toLocaleString()}
Analyst Tool: SOC-GPT v2.0

---

## Incident Summary
| Field | Detail |
|-------|--------|
| Attack Type | ${data.attack_type} |
| Log Source | ${data.log_type} |
| Severity | ${data.severity}/10 (${data.severity_label}) |
| Verdict | ${data.verdict} |
| False Positive Risk | ${data.false_positive_likelihood} |
| Attacker IP | ${data.attacker_ip || "Not identified"} |
| Target | ${data.target} |

---

## Log Analyzed
${rawLog}

---

## What Happened
${data.explanation}

---

## Risk Factors
${data.risk_factors.map(r => `- ${r.factor} (+${r.score})`).join("\n")}

---

## Indicators of Compromise
${data.iocs.map(i => `- ${i}`).join("\n")}

---

## MITRE ATT&CK Techniques
${data.mitre_techniques.map(t => `- ${t.id} — ${t.name}: ${t.description}`).join("\n")}

---

## Remediation Playbook

### Step 1 — Contain
${data.remediation.contain.map(s => `- ${s}`).join("\n")}

### Step 2 — Investigate
${data.remediation.investigate.map(s => `- ${s}`).join("\n")}

### Step 3 — Remediate
${data.remediation.remediate.map(s => `- ${s}`).join("\n")}

---

## Prevention

**Root Cause:** ${data.prevention.root_cause}

### Configuration Fixes
${data.prevention.config_fixes.map(s => `- ${s}`).join("\n")}

### Tools to Deploy
${data.prevention.tools_to_deploy.map(s => `- ${s}`).join("\n")}

### Policy Changes
${data.prevention.policy_changes.map(s => `- ${s}`).join("\n")}

### Detection Rules to Create
${data.prevention.detection_rules.map(s => `- ${s}`).join("\n")}
`;
    const blob = new Blob([report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-report-${Date.now()}.md`;
    a.click();
  };

  const displayAnalysis = activeHistory ? activeHistory.full : analysis;
  const displayLog = activeHistory ? activeHistory.log : log;

  return (
    <div className="app">
      <header className="header">
        <div className="header-brand">
          <span className="logo">⚡ SOC-GPT</span>
          <span className="logo-sub">Intelligent Threat Detection Platform</span>
        </div>
        <div className="header-meta">
          <span className="live-badge">● Live</span>
          {history.length > 0 && (
            <span className="count-badge">{history.length} analysed</span>
          )}
        </div>
      </header>

      <div className="pipeline">
        {["Paste log", "Auto detect", "AI analyse", "Risk breakdown", "Prevention", "Export"].map((s, i) => (
          <div key={i} className="pipeline-step">
            <div className="step-num">{i + 1}</div>
            <div className="step-label">{s}</div>
          </div>
        ))}
      </div>

      <div className="layout">
        <div className="left-panel">
          <div className="input-card">
            <div className="card-title">Paste security log</div>
            <div className="log-type-row">
              {Object.keys(LOG_TYPE_COLORS).map(type => (
                <button
                  key={type}
                  className={`type-btn ${detectedType === type ? "active" : ""}`}
                  style={detectedType === type ? {
                    borderColor: LOG_TYPE_COLORS[type],
                    color: LOG_TYPE_COLORS[type]
                  } : {}}
                  onClick={() => setLog(LOG_EXAMPLES[type] || "")}
                >
                  {type}
                </button>
              ))}
            </div>
            {detectedType && (
              <div className="detected-badge" style={{ color: LOG_TYPE_COLORS[detectedType] }}>
                ● Auto detected: {detectedType}
              </div>
            )}
            <textarea
              className="log-textarea"
              value={log}
              onChange={e => setLog(e.target.value)}
              placeholder="Paste any security log here"
              rows={10}
            />
            <button
              className="analyze-btn"
              onClick={analyzeLog}
              disabled={loading || !log.trim()}
            >
              {loading ? (
                <span className="loading-text">
                  <span className="spinner" />
                  Analysing...
                </span>
              ) : "Analyse →"}
            </button>
          </div>

          {history.length > 0 && (
            <div className="history-card">
              <div className="card-title">Analysis history</div>
              {history.map(h => (
                <div
                  key={h.id}
                  className={`history-item ${activeHistory?.id === h.id ? "active" : ""}`}
                  onClick={() => {
                    setActiveHistory(activeHistory?.id === h.id ? null : h);
                    setActiveTab("analysis");
                  }}
                >
                  <div className="history-attack">{h.attack_type}</div>
                  <div className="history-meta">
                    <span style={{ color: SEVERITY_COLORS[h.severity_label]?.color }}>
                      {h.severity}/10 {h.severity_label}
                    </span>
                    <span style={{ color: VERDICT_COLORS[h.verdict] }}>
                      {h.verdict.replace(/_/g, " ")}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="right-panel">
          {error && <div className="error-card">{error}</div>}

          {(analysis || activeHistory) && displayAnalysis && (
            <div className="results">
              <div className="results-header">
                <div className="tabs">
                  {["analysis", "remediation", "prevention"].map(tab => (
                    <button
                      key={tab}
                      className={`tab ${activeTab === tab ? "active" : ""}`}
                      onClick={() => setActiveTab(tab)}
                    >
                      {tab.charAt(0).toUpperCase() + tab.slice(1)}
                    </button>
                  ))}
                </div>
                <button
                  className="export-btn"
                  onClick={() => generateReport(displayAnalysis, displayLog)}
                >
                  Export ↓
                </button>
              </div>

              {activeTab === "analysis" && (
                <>
                  <div className="metrics-row">
                    <div className="metric-card">
                      <div className="metric-label">Verdict</div>
                      <div className="metric-value" style={{ color: VERDICT_COLORS[displayAnalysis.verdict], fontSize: "14px" }}>
                        {displayAnalysis.verdict.replace(/_/g, " ")}
                      </div>
                      <div className="metric-sub">FP risk: {displayAnalysis.false_positive_likelihood}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Severity</div>
                      <div className="metric-value" style={{ color: SEVERITY_COLORS[displayAnalysis.severity_label]?.color }}>
                        {displayAnalysis.severity}<span style={{ fontSize: "16px", color: "#444" }}>/10</span>
                      </div>
                      <div className="metric-sub" style={{ color: SEVERITY_COLORS[displayAnalysis.severity_label]?.color }}>
                        {displayAnalysis.severity_label}
                      </div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Log source</div>
                      <div className="metric-value" style={{ color: LOG_TYPE_COLORS[displayAnalysis.log_type], fontSize: "14px" }}>
                        {displayAnalysis.log_type}
                      </div>
                      <div className="metric-sub">{displayAnalysis.attack_type}</div>
                    </div>
                  </div>

                  <div className="detail-card">
                    <div className="card-title">What happened</div>
                    <p className="explanation">{displayAnalysis.explanation}</p>
                    {displayAnalysis.attacker_ip && (
                      <div className="attacker-ip">
                        Attacker IP: <strong>{displayAnalysis.attacker_ip}</strong>
                      </div>
                    )}
                  </div>

                  <div className="detail-card">
                    <div className="card-title">Risk breakdown</div>
                    {displayAnalysis.risk_factors.map((r, i) => (
                      <div key={i} className="risk-row">
                        <div className="risk-bar-wrap">
                          <div
                            className="risk-bar"
                            style={{ width: `${(r.score / 4) * 100}%`, background: SEVERITY_COLORS[displayAnalysis.severity_label]?.color }}
                          />
                        </div>
                        <div className="risk-text">
                          <span>{r.factor}</span>
                          <span className="risk-score">+{r.score}</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="detail-card">
                    <div className="card-title">MITRE ATT&CK mapping</div>
                    <div className="mitre-grid">
                      {displayAnalysis.mitre_techniques.map(t => (
                        <div key={t.id} className="mitre-item">
                          <div className="mitre-id">{t.id}</div>
                          <div className="mitre-name">{t.name}</div>
                          <div className="mitre-desc">{t.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {displayAnalysis.iocs.length > 0 && (
                    <div className="detail-card">
                      <div className="card-title">Indicators of compromise</div>
                      <div className="ioc-list">
                        {displayAnalysis.iocs.map((ioc, i) => (
                          <span key={i} className="ioc-tag">{ioc}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}

              {activeTab === "remediation" && (
                <div className="playbook">
                  {[
                    { key: "contain", label: "Step 1 — Contain", color: "#E24B4A", bg: "#1f0a0a" },
                    { key: "investigate", label: "Step 2 — Investigate", color: "#BA7517", bg: "#1f150a" },
                    { key: "remediate", label: "Step 3 — Remediate", color: "#1D9E75", bg: "#0a1f17" }
                  ].map(step => (
                    <div key={step.key} className="playbook-step" style={{ borderColor: step.color, background: step.bg }}>
                      <div className="step-title" style={{ color: step.color }}>{step.label}</div>
                      <ul>
                        {displayAnalysis.remediation[step.key].map((s, i) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "prevention" && (
                <div className="prevention">
                  <div className="detail-card root-cause">
                    <div className="card-title">Root cause</div>
                    <p className="explanation">{displayAnalysis.prevention.root_cause}</p>
                  </div>
                  {[
                    { key: "config_fixes", label: "Configuration fixes", icon: "⚙️" },
                    { key: "tools_to_deploy", label: "Tools to deploy", icon: "🛡️" },
                    { key: "policy_changes", label: "Policy changes", icon: "📋" },
                    { key: "detection_rules", label: "Detection rules to create", icon: "🔍" }
                  ].map(section => (
                    <div key={section.key} className="detail-card">
                      <div className="card-title">{section.icon} {section.label}</div>
                      <ul className="prevention-list">
                        {displayAnalysis.prevention[section.key].map((s, i) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {!analysis && !activeHistory && !loading && (
            <div className="empty-state">
              <div className="empty-icon">⚡</div>
              <div className="empty-title">Ready to analyse</div>
              <div className="empty-sub">Paste any security log on the left or click a log type to load an example</div>
              <div className="empty-features">
                <div className="empty-feature">Auto detects log type</div>
                <div className="empty-feature">MITRE ATT&CK mapping</div>
                <div className="empty-feature">Risk score breakdown</div>
                <div className="empty-feature">Prevention playbook</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}