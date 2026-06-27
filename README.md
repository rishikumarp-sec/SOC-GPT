# ⚡ SOC-GPT — AI Powered Threat Detection Platform

> Analyse any security log instantly using AI. Get MITRE ATT&CK mapping, severity scoring, remediation playbook and prevention guide in seconds.

🔗 **[Live Demo](https://soc-gpt-pk6u.vercel.app)**

---

## What it does

Paste any security log and SOC-GPT instantly returns:

- **Attack type** identified automatically
- **Severity score** with detailed risk breakdown
- **MITRE ATT&CK techniques** mapped automatically
- **Attacker IP** extracted from raw log
- **Remediation playbook** — contain, investigate, fix
- **Prevention guide** — root cause, config fixes, tools, detection rules
- **Downloadable incident report** in Markdown

---

## Supported log formats

| Log Type | Examples |
|----------|---------|
| Linux SSH | auth.log, sshd, PAM |
| AWS CloudTrail | IAM events, API calls |
| Apache Web | access.log, error.log |
| Windows Event | Security, System logs |
| Nmap Scan | Port scan output |
| Generic | Any log format |

---

## Demo

![SOC-GPT Homepage](screenshots/homepage.png)
![Analysis Results](screenshots/analysis.png)
![MITRE Mapping](screenshots/mitre.png)
![Prevention Tab](screenshots/prevention.png)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React |
| AI Engine | Groq API + Llama 3.3 70B |
| Styling | Custom CSS |
| Deployment | Vercel |

---

## Run locally

```bash
git clone https://github.com/rishikumarp-sec/SOC-GPT.git
cd SOC-GPT
npm install
```

Create a `.env` file:
