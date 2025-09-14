# 🛡️ Simple Python WAF

A lightweight Web Application Firewall (WAF) built with Python and Flask that detects and blocks basic web attacks such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Local File Inclusion
- Session Hijacking

This is a basic educational tool meant to demonstrate how request inspection can be used to defend against common attacks in web applications.

---

## 🚀 Features

- 🔍 Inspects `GET`, `POST`, and `Cookie` data
- 📖 Uses regular expressions to detect known malicious patterns
- ⛔ Blocks suspicious requests with HTTP 403
- 🪵 (Optional) Logging of detected attacks

---

## 📦 Requirements

- Python 3.7+
- Flask

Install dependencies:
```bash
pip install flask


