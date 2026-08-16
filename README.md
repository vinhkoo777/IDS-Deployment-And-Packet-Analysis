# IDS Deployment And Packet Analysis
> Made by K0g4 with love <333

Triển khai **Suricata IDS** trên môi trường lab thực chiến để giám sát network traffic, phát hiện tấn công và map theo **MITRE ATT&CK** framework.

## Mục lục
- [Giới thiệu](#giới-thiệu)
- [Kiến trúc hạ tầng](#kiến-trúc-hạ-tầng)
- [Cài đặt](#cài-đặt)
- [Custom Rules](#custom-rules)
- [Documentation](#documentation)

## Kiến trúc hạ tầng

<img width="1129" height="713" alt="image" src="https://github.com/user-attachments/assets/f19ddfe4-e78e-451f-8fc9-69cd0ee2425f" />

## Cài đặt

Xem hướng dẫn cài đặt chi tiết tại [`docs/lab-setup.md`](./docs/lab-setup.md).

## Custom Rules

### Web Application Detection

Rule dạng **signature/pattern-based**, match trực tiếp payload trong HTTP request (`http.uri`, `http.request_body`, `http.user_agent`) nhắm vào OWASP JuiceShop (port 3000).

| Rule File | Attack Type |
|---|---|
| [`sql-detect.rules`](./rules/sql-detect.rules) | SQL Injection |
| [`XSS-detect.rules`](./rules/XSS-detect.rules) | Cross-Site Scripting |
| [`Command-Injection-detect.rules`](./rules/Command-Injection-detect.rules) | OS Command Injection |
| [`PathTraversal-And-LFI.rules`](./rules/PathTraversal-And-LFI.rules) | Path Traversal / LFI |
| [`SSRF-detect.rules`](./rules/SSRF-detect.rules) | Server-Side Request Forgery |
| [`SSTI-detect.rules`](./rules/SSTI-detect.rules) | Server-Side Template Injection |
| [`XXE-detect.rules`](./rules/XXE-detect.rules) | XML External Entity |
| [`File-Upload-detect.rules`](./rules/File-Upload-detect.rules) | Malicious File Upload |
| [`Malicious-User-Agent-Detect.rules`](./rules/Malicious-User-Agent-Detect.rules) | Recon tool fingerprinting (sqlmap, nikto...) |

### Network & Behavioral Detection

Rule dạng **threshold-based**, dựa trên tần suất/hành vi thay vì match nội dung đây là nhóm áp dụng **rule tuning** (điều chỉnh `count`/`seconds`) để cân bằng false positive/negative.

| Rule File | Attack Type |
|---|---|
| [`dos-detect-tuned.rules`](./rules/dos-detect-tuned.rules) | DoS / SYN Flood |
| [`HTTP-Brute-Force-Detect.rules`](./rules/HTTP-Brute-Force-Detect.rules) | HTTP Brute-Force Login |
| [`Nmap-Scan-Detect.rules`](./rules/Nmap-Scan-Detect.rules) | Port Scan (Nmap SYN) |
| [`ping-example.rules`](./rules/ping-example.rules) | ICMP Sweep |

## Documentation

| File | Nội dung |
|------|----------|
| [`docs/lab-setup.md`](./docs/lab-setup.md) | Kiến trúc mạng & hướng dẫn dựng lab |
| [`docs/attack-analysis.md`](./docs/attack-analysis.md) | Phân tích chi tiết từng attack scenario + rule tuning |
| [`config/suricata.yaml`](./config/suricata.yaml) | File cấu hình Suricata đã được tùy chỉnh |
