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
| [`PathTraversal.rules`](./rules/PathTraversal.rules) | Path Traversal |
| [`SSRF-detect.rules`](./rules/SSRF-detect.rules) | Server-Side Request Forgery |
| [`SSTI-detect.rules`](./rules/SSTI-detect.rules) | Server-Side Template Injection |
| [`XXE-detect.rules`](./rules/XXE-detect.rules) | XML External Entity |
| [`Malicious-User-Agent-Detect.rules`](./rules/Malicious-User-Agent-Detect.rules) | Recon tool fingerprinting (sqlmap, nikto...) |

- Validated: SQL Injection, SSRF, SSTI, XXE, Malicious User-Agent
- Rule development only: Chỉ phát triển rule: XSS, Path Traversal, OS Command Injection
> Note: 3 rule trên chưa được xác thực end-to-end do giới hạn attack surface và request handling của Juice Shop. Các rule vẫn được giữ lại dưới dạng detection development.

### Network & Behavioral Detection

Rule dạng **threshold-based**, dựa trên tần suất/hành vi thay vì match trực tiếp nội dung payload.

| Rule File | Attack Type |
|---|---|
| [`dos-detect-tuned.rules`](./rules/dos-detect-tuned.rules) | DoS / SYN Flood |
| [`HTTP-Brute-Force-Detect.rules`](./rules/HTTP-Brute-Force-Detect.rules) | HTTP Brute-Force Login |
| [`Nmap-Scan-Detect.rules`](./rules/Nmap-Scan-Detect.rules) | Port Scan (Nmap SYN) |

## Documentation

| File | Nội dung |
|------|----------|
| [`docs/lab-setup.md`](./docs/lab-setup.md) | Kiến trúc mạng & hướng dẫn dựng lab |
| [`docs/attack-analysis.md`](./docs/attack-analysis.md) | Phân tích chi tiết từng attack scenario + rule tuning |
