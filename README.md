# IDS Deployment And Packet Analysis
> Made by K0g4 with love <333

Triển khai **Suricata IDS** trên môi trường lab thực chiến để giám sát network traffic, phát hiện tấn công và map theo **MITRE ATT&CK** framework.

## Mục lục
- [Giới thiệu](#giới-thiệu)
- [Kiến trúc hạ tầng](#kiến-trúc-hạ-tầng)
- [Cài đặt](#cài-đặt)
- [Custom Rules](#custom-rules)
- [Documentation](#documentation)

## Giới thiệu

**IDS Deployment And Packet Analysis** là dự án triển khai hệ thống phát hiện xâm nhập (Intrusion Detection System) sử dụng **Suricata** trong môi trường lab có kiểm soát.

Dự án tập trung vào:
- **Deploy và cấu hình Suricata IDS** trên Ubuntu 24.04 để giám sát network traffic trong thời gian thực
- **Viết custom detection rules** cho các kịch bản tấn công: SQL Injection, DoS, ICMP scan
- **Sinh attack traffic** từ Kali Linux, capture và phân tích PCAP bằng Wireshark
- **Tune rules** để giảm false positives trong khi vẫn đảm bảo detection coverage
- **Map toàn bộ attack scenarios** sang MITRE ATT&CK TTPs

## Kiến trúc hạ tầng

<img width="1129" height="713" alt="image" src="https://github.com/user-attachments/assets/f19ddfe4-e78e-451f-8fc9-69cd0ee2425f" />

## Cài đặt

Xem hướng dẫn cài đặt chi tiết tại [`docs/lab-setup.md`](./docs/lab-setup.md).

## Documentation

| File | Nội dung |
|------|----------|
| [`docs/lab-setup.md`](./docs/lab-setup.md) | Kiến trúc mạng & hướng dẫn dựng lab |
| [`docs/attack-analysis.md`](./docs/attack-analysis.md) | Phân tích chi tiết từng attack scenario |
| [`config/suricata.yaml`](./config/suricata.yaml) | File cấu hình Suricata đã được tùy chỉnh |
