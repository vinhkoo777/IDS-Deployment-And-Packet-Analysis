# Attack Analysis

## 1. SQL Injection

### Chuẩn bị 

Ở đây tôi đã chuẩn bị sẳn một rule phát hiện SQL injection với tên là `sql-detect.rules`. 

```bash
alert http any any -> $HOME_NET 3000 (msg: "SQLi Attempt - Contains singlequote"; flow:established,to_server; content:"'"; nocase; http_uri; sid:10;)
alert http any any -> $HOME_NET 3000 (msg: "SQLi Attempt - Contains singlequote POST data"; flow:established,to_server; content:"'"; nocase; http_client_body; sid:11;)

alert http any any -> $HOME_NET 3000 (msg: "SQLi Attempt - Contains UNION"; flow:established,to_server; content:"UNION"; nocase; http_uri; sid:12;)
alert http any any -> $HOME_NET 3000 (msg: "SQLi Attempt - Contains UNION POST data"; flow:established,to_server; content:"UNION"; nocase; http_client_body; sid:13;)

alert http any any -> $HOME_NET 3000 (msg: "SQLi Attempt - Contains comment (--)"; flow:established,to_server; content:"--"; nocase; http_uri; sid:16;)
alert http any any -> $HOME_NET 3000 (msg: "SQLi Attempt - Contains comment POST data"; flow:established,to_server; content:"--"; nocase; http_client_body; sid:17;)
```

Ta thêm rule này vào và thực hiện như bước set up lab.

### Mô tả
Attacker inject SQL payload vào HTTP request nhắm vào OWASP JuiceShop chạy trên port 3000, nhằm bypass authentication hoặc extract dữ liệu.

### Thực hiện

Trước khi bắt đầu tấn công, trên máy Suricata ta chạy `tcpdump` để capture traffic song song với Suricata đang monitor.

```bash
sudo tcpdump -w dos.pcap -i ens33
```

**Trên Kali Linux:**

Đầu tiên trên kali tôi sẽ sử dụng burp suite. Thì trong lab này thì juice shop bị SQLi trong trang đăng nhập. Lí do tôi biết là khi nhập dấu `'` thì nó xuất hiện lỗi.

<img width="1607" height="886" alt="image" src="https://github.com/user-attachments/assets/43434aa7-a178-4916-b056-a9059c8cd02a" />

Kiểm tra trong burp suite thì ta thấy gói tin liên quan đến cái trang đăng nhập hồi nãy. 

<img width="634" height="602" alt="image" src="https://github.com/user-attachments/assets/5873bb27-28bb-4c03-9da0-6177341d72e5" />

Khi này tôi nhập payload `' OR true --` khiến câu query SQL luôn trả về true, từ đó bypass authentication và đăng nhập được với quyền admin. Thì có thể ví dụ Query gốc có dạng WHERE email='...' AND password='...', sau khi inject thành WHERE email='' OR true -- thì phần password bị comment out và điều kiện luôn đúng.

<img width="1599" height="896" alt="image" src="https://github.com/user-attachments/assets/66b73d60-0870-4c1e-8f41-3643a675b9d6" />

### Suricata Alert

Đây là alert được suricata tạo ra.

<img width="1846" height="143" alt="image" src="https://github.com/user-attachments/assets/06d8fc1b-4446-4317-9bb6-329e1506f96b" />

### Wireshark Analysis

Ta dừng tcpdump lại. Và thu được file pcap. 

<img width="988" height="792" alt="image" src="https://github.com/user-attachments/assets/3343bdd8-ee94-431c-a603-3e81522ce453" />

Ví dụ như trong hình thì kẻ tấn công đang cố thử dùng dấu nháy đơn `'` liệu có xuất hiện lỗi hay gì không. Thì attacker đã thành công trong việc đó. Tiếp đó kẻ tấn công thử nhập `' OR true --` và nhưu hình dưới thì attacker đã thành công trong việc vào tài khoản admin.

<img width="953" height="653" alt="image" src="https://github.com/user-attachments/assets/b89af45b-d0dd-4abe-8cfe-ac9125ed4d22" />

### MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |

---

## 2. DoS - SYN Flood

### Chuẩn bị 

Ở đây tôi đã chuẩn bị sẳn một rule phát hiện tấn công DoS với tên là `dos-detect.rules`.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"[!] DOS flood inbound, Potential DOS"; flow:to_server; flags: S,12; threshold: type both, track by_dst, count 5000, seconds 5; classtype:attempted-dos; sid:5; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"[!] DOS flood outbound, Potential DOS"; flow:to_server; flags: S,12; threshold: type both, track by_dst, count 5000, seconds 5; classtype:attempted-dos; sid:6; rev:1;)
```

Ta thêm rule này vào và thực hiện như bước set up lab.

### Mô tả
Attacker gửi lượng lớn SYN packet đến target nhằm làm cạn kiệt tài nguyên và gây **Denial of Service**.

### Thực hiện

Trước khi bắt đầu tấn công, trên máy Suricata ta chạy `tcpdump` để capture traffic song song với Suricata đang monitor.

```bash
sudo tcpdump -w dos.pcap -i ens33
```

**Trên Kali Linux:**

Tôi sẽ chuẩn bị 1 đoạn file python tên là dos.py có nội dung như dưới. Đoạn code đó dùng để thực hiện việc DoS. Vào máy metasploitable2 có ip là `192.168.15.131`

```python
import os

target_ip = "192.168.15.131"
os.system("hping3 -c 10000 -d 120 -S -w 64 -p 21 --flood --rand-source "+target_ip)
```

Tiếp đó thục thi dos.py

```
sudo python3 dos.py
```
<img width="636" height="182" alt="image" src="https://github.com/user-attachments/assets/99dfdb9d-d383-443a-954e-2cd419648415" />

### Suricata Alert

<img width="1542" height="140" alt="image" src="https://github.com/user-attachments/assets/86c99a0e-73b7-47b6-9661-6665021a2a42" />

### Wireshark Analysis

Khi này ta dừng tcpdump và thu được một file pcap. 

<img width="1538" height="781" alt="image" src="https://github.com/user-attachments/assets/daf08efb-eba2-4f27-93cb-28b1ce603351" />

Như trong hình, source IP liên tục thay đổi do attacker sử dụng tùy chọn `--rand-source`, nhằm gây khó khăn cho việc truy vết và chặn theo IP nguồn. Đồng thời, một lượng lớn **TCP SYN packets** kèm payload `XXXXXXXX...` được gửi liên tục đến target trong khoảng thời gian rất ngắn. Hành vi này có thể khiến máy target tiêu tốn tài nguyên để xử lý các kết nối giả mạo, từ đó dẫn đến tình trạng **Denial of Service**. 

### MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Impact | Network Denial of Service | T1498 |

---

# Rule Tuning

## Rule Tuning - SQLi Detection

### Vấn đề rule gốc

- Match đơn lẻ `'` hoặc `--` nên **false positive** cao (xuất hiện trong dữ liệu hợp lệ hoặc URL bình thường).
- Chưa phân loại được từng kỹ thuật SQL Injection.
- Sử dụng `http_client_body` và `http_uri`, không còn phù hợp với cú pháp **Suricata 8**.

### Hướng tuning

Sử dụng sticky buffer mới của Suricata 8 (`http.request_body`, `http.uri`) kết hợp với biểu thức PCRE để yêu cầu quote + keyword/comment thay vì chỉ match ký tự đơn lẻ, đồng thời tách rule theo từng kỹ thuật SQLi giúp việc điều tra và phân loại cảnh báo rõ ràng hơn.

| SID | Pattern | Buffer | Kỹ thuật |
|-----|---------|--------|----------|
| 20 | `'`/`"` + OR/UNION/SELECT | Request Body | Auth Bypass, UNION-based |
| 21 | `'`/`"` + `--`/`#`/`/*` | Request Body | Comment Injection |
| 22 | `'`/`"` + `--`/`#`/`/*` | URI | Comment Injection (GET) |
| 23 | `information_schema.tables` + comment | Request Body | Schema Enumeration |
| 24 | `information_schema.tables` + comment | URI | Schema Enumeration (GET) |
| 25 | `'`/`"` + CASE/IF | Request Body | Boolean-based Blind |
| 26 | `'`/`"` + SLEEP/BENCHMARK | Request Body | Time-based Blind |
| 27 | `'`/`"` + EXTRACTVALUE/UPDATEXML | Request Body | Error-based |
| 28 | `'`/`"` + LOAD_FILE/INTO OUTFILE | Request Body | File Read/Write |
| 29 | CONCAT()/DATABASE()/VERSION()/USER() | Request Body | DB Fingerprinting |

## Vì sao giảm false positive

- Chỉ sinh cảnh báo khi **quote xuất hiện cùng keyword SQL**, giảm các trường hợp chứa dấu `'` hợp lệ (ví dụ: `Vinh'Tam`).
- Sử dụng `http.request_body` và `http.uri`*giúp giới hạn phạm vi kiểm tra đúng vào Request Body hoặc URI, giảm việc phân tích các phần không liên quan của gói HTTP.
- Tách riêng từng kỹ thuật SQL Injection giúp xác định loại tấn công nhanh hơn và thuận tiện cho việc điều tra.
- SID 29 phát hiện các hàm SQL đặc trưng (`CONCAT`, `DATABASE`, `VERSION`, `USER`) nên không cần yêu cầu dấu quote mà vẫn có tỷ lệ false positive thấp.

## Full Rules

```suricata
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - quote with OR/UNION"; flow:established,to_server; http.request_body; pcre:"/['\"]\s*(OR|UNION|SELECT)\b/i"; sid:20; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - SQL Comment Injection"; flow:established,to_server; http.request_body; pcre:"/['\"]\s*(--|#|\/\*)/i"; sid:21; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - SQL Comment Injection (URI)"; flow:established,to_server; http.uri; pcre:"/['\"]\s*(--|#|\/\*)/i"; sid:22; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - Retrieve Database contents"; flow:established,to_server; http.request_body; pcre:"/information_schema\.tables.*(--|#|\/\*)/i"; sid:23; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - Retrieve Database contents (URI)"; flow:established,to_server; http.uri; pcre:"/information_schema\.tables.*(--|#|\/\*)/i"; sid:24; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - CASE/IF Expression"; flow:established,to_server; http.request_body; pcre:"/['\"]\s*(CASE|IF)\b/i"; sid:25; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - Time-based"; flow:established,to_server; http.request_body; pcre:"/['\"]\s*(SLEEP|BENCHMARK)\b/i"; sid:26; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - Error-based"; flow:established,to_server; http.request_body; pcre:"/['\"]\s*(EXTRACTVALUE|UPDATEXML)\b/i"; sid:27; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - File access"; flow:established,to_server; http.request_body; pcre:"/['\"]\s*(LOAD_FILE|INTO\s+OUTFILE)\b/i"; sid:28; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"SQLi Attempt - Dangerous SQL Functions"; flow:established,to_server; http.request_body; pcre:"/(CONCAT|DATABASE|VERSION|USER)\s*\(/i"; sid:29; rev:1;)
```

=> Dưới đây là kết quả rule đã test 

<img width="1383" height="224" alt="image" src="https://github.com/user-attachments/assets/4e598a73-b1a9-4037-bffc-e587baf05ca8" />


<img width="1337" height="718" alt="image" src="https://github.com/user-attachments/assets/d6cbe0ac-8031-4ad0-aace-9def6e0a337d" />

## Rule Tuning - DoS Detection

### Vấn đề rule gốc

- Threshold cố định **5000 packet/5s (~1000 pps)** nên chỉ phát hiện được SYN Flood tốc độ cao.
- Dễ bỏ sót **low-rate SYN Flood**.
- Chưa phân biệt rõ cảnh báo **inbound** và **outbound**.

### Hướng tuning

Giảm threshold để tăng độ nhạy, đồng thời giữ `track by_dst` và `threshold type both` nhằm hạn chế alert trùng lặp.

| SID | Threshold | Hướng | Kỹ thuật |
|-----|-----------|-------|----------|
| 5 | 1000 packet/5s| Inbound (EXTERNAL → HOME) |SYN Flood|
| 6 | 1000 packet/5s| Outbound (HOME → EXTERNAL)| SYN Flood |

### Vì sao giảm false negative

- Giảm threshold từ **5000** xuống **1000 packet/5s** giúp phát hiện **low-rate SYN Flood**.
- `track by_dst` và `threshold type both` chỉ tạo **1 alert/đích/5 giây**, hạn chế spam alert.
- Vẫn sử dụng `flags:S,12` để chỉ phát hiện các gói SYN có đặc trưng của SYN Flood.

## Full Rules

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"[!] DOS flood inbound, Potential DOS"; flow:to_server; flags:S,12; threshold:type both, track by_dst, count 1000, seconds 5; classtype:attempted-dos; sid:5; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"[!] DOS flood outbound, Potential DOS"; flow:to_server; flags:S,12; threshold:type both, track by_dst, count 1000, seconds 5; classtype:attempted-dos; sid:6; rev:2;)
```

=> Dưới đây là kết quả 

<img width="1398" height="376" alt="image" src="https://github.com/user-attachments/assets/60380dc4-11b0-444f-84ad-d059afa1d0ff" />


