# Lab Set Up

## Phase 1: Lab Environment

### Sơ đồ mạng (diagram)

Sơ đồ dưới đây mô tả topology mạng được sử dụng trong lab. Kali Linux đóng vai trò máy tấn công, trong khi Suricata IDS giám sát toàn bộ traffic trên network segment chứa OWASP JuiceShop và Metasploitable2.

> **Note:** Sơ đồ mang tính minh họa. Trong thực tế, attacker machine sẽ được phân tách bởi firewall/router.

<img width="1137" height="715" alt="image" src="https://github.com/user-attachments/assets/b2a963a4-58bd-4649-97a1-145f2fb6d87d" />

### Các máy sử dụng trong lab

| Machine         | OS             | Role        | IP Address      |
|-----------------|----------------|-------------|-----------------|
| Metasploitable2 | Ubuntu 8.04    | Target      | 192.168.15.131   |
| Kali Linux      | Kali Linux     | Attacker    | 192.168.15.130   |
| Suricata        | Ubuntu 24.04.4 | IDS Monitor | 192.168.15.129   |
| JuiceShop       | Ubuntu Server  | Target (Web)| 192.168.15.128   |


> **Note:** Tất cả các máy đã được chuẩn bị sẵn. Phase 2 chỉ tập trung vào việc triển khai Suricata IDS.

## Phase 2: Set Up Suricata 

### Bước 1: Chuẩn bị máy ảo

Đầu tiên cần phải chuẩn bị trước một máy ảo. Ở đây tôi đã chuẩn bị trước máy ảo Ubuntu 24.04.4 LTS.

<img width="1608" height="942" alt="image" src="https://github.com/user-attachments/assets/6a8fcd43-90b5-4241-a9d6-2291ccaaa5da" />

### Bước 2: Cài đặt suricata

Đầu tiên thực hiện các lệnh dưới đây để setup trước khi cài đặt suricata.

```bash 
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
```

Tiếp theo đó là cài đặt suricata thông qua lệnh.

```bash 
sudo apt-get install suricata
```

### Bước 3: Cấu hình suricata 

Đầu tiên ta sẽ chỉnh 1 vài thứ trong file config của suricata. Ta thực hiện lệnh. 

```bash
sudo nano /etc/suricata/suricata.yaml   
```
Tại phần **address-groups** ở mục **HOME_NET:** Tôi sẽ để dãi ip là `192.168.15.0/24` thì đây sẽ là dãy ip mà tôi sẽ muốn suricata quan sát các traffic đến và đi. 

<img width="1423" height="282" alt="image" src="https://github.com/user-attachments/assets/704c5368-a524-41e4-bed9-94b4da860108" />

Tiếp theo là phần quan trọng nhất là **af-packet** thì mục đích của phần này là chúng ta sẽ chỉnh interface mà chúng ta quan sát traffic đến và đi.

<img width="1017" height="510" alt="image" src="https://github.com/user-attachments/assets/9a1690e0-004e-4df5-b139-c815d6accaf3" />

#### Trên máy suricata

Sử dụng lệnh `ip a`.Và như ta thấy interface hiện tại là ens33. Nên sẽ cần đổi eth0 thành ens33

<img width="1176" height="316" alt="image" src="https://github.com/user-attachments/assets/05444db1-f54a-4f68-90aa-a35c1020b04a" />

---

<img width="1285" height="120" alt="image" src="https://github.com/user-attachments/assets/785497ca-e0bb-452d-a88d-0d6e92338122" />

Nên `cluster-id` thành `10` để tránh conflict với các instance khác nếu có nhiều Suricata process chạy trên cùng một máy.

<img width="1172" height="390" alt="image" src="https://github.com/user-attachments/assets/859ee16a-1578-455e-899e-bc0494ce752f" />

Tiếp đó ấn tổ hợp `ctrl + s` để lưu lại và `ctrl + x` để thoát ra.

## Bước 4: Thêm rule vào suricata.

Tại đây tôi chuẩn bị sẳn rule về ping.

**ping-example.rules**
```bash
alert icmp any any -> $HOME_NET any (msg:"PING command"; sid:1; rev:1;)
```
**Trong đó**

- **alert:** Dùng để tạo cảnh báo khi điều kiện trong rule thỏa mãn
- **icmp:** protocol mà rule sẽ tập trung nào
- `$HOME_NET` là dãy IP mà ta đã set trong file config của suricata
- **msg:** Chứa nội dung sẽ hiện trong alert

Thì rule này có nghĩa là khi có 1 máy thực hiện việc ping đến máy khác thì alert này sẽ được tạo ra.

File chứa các rule của suricata thường được đặt mặc định ở `/var/lib/suricata/rules`. Ta có thể kiểm tra bằng cách sử dụng.

```bash
sudo ls -la /var/lib/suricata/rules
```

<img width="745" height="147" alt="image" src="https://github.com/user-attachments/assets/aa4c7ce9-6d32-4a6e-8345-08896bc68fd1" />

Ta tiến hành tạo rule bằng cách sử dụng lệnh `nano`. Tôi sẽ ví dụ trước lệnh `ping-example.rules`. 

```bash
sudo nano /var/lib/suricata/rules/ping-example.rules
```

Tiếp đó ta thêm nội dung vào và ấn tổ hợp `ctrl + s` để lưu lại và `ctrl + x` để thoát ra. 

<img width="752" height="201" alt="image" src="https://github.com/user-attachments/assets/e85f6284-1bcb-4c9a-b509-0c407bd5a5f8" />

Quay lại file `suricata.yaml`, tìm đến phần **rule-files** và thêm vào tên các rule files muốn load.

```bash
sudo nano /etc/suricata/suricata.yaml  
```

<img width="772" height="267" alt="image" src="https://github.com/user-attachments/assets/85ae5be2-a326-48b3-9b65-240fc8a45ad8" />

Tiếp ta tiến hành lưu lại config và thực hiện lệnh dưới đây để update config.

```bash
sudo suricata-update
```

Và sau đó thực hiện lệnh dưới để restart lại service suricata.
```
sudo systemctl restart suricata
```

Khi khởi động lại dịch vụ xong ta có thể sử dụng lệnh `sudo systemctl status suricata` để xem service đã khưởi động thành công hay chưa.

Xong rồi ta thực hiện lệnh dưới để kiểm tra rule đã được parse thành công hay chưa. Thì flag `-T` có nghĩa là Test mode. Nếu có lỗi thì nó sẽ báo lỗi.

```
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Nếu không có lỗi gì thì ta thực hiện tiếp lệnh dưới. 

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i ens33 -v
```

## Phase 3: Test Rules

### ICMP Detection (ping-example.rules)

Để kiểm tra rule phát hiện ICMP, trên máy Kali Linux thực hiện lệnh ping đến máy Suricata.

```bash
ping 192.168.15.128
```

Sau đó kiểm tra alert log trên máy Suricata bằng lệnh.

```bash
sudo tail -f /var/log/suricata/fast.log
```

Nếu rule hoạt động đúng, ta sẽ thấy alert xuất hiện trong log với nội dung `PING command`. Thì Kali ping đến JuiceShop (192.168.15.128) và Suricata monitor traffic trên cùng network segment nên vẫn bắt được gói ICMP này và tạo alert.

<img width="1433" height="99" alt="image" src="https://github.com/user-attachments/assets/a39bb547-aa72-44b2-98ab-49264858f817" />

---
## TÀI LIỆU THAM KHẢO
Documentation của suricata: [Link](https://suricata.io/documentation/) 

