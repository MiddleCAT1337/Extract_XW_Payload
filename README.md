# extract_xworm_config.py

สคริปต์ Python สำหรับดึงค่าตั้งค่า C2 จาก payload ฝั่ง client ของ XWorm รุ่น V5 ถึง V6 จากไฟล์ที่ builder สร้างไว้ ไม่ต้องรัน malware จริง แค่เปิดไฟล์แล้วอ่าน metadata และ string ที่ฝังอยู่ใน PE

ใช้ได้กับ client ตรงๆ และกรณีที่มี Xbinder ห่อ client ไว้ใน resource ของ stub อีกชั้น รวมถึงไฟล์ batch ที่แอบใส่ exe เป็น base64 หรือ hex

---

## สิ่งที่ได้จากสคริปต

| ค่า | ความหมายคร่าวๆ |
|-----|----------------|
| Host | IP หรือโดเมน server |
| Port | พอร์ต TCP |
| Key | ค่าในรูป `<...>` ใช้กับ traffic (มักเป็นตัวเลข เช่น `<666666>`) |
| Group | ค่าใน `<...>` อื่นๆ ถ้ามี |
| SPL | ตัวคั่น/สตริงพิเศษของ builder ถ้ามี |
| Mutex / mutex_seed | สตริง seed ที่ builder ใช้ทั้งเป็นคีย์ถอดรหัส config และชื่อ mutex |
| kind | ประเภท เช่น client, xbinder, bat |
| drops | รายชื่อ exe ที่ binder จะปล่อย (กรณี xbinder) |
| binder_mutex | mutex ที่ใช้ถอด resource ของ binder |
| embedded_from | ชื่อ resource ที่ถอดได้ client จริง |
| traffic_md5 | MD5 ของ Key ใช้เทียบกับ key ใน traffic (มีในโหมด debug) |

---

## XWorm เก็บ config ยังไง (แบบสั้นๆ)

ตอน build client ฝั่ง .NET จะมีคลาส config ที่เป็น field สตริง static หลายตัว

1. มี seed ตัวหนึ่งเป็นข้อความธรรมดา ความยาวประมาณ 8–20 ตัว ตัวอักษรกับเลข ค่านี้มักใช้เป็นชื่อ mutex ด้วย
2. ค่าอื่นๆ เช่น Host Port Key ถูกเข้ารหัสแล้ว encode เป็น Base64 เก็บใน field
3. วิธีเข้ารหัส: AES โหมด ECB + padding แบบ PKCS7
4. การทำ key จาก seed (ฝั่ง client config):
   - เอา seed ไป hash ด้วย MD5 ได้ 16 byte
   - ขยายเป็น key 32 byte ตามที่ stub ทำ (สคริปต์ใช้ฟังก์ชัน derive_aes_key ให้ตรงกับ RijndaelManaged ใน stub)
5. ถอด Base64 ด้วย key นั้น ได้ plaintext เป็น IP พอร์ต หรือสตริงใน `<...>`

สคริปต์ไม่รู้ชื่อ field ล่วงหน้า เพราะ obfuscate เปลี่ยนชื่อ class ได้ จึงเก็บ string จากหลายแหล่งแล้วลอง seed กับ blob จน plaintext ดูสมเหตุสมผล (มี IP พอร์ต key)

---

## ขั้นตอนการทำงานของสคริปต (ไล่ตามโค้ด)

### 1. เปิดไฟล์

- exe / dll: อ่านเป็น PE แล้วเช็คว่ามี .NET metadata
- bat / cmd: ไปทาง extract_bat_file ก่อน

### 2. เก็บ string (harvest)

ดึงข้อความที่น่าจะเป็น config จาก

- ตาราง Constant ใน metadata (ค่า default ของ field)
- UserStrings heap (#US) ใน .NET
- สแกน raw ในไฟล์ หา Base64 และ seed แบบ ASCII หรือ UTF-16

กรอง noise ของ .NET เช่น System Microsoft ออก

### 3. จับคู่ seed กับ Base64 (brute force แบบจำกัด)

- seed: สตริงสั้น a-z A-Z 0-9 ไม่ใช่ Base64 ที่ดูเหมือน config
- blob: สตริงที่ decode Base64 ได้ ยาวพอ

ลองทุก seed กับทุก blob ถอดด้วย AES แล้วให้คะแนน ถ้าได้ IP พอร์ต และค่า `<...>` ครบแนวๆ ถือว่าผ่าน

### 4. แยกประเภทค่าที่ถอดแล้ว (classify)

- ตัวเลข 1–65535 → Port
- รูป IP หรือ hostname → Host
- ข้อความใน `<...>` → แยก Key Group SPL ตาม heuristic (Key มักเป็นตัวเลขใน bracket)

### 5. กรณี Xbinder (binder)

บางตัวไม่ใช่ client ตรงๆ แต่เป็น stub ที่

- มีสตริงรายการ drop แบบ `something.exe-=>True-=>False`
- หรือมีชื่ออย่าง GetTheResource AES_Decryptor ใน binary
- ฝัง client จริงเป็น byte ใน .resources ของ assembly

ขั้นตอน:

1. ตรวจว่าเป็น xbinder (is_xbinder_stub)
2. อ่าน resource ขนาดใหญ่จาก manifest
3. หา mutex candidate จาก seed ในไฟล์ (binder มักใช้ mutex 16 ตัว)
4. ใช้ MD5(mutex) 16 byte เป็น AES key ถอด resource
5. ถ้า plaintext ขึ้นต้นด้วย MZ แปลว่าเป็น PE เอาไป extract_pe_bytes อีกรอบ (depth 1) เพื่อดึง Host Port Key ของ client จริง

ผลลัพธ์จะมี kind เป็น xbinder และบอก binder_mutex กับ embedded_from

### 6. กรณีไฟล์ batch

ไฟล์ .bat / .cmd อาจมี

- PowerShell -enc / -e ที่เป็น base64
- ก้อน base64 หรือ hex ยาวๆ ของ exe

สคริปต normalize ข้อความ (ตัด caret แบบ batch) แล้ว decode หา PE ที่ขึ้น MZ จากนั้นเรียก extract_pe_bytes เหมือนเปิด exe โดยตรง ถ้าสำเร็จจะมี payload_from บอกว่า PE มาจากชั้นไหนใน bat

---

## โฟลว์ภาพรวม

```text
ไฟล์เข้า (.exe / .dll / .bat)
        |
        v
   [ bat? ] ----yes----> แกะ PE จาก base64/hex/ps --> PE bytes
        | no
        v
   เปิด PE .NET + harvest strings
        |
        v
   ลอง seed + Base64 --> ได้ Host/Port/Key?
        |
       yes --> จบ (kind = client)
        |
       no
        v
   เป็น xbinder? ----yes----> MD5(mutex) ถอด resource --> PE ชั้นใน --> วนขั้นถอด config อีกครั้ง
        |
       no --> แจ้ง error (ไม่ match)
```

---

## ตัวอย่างผลลัพธ์

โหมดปกติ:

```text
=== svchost.exe ===
  Host:  127.0.0.1
  Port:  6000
  Key:   <666666>
  Mutex: 96XK7SHWyJNjE9Pg
```

โหมด debug จะพิมพ์ลง stderr เช่น จำนวน field constant seed candidates รายการ drop ของ binder

---

## ข้อจำกัดที่ควรรู้

- ใช้กับ stub / client ที่โครงสร้างใกล้เคียง XWorm V5–V6 ที่วิเคราะห์มา ถ้า builder เปลี่ยนวิธีเข้ารหัสลึกๆ อาจดึงไม่ได้
- obfuscator หนัก metadata อ่านยาก สคริปต์พึ่ง harvest จาก binary เป็นหลัก บาง build อาจต้องดู log debug ว่า seed หรือ blob ขาดไปไหม
- xbinder ซ้อนเกิน 1 ชั้น depth จำกัดที่ 1 ในโค้ดปัจจุบัน
- ใช้เพื่อการวิเคราะห์ malware ในห้องแล็บหรืองานที่ได้รับอนุญาตเท่านั้น ไม่ใช่เครื่องมือโจมตี

---

## ไฟล์ในโปรเจกต์

- main.py ตัวสคริปต์หลัก
- README.md เอกสารนี้

---

## สรุปหนึ่งย่อหน้า

สคริปต์อ่านไฟล์ XWorm client หรือ dropper ที่เกี่ยวข้อง เก็บ string และค่า metadata จาก PE แล้วใช้ seed กับ AES ถอด Base64 จนได้ IP พอร์ต และ Key ถ้าเป็น binder จะถอด resource ด้วย MD5 ของ mutex แล้วแกะ client ข้างในอีกที ถ้าเป็น batch จะดึง exe ที่ซ่อนอยู่ก่อน ทั้งหมดทำ offline บนไฟล์ที่เราให้ ไม่ต้องรันตัว malware
