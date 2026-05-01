# SecAudit offline signatures

Thu muc nay mo ta cach cap nhat 2 lop phat hien offline:

1. YARA rule pack noi bo.
2. Local hash feed co chu ky.

SecAudit khong goi Internet va khong upload mau. Moi rule/hash feed duoc doc tu may cuc bo hoac USB WinPE.

## 1. YARA rule pack noi bo

Thu muc duoc SecAudit tu dong doc:

- Windows cai dat binh thuong: `%ProgramData%\SecAudit\signatures\yara\*.yar`
- Ban portable/WinPE: `.\signatures\yara\*.yar` nam canh `SecAudit.exe` hoac `SecAudit.Cli.exe`

Moi rule nen co `meta`:

```yara
meta:
    verdict = "Suspicious"
    family = "Internal-Family-Name"
    confidence = 70
```

Gia tri `verdict` nen dung mot trong cac muc:

- `Malicious`: hash/rule rat dac hieu, co the xu ly nhu doc hai.
- `Suspicious`: can uu tien dieu tra.
- `TestFile`: chi dung cho test rule pack.

SecAudit dang ho tro tap con YARA an toan cho WinPE: string text/hex, `nocase`, `wide ascii`, `any/all/N of them`, va dieu kien `$a and $b` hoac `$a or $b`.

Bo mau:

- `yara/internal-triage.example.yar`: rule mau de viet rule noi bo.
- `yara/internal-verified-starter.yar`: rule starter chat hon cho cac mau da xac minh noi bo; chi copy vao USB sau khi test voi baseline sach.
- `yara/test-samples/suspicious/`: file gia lap de test rule.
- `yara/test-samples/clean/`: file sach de dam bao rule khong qua rong.

Quy trinh lam rule:

1. Lay IOC tu mau da xac minh bang Kaspersky/Defender/VirusTotal hoac phan tich noi bo.
2. Chon chuoi dac hieu it trung voi phan mem hop le: family name, mutex, C2 path, ransom note marker, command marker.
3. Tao rule co toi thieu 2-3 string va dieu kien `2 of them` de giam false positive.
4. Test tren thu muc `test-samples/suspicious` phai hit, `test-samples/clean` khong duoc hit.
5. Copy rule da duyet vao `signatures\yara` tren USB/ProgramData.

## 2. Local hash feed co chu ky

Feed hash la JSON:

```json
{
  "metadata": {
    "schemaVersion": 1,
    "feedId": "soc-feed",
    "version": "2026.05.01.1",
    "publisher": "Internal SOC",
    "generatedAtUtc": "2026-05-01T00:00:00Z",
    "expiresAtUtc": "2026-06-01T00:00:00Z"
  },
  "hashes": [
    {
      "sha256": "0123456789ABCDEF...",
      "md5": "",
      "verdict": "Malicious",
      "family": "Internal-IOC",
      "confidence": 100,
      "source": "LocalSOC"
    }
  ],
  "allowlist": [
    {
      "pathPrefix": "C:\\Program Files\\InternalTool\\",
      "family": "Org-Baseline",
      "confidence": 95,
      "reason": "approved internal administration tool"
    },
    {
      "sha256": "ABCDEF0123456789...",
      "family": "Known-Good-Installer",
      "confidence": 100,
      "reason": "installer verified by internal SOC"
    }
  ]
}
```

Thu muc duoc SecAudit tu dong doc:

- Windows cai dat binh thuong: `%ProgramData%\SecAudit\signatures\local-reputation.json`
- Ban portable/WinPE: `.\signatures\local-reputation.json`

Tu phien ban nay, feed ngoai chi duoc nap neu co:

- `local-reputation.json`
- `local-reputation.json.sig`: chu ky RSA-SHA256 cua dung byte trong file JSON.
- Public key tin cay trong:
  - `%ProgramData%\SecAudit\signatures\trust\*.pem`
  - hoac `.\signatures\trust\*.pem` canh file exe.

Metadata la bat buoc. SecAudit se bo qua feed neu:

- thieu `metadata`;
- thieu `metadata.version`;
- thieu hoac da qua `metadata.expiresAtUtc`;
- chu ky khong khop voi JSON hien tai.

`allowlist` chi nen dung de ha diem noise cua phan mem noi bo hop le. No khong ha diem cac tin hieu doc hai manh nhu hash `Malicious`, EICAR/TestFile, chu ky bi thu hoi/khong tin cay, ransomware command, Defender tamper, hoac encoded PowerShell kem download cradle.

Layout khuyen nghi tren USB WinPE:

```text
SecAudit\
  SecAudit.Cli.exe
  Run-SecAudit-WinPE.cmd
  signatures\
    local-reputation.json
    local-reputation.json.sig
    trust\
      local-feed-2026.public.pem
    yara\
      internal-triage.yar
```

Nguyen tac van hanh:

1. Giu private key tren may SOC noi bo, khong copy len USB quet.
2. Moi khi them hash moi, ky lai `local-reputation.json`.
3. USB/may quet chi can public key va feed da ky.
4. Neu feed bi sua sau khi ky, SecAudit se bo qua feed va ghi warning vao log.

Vi du ky feed bang OpenSSL tren may SOC:

```powershell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out local-feed-2026.private.pem
openssl rsa -in local-feed-2026.private.pem -pubout -out local-feed-2026.public.pem
openssl dgst -sha256 -sign local-feed-2026.private.pem -out local-reputation.json.sig.bin local-reputation.json
openssl base64 -A -in local-reputation.json.sig.bin -out local-reputation.json.sig
```

Kiem tra chu ky truoc khi copy sang USB:

```powershell
openssl base64 -d -in local-reputation.json.sig -out local-reputation.json.sig.bin
openssl dgst -sha256 -verify local-feed-2026.public.pem -signature local-reputation.json.sig.bin local-reputation.json
```

Sau do copy:

```text
local-reputation.json      -> signatures\local-reputation.json
local-reputation.json.sig  -> signatures\local-reputation.json.sig
local-feed-2026.public.pem -> signatures\trust\local-feed-2026.public.pem
```
