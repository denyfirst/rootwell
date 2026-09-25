# DenyFirst Rootwell — məhsul və icra planı

**Status:** ilkin plan, v0.1

**Tarix:** 2026-09-20

**Məhsul adı:** DenyFirst Rootwell
**Əsas prinsip:** kiçik və yoxlanılan nüvədən başlayıb mərhələli şəkildə tam certificate lifecycle platformasına çevrilmək

Rootwell-in certificate lifecycle-dan daha geniş platforma istiqaməti — Vault,
SSH key management, qısamüddətli SSH certificate-ləri, browser terminal və PGP
— [`PLATFORM-VISION-AZ.md`](PLATFORM-VISION-AZ.md) sənədində təsvir olunur. Bu
geniş vizyon ilk mərhələnin scope-unu dəyişmir: başlanğıc yenə lokal Workbench və
təhlükəsiz kripto nüvəsidir.

Bu sənəd məhsulun uzunmüddətli istiqamətini, təhlükəsizlik sərhədlərini və ilk
icra mərhələsini müəyyən edir. Yeni fikir yarandıqda birbaşa implementasiyaya
əlavə edilməməli, əvvəl bu plana və uyğun mərhələyə yerləşdirilməlidir.

## 1. Məhsulun məqsədi

Rootwell şirkətlərin və texniki istifadəçilərin certificate və kriptoqrafik
aktivlərini təhlükəsiz şəkildə görməsi, yoxlaması, yaratması, yeniləməsi,
yerləşdirməsi və ləğv etməsi üçün self-hosted platforma olacaq.

Qısa məhsul vədi:

> Certificate və açarlarını üçüncü tərəfə təhvil vermədən tap, yoxla, yenilə,
> yerləşdir və nəticəni sübut et.

Porch ilə münasibət:

- Porch xaricdən serverin həqiqətən nə təqdim etdiyini ölçür.
- Rootwell certificate-in daxili lifecycle-ını idarə edir.
- Rootwell deployment-dan sonra Porch ilə müstəqil verification aparır.
- Porch ayrıca və müstəqil məhsul olaraq qalır; Rootwell onun versiyalanmış JSON/CLI
  contract-ından istifadə edir.

## 2. Həll etdiyimiz əsas problemlər

1. İstifadəçilər certificate və private key conversion üçün etibar edilməyən
   online saytlardan istifadə edir.
2. Certificate-lər müxtəlif server, laptop, appliance, cloud hesabı və
   qovluqlarda səpələnir.
3. Certificate-in sahibi, istifadə yeri və bitmə tarixi məlum olmur.
4. Renewal certificate-i yaradır, amma onu düzgün yerə deploy və reload etmək
   ayrıca, riskli iş olaraq qalır.
5. Deployment-dan sonra serverin yeni certificate-i həqiqətən təqdim etdiyi
   müstəqil şəkildə yoxlanmır.
6. Bir çox həll private key-ləri mərkəzi bazada toplayaraq böyük blast radius
   yaradır.
7. Mövcud açıq mənbə həllər çox vaxt yalnız ACME, yalnız Kubernetes, yalnız
   Docker və ya yalnız CA funksiyasına fokuslanır.
8. Xəta zamanı səbəb, görülən əməliyyat və rollback vəziyyəti aydın olmur.

## 3. Məhsulu fərqləndirən xüsusiyyətlər

Feature sayından əvvəl aşağıdakı davranışlar Rootwell-in əsas fərqi olacaq:

- **Local-first:** conversion və inspection üçün şəbəkə tələb edilmir.
- **Key-local by default:** private key mümkün qədər istifadə ediləcəyi hostda
  yaranır və həmin hostu tərk etmir.
- **No hidden upload:** lokal alətlərdə telemetry və gizli network request yoxdur.
- **Evidence-based:** hər verdict konkret certificate sahəsi, policy versiyası
  və mənbə ilə izah olunur.
- **Safe deployment:** stage, validate, atomic replace, reload, verify və
  rollback bir əməliyyat kimi idarə olunur.
- **Independent verification:** deployment uğuru yalnız faylın yazılması ilə
  deyil, Porch vasitəsilə real TLS handshake ilə təsdiqlənir.
- **No remote shell agent:** control plane agentə arbitrary shell command
  göndərə bilmir; yalnız məhdud və əvvəlcədən müəyyən edilmiş action-lar var.
- **Capability honesty:** sistem edə bilmədiyi renewal və revocation-u düymə
  kimi göstərmir; səbəbi və tələb olunan səlahiyyəti izah edir.
- **Recoverability:** backup, rollback və disaster recovery sonradan əlavə
  olunan funksiya deyil, dizaynın bir hissəsidir.

## 4. Dəyişməz təhlükəsizlik qaydaları

Bu qaydalar məhsul böyüdükcə yumşaldılmamalıdır:

1. Private key, password, API secret və recovery material heç vaxt log-a
   yazılmır.
2. Password CLI argument və ya URL daxilində qəbul edilmir. İnteraktiv TTY,
   məhdud icazəli fayl və ya OS secret store istifadə olunur.
3. Private key məzmunu default JSON/text output-a daxil edilmir.
4. Yeni secret faylları mümkün olan ən məhdud filesystem icazələri ilə və
   atomik şəkildə yazılır.
5. Mövcud fayl explicit təsdiq olmadan overwrite edilmir.
6. Agent inbound idarəetmə portu açmır; control plane-ə outbound, mutual TLS
   əlaqəsi qurur.
7. Hər agent yalnız ona təyin olunmuş domain, path və action-larla işləyə bilər.
8. Root CA private key daimi online control plane-də saxlanmır.
9. Root və intermediate CA rotation ayrıca ceremony və recovery planı tələb edir.
10. Import edilmiş certificate yalnız issuer səlahiyyəti olduqda revoke edilə
    bilər; UI bunu yanlış təqdim etmir.
11. Renewal uğuru certificate issuance deyil, sağlam deployment və xarici
    verification tamamlandıqda qeydə alınır.
12. Kriptoqrafik parser-lər malformed input-a qarşı fuzz və negative test-lərlə
    yoxlanmadan release edilmir.
13. Dependency əlavə ediləndə lisenziya, maintenance, security history və
    transitive dependency-lər ayrıca yoxlanılır.
14. Security invariant-ı pozan convenience feature qəbul edilmir.

## 5. Hədəf istifadəçilər

### İlkin hədəf

- 20–500 certificate idarə edən kiçik və orta DevOps/security komandaları
- Linux, Windows, Docker və appliance qarışığı olan şirkətlər
- Enterprise CLM məhsullarının qiymət və mürəkkəbliyini istəməyən komandalar
- Self-hosting və data ownership tələb edən təşkilatlar
- MSP-lər — sonrakı multi-tenant mərhələsində

### Community kanalı

- Homelab istifadəçiləri
- Sistem administratorları
- Lokal/offline certificate conversion ehtiyacı olan developer-lər

Community istifadəçiləri məhsulun əsas kommersiya hədəfi olmasa da, real cihaz
və deployment müxtəlifliyini test etmək üçün vacibdir.

## 6. Yekun sistemin komponentləri

```text
┌───────────────────────────────────────────┐
│ Rootwell Server / Control Plane               │
│ UI · inventory · policy · scheduler       │
│ CA connectors · audit · agent management  │
└───────────────────┬───────────────────────┘
                    │ outbound mTLS
        ┌───────────▼───────────┐
        │ Rootwell Agent            │
        │ local key generation  │
        │ deploy · reload       │
        │ verify · rollback     │
        └───────────┬───────────┘
                    │
        Nginx · Apache · IIS · HAProxy

Rootwell Workbench
└── offline CLI/UI: inspect · match · convert · CSR

Porch
└── independent post-deployment TLS verification
```

Komponentlər:

- `rootwell`: offline Workbench CLI
- `rootwelld`: gələcək self-hosted control plane
- `rootwell-agent`: hədəf hostlarda məhdud daemon/service
- `rootwell-web`: control plane UI; yalnız server mərhələsində
- `porch-scan`: ayrıca məhsul və verification dependency-si
- connectors: ACME, Sectigo, DigiCert, Vault, Smallstep, AD CS və digərləri

## 7. Mərhələli roadmap

Tarixlər ilkin komandanın sürəti ölçülmədən verilməyəcək. Hər mərhələ yalnız
çıxış meyarları ödənəndə bağlanır.

### Mərhələ 0 — Foundation və threat model

**Məqsəd:** private key işləyən kod yazmazdan əvvəl sərhədləri və riskləri
müəyyən etmək.

Deliverable-lar:

- threat model
- data classification
- security invariants
- certificate/key format matrix
- dependency review qaydası
- CLI contract və error modeli
- test fixture qaydası
- responsible disclosure üçün `SECURITY.md`
- əsas architecture decision record-lar

Çıxış meyarı:

- aktivlər, threat actor-lar və trust boundary-lər sənədləşdirilib;
- v0.1-in etdikləri və etmədikləri dəqiqdir;
- seçilən kripto kitabxanaları review edilib;
- malformed və secret-bearing test fixture-lərin təhlükəsiz saxlanma qaydası var.

### Mərhələ 1 — Rootwell Workbench CLI v0.1

**Məqsəd:** internetə heç nə göndərmədən gündəlik certificate işlərini təhlükəsiz
həll edən kiçik, etibarlı alət hazırlamaq.

İlk əmrlər:

```text
rootwell inspect <file>
rootwell match --cert <file> --key <file>
rootwell verify <file> --trust-bundle <roots.pem> --hostname <name>
rootwell convert --input <file> --to pem|der|p12
rootwell csr --key <file> --dns example.com --dns www.example.com
```

v0.1 format scope-u:

- X.509 certificate: PEM və DER
- CSR: PEM və DER
- private key: PKCS#8, PKCS#1 və SEC1
- bundle: PKCS#12/PFX
- certificate chain: PEM bundle

v0.1 funksiyaları:

- fayl tipini təhlükəsiz müəyyən etmək
- subject, issuer, serial, SAN, validity, key algorithm və fingerprint göstərmək
- certificate/private-key uyğunluğunu yoxlamaq
- təqdim edilmiş trust bundle ilə offline chain verification
- PEM/DER/PFX çevirmələri
- CSR yaratmaq və daxil edilən SAN-ları nəticədə yenidən yoxlamaq
- human-readable və secret-free JSON output
- explicit, sabit exit code-lar

v0.1-də olmayacaq:

- server və ya web UI
- user account
- certificate inventory database
- ACME və digər network request
- private key vault
- root/intermediate CA yaratmaq
- automatic renewal/deployment
- GPG, SSH, JKS və code-signing lifecycle

Çıxış meyarı:

- tool şəbəkəsiz işləyir və network call yaratmır;
- supported format matrix üzrə bütün əməliyyatlar testlidir;
- parser və conversion path-ləri fuzz test-dən keçir;
- output və log-larda secret olmadığı testlə yoxlanır;
- OpenSSL ilə hazırlanmış uyğun fixture-lər üzərində nəticələr müqayisə edilir;
- Windows və Linux build-ləri deterministik release prosesindən çıxır;
- təhlükəsiz istifadə və məhdudiyyətlər dokumentasiya olunur.

### Mərhələ 2 — Lokal Workbench UI

**Məqsəd:** CLI istifadə etməyən istifadəçiyə online converter əvəzi vermək.

İlk foundation increment-i Inspect və Verify axınlarının dependency-free statik
UI shell-ini qurdu. İkinci increment public PEM/DER X.509 inspection-u eyni Go
core-un WebAssembly build-i ilə browser daxilində işlədir. Certificate byte-ları
server API-yə göndərilmir; asset loader və file-reading kod ayrı capability-lərdə
saxlanır. Private key və digər secret-bearing browser əməliyyatları ayrıca
threat-model review olmadan bu sərhədə daxil edilmir.

Browser public bundle explorer artıq 1–8 seçilmiş public faylı (tək DER
certificate və ya PEM bundle) eyni Go parser-i ilə lokal açır. Ümumi limit
16 MiB və 64 certificate-dir; fayllararası duplicate rədd edilir. O,
bu halda iki faylı və tam fingerprint-i xəbərdarlıqda göstərir; eyni faylın
daxilindəki duplicate üçün yalnız faylı göstərir. Qismən nəticə yoxdur.
Rootwell certificate metadata-sını və imzası uyğun gələn mümkün issuer
əlaqələrini göstərir, amma leaf/verified chain/trust qərarı vermir. Kartlardan
açıq seçilmiş public hissələri göstərilən sırada yeni PEM bundle
kimi hazırlaya bilir, amma onu verified fullchain adlandırmır. Seçilən bir
public certificate-i PEM və ya DER kimi browser-managed download-a hazırlayır;
`.crt` və `.cer` uzantıları
hər iki encoding ilə açıq seçilə bilir. Private key/PFX qəbul etmir.
Bu sərhəd browser Verify-dan
ayrıdır.

Sadə certificate import/Verify və public bundle explorer üçün konkret
istifadəçi axını, etibar mənbəyi sərhədi və mərhələli qəbul meyarları
[`WORKBENCH-IMPORT-UX-AZ.md`](WORKBENCH-IMPORT-UX-AZ.md) sənədindədir.
Default görünüş CA-nın verdiyi bir və ya bir neçə fayldan başlayacaq;
Advanced eyni verification core-u və policy-ni istifadə edərək texniki
rolları açıq göstərəcək. Bundle içindəki root avtomatik trusted
sayılmayacaq. Bir public hissəni ayrıca endirmək, çoxfayllı metadata və
mümkün issuer əlaqələri və seçilmiş public PEM bundle export-u işləkdir;
Explore daxilində avtomatik fullchain sırası və qəti rol/chain təyini hələ
ayrıca mərhələdir. Browser Verify artıq ayrıca seçilən PEM trust anchor,
hostname və eyni CLI Go policy-si ilə Simple/Advanced rejimlərində işləyir.
Uğurlu Verify nəticəsindən sonra faylları yenidən yoxlayıb yalnız təsdiqlənmiş
leaf + intermediate yolunu public PEM kimi endirmək də mümkündür; root və
private key output-a daxil edilmir. Bu, canlı endpoint və revocation hökmü
vermir. Public demo faylları ilə hər iki rejim sınana bilir.
Private key/PFX axını isə ayrıca security review tələb edir.
Browser Verify-da ayrıca etibarlı mənbədən alınmış tam root SHA-256 fingerprint-i
istəyə bağlı pin etmək olur; yanlış pin rədd edilir, boş pin isə root kimliyini
təsdiqləmir. Bu, canlı endpoint/MITM yoxlamasını əvəz etmir.

CLI nüvəsində certificate/private-key uyğunluq yoxlaması strict və bounded
sərhədlə mövcuddur. Bu, browserdə secret-bearing input qəbul etmək üçün
avtomatik icazə deyil; browser match ayrıca review tələb edir.

- drag-and-drop inspection və conversion
- bütün processing lokal
- offline işləmə
- secret-bearing fayllar üçün aydın UI xəbərdarlıqları
- certificate chain vizual görünüşü
- key/cert match nəticəsi
- CSR wizard
- CLI ilə eyni core və test nəticələri

Web UI seçilərsə Content Security Policy, dependency-free və ya ciddi pinned
dependency modeli, XSS threat model və browser memory məhdudiyyətləri ayrıca
review edilməlidir. Lokal desktop shell yalnız real fayda verərsə əlavə olunur.

### Mərhələ 3 — Inventory və monitoring

**Məqsəd:** əvvəl metadata-nı mərkəzləşdirmək; private key custody-ni yox.

- manual certificate import
- public endpoint discovery
- Porch scan nəticəsindən asset yaratmaq
- owner, team, environment, location və tags
- expiry timeline və configurable alert-lər
- duplicate və orphan certificate detection
- weak algorithm, hostname, chain və policy statusu
- dəyişiklik tarixçəsi
- private key-in olub-olmaması və harada saxlanması barədə metadata; key-in özü yox

Çıxış meyarı:

- inventory yalnız public certificate məlumatı ilə faydalıdır;
- unknown owner/location açıq görünür;
- notification itməsi certificate expiry-yə səssiz səbəb olmur;
- discovery private key toplamır.

### Mərhələ 4 — ACME issuance və renewal

**Məqsəd:** əvvəl standard protokol ilə yeni certificate almaq.

- ACME account və External Account Binding
- HTTP-01 və DNS-01
- əvvəl məhdud sayda keyfiyyətli DNS provider connector-u
- renewal window və retry/backoff
- rate-limit awareness
- yeni key yaratmaq və CSR
- renewal history
- manual approval seçimi
- Let’s Encrypt staging ilə integration test
- Sectigo ACME/EAB compatibility

Bu mərhələdə issuance var, amma ümumi-purpose server agent hələ ayrıca mərhələdir.
Müştəri certificate-i manual və ya sadə export ilə götürə bilər.

### Mərhələ 5 — Rootwell Agent və təhlükəsiz deployment

**Məqsəd:** certificate-i yaratmaqdan real workload-da sağlam işlətməyə keçmək.

İlk platforma: Linux systemd host və Nginx.

Deployment transaction:

1. agent lokal yeni key yaradır;
2. CSR control plane/CA-ya göndərilir;
3. gələn certificate key və request ilə yoxlanır;
4. yeni fayllar staging path-ə məhdud permission-la yazılır;
5. Nginx config test edilir;
6. mövcud faylların rollback copy-si saxlanır;
7. atomic replace edilir;
8. reload edilir;
9. lokal health check və Porch handshake aparılır;
10. fingerprint/hostname/chain/policy gözlənilən deyilsə rollback edilir.

Sonrakı adapter-lər:

- Apache
- HAProxy
- IIS/Windows
- Docker volume
- Kubernetes/cert-manager integration
- appliance və cloud API-ləri

Agent təhlükəsizlik sərhədi:

- arbitrary command execution yoxdur;
- path allowlist;
- domain/SAN allowlist;
- hər host üçün unikal identity;
- qısaömürlü və rotasiya edilən mTLS credential;
- signed desired-state message;
- replay protection;
- minimal OS privilege;
- tam audit və aydın rollback nəticəsi.

### Mərhələ 6 — CA connector-ları və revocation

**Məqsəd:** multi-CA lifecycle idarəçiliyi.

Prioritet:

1. generic ACME
2. Sectigo SCM REST/ACME
3. DigiCert
4. Smallstep
5. Vault/OpenBao
6. Microsoft AD CS
7. EJBCA

Ortaq connector capability modeli:

```text
Discover
Enroll
Renew/Reissue
Replace
Revoke
ReadStatus
ListProfiles
```

Hər connector dəstəkləmədiyi əməliyyatı explicit bildirir. `Renew` daxilən yeni
key/CSR/certificate issuance deməkdir; mövcud certificate-in `NotAfter` sahəsi
dəyişdirilmir.

### Mərhələ 7 — Komanda və enterprise funksiyaları

- çox istifadəçi və RBAC
- OIDC/SAML SSO
- approval workflow
- separation of duties
- immutable/tamper-evident audit
- maintenance windows
- multi-tenant MSP modeli
- KMS/HSM/TPM və non-exportable key-lər
- encrypted backup və restore drill
- SIEM/webhook integration
- compliance evidence export

### Mərhələ 8 — SSH key management və SSH CA

- server, account, owner və public-key inventory
- legacy `authorized_keys` idarəetməsi; yalnız public key push edilir
- host enrollment və `sshd_config` dəyişiklikləri üçün validate/rollback
- SSH user və host CA
- `TrustedUserCAKeys` və host certificate rollout-u
- qısamüddətli user certificate-ləri
- principal, TTL, source və extension policy-si
- KRL və emergency deny mexanizmi
- CLI vasitəsilə native OpenSSH access

### Mərhələ 9 — Browser SSH Access Gateway

- OIDC/passkey/MFA authentication
- deny-by-default RBAC/ABAC
- request/approval və step-up authentication
- browser terminal üçün WebSocket gateway
- hər sessiya üçün ephemeral key və qısamüddətli SSH certificate
- host certificate verification
- port/agent forwarding və file transfer üçün ayrıca policy
- session metadata audit-i
- opt-in/policy-based encrypted session recording
- session termination və emergency access revocation

Browser heç vaxt uzunömürlü SSH private key almır. Gateway arbitrary credential
vault deyil; sessiya key-i yalnız yaddaşda yaşayır və sessiya bitəndə silinir.

### Mərhələ 10 — Vault və digər kriptoqrafik aktivlər

- typed key object modeli: X.509, SSH, PGP, S/MIME və code signing
- exportable və non-exportable key fərqi
- local encrypted backend, PKCS#11/HSM, TPM, Vault/OpenBao və cloud KMS adapter-ləri
- hər obyekt üçün ayrı data-encryption key və xarici key-encryption key
- dual control, break-glass və recovery ceremony
- GPG/PGP key generation
- primary key, signing/encryption/auth subkey ayrılığı
- expiry və subkey rotation
- yaradılma zamanı revocation certificate
- hardware token və offline primary-key workflow-u
- S/MIME və code-signing certificate-ləri
- JKS və platform trust store-ları

Bu aktivlər ortaq inventory-də görünə bilər, amma X.509 lifecycle məntiqinə zorla
salınmamalıdır. Hərəsinin ayrıca trust, rotation və revocation modeli saxlanmalıdır.

## 8. İlkin texniki istiqamət

### Dil və repository

- İlkin seçim: Go; Porch ilə komanda təcrübəsi, statik binary və sadə deployment.
- Başlanğıc: ayrıca `rootwell` repository-si, monorepo daxilində CLI/core.
- Control plane və agent sonradan eyni repo daxilində ayrıca command ola bilər.
- Porch source-u Rootwell repo-suna copy edilmir.

### Kod quruluşu üçün ilkin fikir

```text
rootwell/
├── cmd/rootwell/
├── internal/
│   ├── classify/
│   ├── x509inspect/
│   ├── keymatch/
│   ├── chainverify/
│   ├── convert/
│   ├── csr/
│   └── safeio/
├── testdata/
├── docs/
└── SECURITY.md
```

Package adları plan göstəricisidir, implementasiya kontraktı deyil.

### Dependency siyasəti

Porch-un zero-dependency prinsipi Rootwell üçün avtomatik tələb deyil. PKCS#12 kimi
funksiyalar üçün yetkin kitabxana istifadə etmək öz kripto implementasiyamızı
yazmaqdan daha təhlükəsiz ola bilər. Hər dependency üçün:

- maintainer və release fəaliyyəti;
- məlum vulnerability-lər;
- istifadə etdiyi kripto primitive-lər;
- parsing limit-ləri;
- lisenziya;
- transitive dependency-lər;
- fuzzing və test keyfiyyəti

review edilməlidir. Öz ASN.1, cipher və ya password-based encryption primitive-i
yazılmamalıdır.

## 9. Test və keyfiyyət strategiyası

Hər mərhələ üçün uyğun hissələr məcburidir:

- unit test
- table-driven format test-ləri
- golden output test-ləri
- malformed input və truncation test-ləri
- fuzz test
- cross-tool fixture: OpenSSL və uyğun platform tool-ları
- race detector
- static analysis və vulnerability scan
- permission və atomic-write test-ləri
- secret leakage test-ləri
- network isolation test-i
- upgrade/migration test-ləri
- rollback və fault-injection test-ləri
- supported platform integration test-ləri

Security-critical dəyişiklik yalnız implementasiyanı yazan şəxsin testləri ilə
release edilməməlidir. İnkişaf mərhələsində maintainer ayrıca adversarial
self-review və CI sübutlarını PR-da qeyd edə bilər; bu, müstəqil audit deyil.
İlk public release-dən əvvəl kənar təhlükəsizlik auditi, tapıntıların aradan
qaldırılması və dəyişən hissələrin yenidən yoxlanması məcburidir. Sonrakı
security-critical release-lər üçün də kənar audit təkrarlanır. AI audit yüksək
riskli açar saxlama və remote access üçün mütəxəssis insan review-unu əvəz etmir.

## 10. Məhsul və biznes sərhədi

İlkin istiqamət:

- self-hosted və yoxlanıla bilən community nüvə;
- kommersiya dəyəri: komanda idarəetməsi, premium connector-lar, SSO/RBAC,
  approvals, multi-tenant, KMS/HSM və enterprise support;
- certificate satmaq yox, təhlükəsiz lifecycle və outage prevention satmaq;
- hosted xidmət gələcəkdə mümkündür, amma private key-lərin müştəri agentində
  qalması əsas üstünlük olmalıdır.

Lisenziya qərarı ayrıca ADR tələb edir. Porch-un AGPL seçimi avtomatik olaraq
Rootwell-ə tətbiq edilmir, amma brendin yoxlanıla bilənlik prinsipinə uyğun seçim
edilməlidir.

## 11. İlk icra backlog-u

İlk koddan əvvəl və sonra sıra dəyişdirilmədən görüləcək işlər:

1. `THREAT-MODEL.md` — asset, actor, boundary və abuse case-lər.
2. `SECURITY-INVARIANTS.md` — test edilə bilən dəyişməz qaydalar.
3. `FORMAT-MATRIX.md` — hansı format, encryption və algorithm dəstəklənir.
4. ADR: Go versiyası, dependency siyasəti və CLI output contract.
5. Minimal `cmd/rootwell` və sabit exit-code/error modeli.
6. Təhlükəsiz input classification və parsing limit-ləri.
7. `rootwell inspect`.
8. `rootwell match`. *(implemented: unencrypted PKCS#8/PKCS#1/SEC1, PEM/DER)*
9. Explicit trust bundle ilə `rootwell verify`.
10. Conversion dependency review və `rootwell convert`.
11. `rootwell csr`.
12. Fuzz corpus, malformed fixtures və cross-tool compatibility suite.
13. Windows/Linux CI və signed release dizaynı.
14. Security usage guide və v0.1 audit/review.

## 12. İlk mərhələdə cavablandırılacaq açıq qərarlar

- Workbench üçün yalnız CLI, yoxsa eyni release-də lokal UI?
- PKCS#12 üçün hansı kitabxana istifadə ediləcək?
- System trust store v0.1-də olacaq, yoxsa yalnız explicit bundle?
- Encrypted legacy PKCS#1/SEC1 import scope-a daxil olacaqmı?
- FIPS tələb edən mühitlər ilkin hədəfdirmi?
- Windows private-key output ACL-ləri necə test ediləcək?
- Release signing üçün hansı model seçiləcək?
- Community və kommersiya lisenziya sərhədi necə olacaq?

Default cavab: risk və scope artıran funksiya v0.1-dən çıxarılır, lakin format və
architecture onu gələcəkdə əlavə etməyə mane olmur.

## 13. Hazırkı qərar

İlk real məhsul increment-i **Rootwell Workbench CLI v0.1** olacaq. Server, database,
agent və ACME ilə başlamırıq. Əvvəl certificate/key parsing, təhlükəsiz file I/O,
conversion və verification nüvəsini yüksək keyfiyyətlə hazırlayırıq. Bu nüvə
sonrakı bütün Rootwell komponentlərinin ortaq və audit edilə bilən əsası olacaq.
