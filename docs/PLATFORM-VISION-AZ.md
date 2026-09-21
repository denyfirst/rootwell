# DenyFirst Rootwell — geniş platforma vizyonu

**Status:** istiqamət sənədi, v0.1

**Tarix:** 2026-09-21
**Əhatə:** Workbench, Inventory, Vault, Certificates, SSH Access və PGP

## 1. Məhsulun yeni tərifi

Rootwell yalnız certificate manager deyil. Uzunmüddətli məhsul belə tərif olunur:

> Şirkətin certificate-lərini, SSH və PGP açarlarını bir inventarda göstərən,
> kriptoqrafik əməliyyatları lokal və təhlükəsiz yerinə yetirən, TLS lifecycle-ı
> avtomatlaşdıran və serverlərə qısamüddətli identity ilə təhlükəsiz giriş verən
> self-hosted security workspace.

Bu vizyon bir executable daxilində bütün funksiyaları qarışdırmaq demək deyil.
Rootwell eyni UI, policy və audit modelindən istifadə edən, amma ayrı trust
boundary-ləri olan modullar ailəsidir.

## 2. Məhsul modulları

### Rootwell Workbench

Gündəlik lokal kripto alətləri:

- certificate/key inspection
- PEM, DER, PKCS#12/PFX və sonradan JKS conversion
- certificate/private-key match
- chain verification
- CSR və təhlükəsiz key generation
- SSH public/private key inspection və format conversion
- PGP key inspection
- heç bir upload və telemetry olmadan offline iş

### Rootwell Inventory

İstifadəçiyə “nəyim var və haradadır?” sualını cavablandırır:

- X.509 certificate-lər
- TLS endpoint-lər
- SSH host key-ləri
- SSH user public key-ləri
- PGP primary key və subkey metadata-sı
- owner, team, environment, server və tətbiq əlaqəsi
- expiry, rotation, revocation və backup statusu
- public metadata default; secret material ayrıca Vault sərhədindədir

### Rootwell Vault

Private material üçün ayrıca təhlükəsizlik sərhədi:

- key object və key-handle modeli
- exportable/non-exportable status
- encryption at rest və per-object encryption
- external KMS/HSM/TPM/Vault/OpenBao backend-ləri
- access policy, approvals və tam audit
- backup, restore və recovery ceremony
- mümkün olduqda “key-i göstər” deyil, “key ilə əməliyyat et” modeli

### Rootwell Certificates

- ACME və CA connector-ları
- issuance, renewal/reissue və revocation
- TLS certificate inventory və ownership
- agent-based deployment
- reload, Porch verification və rollback
- public və private PKI

### Rootwell SSH

- server və account inventory
- public-key management
- SSH user/host CA
- qısamüddətli certificate-lər
- native OpenSSH login
- browser-based access gateway
- access request, approval, MFA və audit

### Rootwell PGP

- primary key və subkey lifecycle
- signing, encryption və authentication capability-ləri
- expiry və subkey rotation
- revocation certificate və recovery statusu
- hardware token/offline primary key dəstəyi
- public-key publishing sonrakı connector kimi

## 3. Bir UI, ayrı təhlükəsizlik sərhədləri

```text
┌─────────────────────────────────────────────────────────┐
│ Rootwell Web / CLI                                          │
│ ortaq dizayn · inventory · policy · audit · approvals   │
└──────────────┬──────────────────┬───────────────────────┘
               │                  │
     ┌─────────▼────────┐  ┌─────▼─────────────────┐
     │ Control Plane    │  │ Vault / Signing Plane │
     │ metadata, jobs   │  │ key handles, signing │
     │ heç bir shell yox│  │ ayrıca unlock/policy │
     └──────┬───────────┘  └─────┬─────────────────┘
            │ outbound mTLS       │ KMS/HSM/TPM
     ┌──────▼───────────┐         │
     │ Rootwell Agent       │◀────────┘
     │ host operations  │
     └──────┬───────────┘
            │
     ┌──────▼───────────┐
     │ Target services  │
     │ sshd, TLS, apps  │
     └──────────────────┘

Browser SSH:
Browser ──WSS──▶ Access Gateway ──SSH──▶ Target host
                       │
                  short-lived cert
```

Control Plane compromise avtomatik olaraq bütün exportable private key-lərin
oxunması demək olmamalıdır. Vault/Signing Plane ayrıca authorization, unlock və
audit sərhədinə sahib olmalıdır.

## 4. SSH key-ləri necə serverlə əlaqələndiririk?

Inventory-də SSH key obyektinin əlaqələri olur:

```text
Key ID: ssh-user-0193
Fingerprint: SHA256:...
Type: Ed25519 public key
Owner: rashad@example.com
Purpose: interactive-admin
Servers: prod-web-01, prod-web-02
Accounts: deploy, ops
Source: imported / generated / hardware-backed
Status: active / expiring / revoked / unknown
Last policy change: ...
```

Private key-in serverə push edilməsi qadağandır. İki təhlükəsiz model var.

### Legacy model — managed `authorized_keys`

- Rootwell yalnız public key-i serverə yazır.
- Agent idarə etdiyi sətrləri marker/blok ilə ayırır.
- Dəyişiklikdən əvvəl backup və syntax/permission yoxlaması edir.
- Atomic replace istifadə edir.
- İstifadəçiyə aid olmayan mövcud sətrləri silmir.
- Remove əməliyyatı yalnız Rootwell-in idarə etdiyi entry-yə toxunur.
- Private key istifadəçinin cihazında, hardware token-də və ya ayrıca vault-da qalır.

Bu compatibility rejimidir; böyük mühitdə əsas model olmamalıdır.

### Əsas model — SSH certificates

Serverə hər istifadəçinin key-i deyil, bir dəfə Rootwell SSH CA-nın **public key-i**
yerləşdirilir:

```text
TrustedUserCAKeys /etc/ssh/rootwell-user-ca.pub
```

İstifadəçi daxil olmaq istəyəndə Rootwell onun public key-inə qısaömürlü certificate
imzalayır. Certificate daxilində:

- principal/Linux username;
- validity interval və qısa TTL;
- unique serial və key ID;
- icazə verilən extension-lar;
- lazım olduqda source-address restriction

olur. Default policy:

- TTL 5–15 dəqiqə; rol üzrə maksimum ayrıca təyin edilir;
- `permit-agent-forwarding`, `permit-port-forwarding`, `permit-X11-forwarding`
  default bağlıdır;
- production/root access üçün MFA və approval tələb olunur;
- hər issuance və session ayrıca audit event-dir.

Host identity də SSH host certificate ilə idarə edilə bilər. Bu, istifadəçinin
saxta hosta qoşulmasının və trust-on-first-use riskinin qarşısını alır.

## 5. Server enrollment və agent

Yeni server üçün:

1. Admin Rootwell-də server asset yaradır.
2. Qısaömürlü, bir dəfəlik enrollment token yaradılır.
3. `rootwell-agent enroll` token və server identity/attestation ilə qoşulur.
4. Agent öz mTLS identity-sini alır.
5. Agent mövcud `sshd_config`, host key-ləri və account-ları yalnız oxuyub report edir.
6. Admin təklif olunan dəyişiklik diff-ini görür və təsdiq edir.
7. Agent backup yaradır, `sshd -t` ilə yeni config-i yoxlayır və atomik tətbiq edir.
8. Yeni ayrıca test connection uğurlu olmadan köhnə giriş üsulu silinmir.
9. Uğursuzluqda avtomatik rollback edilir.

Agent arbitrary remote shell deyil. Control plane yalnız versiyalanmış action
tipləri göndərə bilər, məsələn:

```text
InstallTrustedUserCA
InstallHostCertificate
ManageAuthorizedKey
DeployTLSCertificate
ReloadKnownService
RunDefinedHealthCheck
```

Generic `RunCommand` action-ı yoxdur.

## 6. Browser üzərindən SSH bağlantısı

Browser-based SSH mümkündür, amma browserə uzunömürlü private key vermək olmaz.
Təhlükəsiz axın:

1. İstifadəçi Rootwell-ə OIDC və ya passkey ilə daxil olur.
2. Target server və istənilən account seçilir.
3. Policy engine user, group, target, environment, vaxt və risk əsasında qərar verir.
4. Lazımdırsa MFA/approval tələb olunur.
5. Access Gateway sessiya üçün ephemeral key pair yaradır.
6. SSH CA public key-i 1–5 dəqiqəlik certificate kimi imzalayır.
7. Gateway target host certificate-ni yoxlayaraq SSH bağlantısı qurur.
8. Terminal stream WebSocket ilə browserə ötürülür.
9. Sessiya bitəndə ephemeral private key yaddaşdan silinir.
10. Certificate qısa müddətdə özü etibarsız olur.

Browserdə saxlanmayacaq:

- SSH private key
- CA signing key
- reusable SSH certificate
- vault master key
- secret-in `localStorage` nüsxəsi

Browser gateway üçün məcburi controls:

- strict CSP və dependency review
- secure, HttpOnly, SameSite session cookie
- WebSocket origin və session binding
- CSRF/replay protection
- qısa idle və absolute timeout
- step-up authentication
- clipboard, paste, file upload/download və port forwarding üçün ayrıca policy
- connection rate limit və abuse controls
- host key/certificate verification
- secret-safe structured logs

Session recording default universal olmamalıdır. Şirkət policy-si tələb edərsə:

- recording ayrıca encrypted storage-da saxlanır;
- kim baxıbsa ayrıca audit edilir;
- retention və access policy açıqdır;
- istifadəçi recording barədə session başlamazdan əvvəl məlumatlandırılır;
- typed password terminal echo etməsə belə command/output daxilində başqa secret-lərin
  görünə biləcəyi qəbul edilir.

## 7. Vault təhlükəsizlik modeli

“Bütün key-ləri bir database-ə yığmaq” Rootwell Vault-un məqsədi deyil. Vault key-in
harada olduğunu və onunla hansı əməliyyatın edilə biləcəyini idarə edir.

Key location növləri:

- `local-file`
- `local-encrypted-vault`
- `agent-host`
- `os-keystore`
- `TPM`
- `PKCS11-HSM`
- `Vault/OpenBao`
- `cloud-kms`
- `hardware-token`
- `offline`

Hər key üçün:

- type və algorithm;
- fingerprint/public material;
- owner/purpose;
- exportability;
- backend/location;
- rotation/expiry;
- backup/recovery status;
- allowed operations;
- approval requirement

saxlanır.

Mərkəzi secret storage əlavə ediləndə:

- per-object random DEK;
- DEK-in xarici KEK ilə envelope encryption-u;
- KEK database ilə eyni yerdə saxlanmır;
- tenant/team sərhədi;
- export əməliyyatı signing/decrypt əməliyyatından ayrıca permission-dır;
- two-person approval və break-glass;
- offline encrypted backup;
- periodik restore drill;
- append-only/tamper-evident audit

tələb olunur.

## 8. PGP modeli

PGP “bir dənə key yarat və vault-a qoy” kimi dizayn edilməməlidir.

Tövsiyə edilən model:

- primary certification key offline və ya hardware-backed;
- gündəlik istifadə üçün signing/encryption/authentication subkey-ləri;
- subkey-lərə ayrıca expiry;
- rotation zamanı primary key ilə yeni subkey imzalanması;
- yaradılma zamanı revocation certificate;
- ən az bir test edilmiş encrypted backup;
- public key export/publish ilə private key export-un tam ayrılması;
- owner identity verification statusunun ayrıca göstərilməsi.

İlk PGP mərhələsi inspection və inventory-dir. Browserdə server-side PGP signing
yalnız Vault/Signing Plane və approval modeli yetişdikdən sonra əlavə edilə bilər.

## 9. Porch ilə ortaq dizayn və davranış

Vizual dil ortaq olacaq:

- neytral qara fon, ölçülü qırmızı vurğu;
- sistem şriftləri və xarici font request-i yoxdur;
- texniki dəyərlər üçün monospace;
- hər təhlükəli əməliyyatda target, təsir və rollback açıq görünür;
- “success” yalnız bütün verification tamamlandıqda göstərilir;
- ölçülməyən və bilinməyən vəziyyət gizlədilmir;
- demo/sample data production nəticəsi kimi göstərilmir.

Rootwell Porch-un görünüşünü paylaşa bilər, amma scanner UI-sini certificate və access
workflow-larına zorla köçürməməlidir. Ortaq design tokens və komponentlər, ayrıca
məhsul informasiya arxitekturası istifadə olunmalıdır.

Təklif olunan əsas naviqasiya:

```text
Overview
Inventory
Certificates
SSH Access
PGP
Vault
Agents
Policies
Audit
Settings
```

## 10. Risk əsaslı icra sırası

Geniş vizyon təsdiqlənsə belə implementasiya bu ardıcıllıqla gedir:

1. Threat model, security invariants və format matrix
2. Offline Rootwell Workbench CLI
3. Lokal Workbench UI
4. Public-metadata Inventory
5. Certificate monitoring və Porch integration
6. ACME və TLS renewal
7. Rootwell Agent və təhlükəsiz TLS deployment
8. SSH public-key inventory və legacy `authorized_keys` management
9. SSH user/host CA və native CLI access
10. Vault/Signing Plane və KMS/HSM backend-ləri
11. Browser SSH Access Gateway
12. PGP lifecycle
13. S/MIME, code signing və daha geniş platform connector-ları

Browser SSH erkən demo üçün qabağa çəkilməməlidir. O, authentication, policy,
gateway, SSH CA, host verification, audit və incident-response mexanizmlərinin
hamısına bağlıdır.

## 11. Məhsulun gündəlik istifadə dəyəri

İstifadəçi Rootwell-i yalnız ildə bir dəfə certificate yeniləmək üçün açmamalıdır.
Gündəlik dəyər belə yaranır:

- tez və offline certificate/key inspection;
- təhlükəsiz conversion;
- bütün crypto asset-lərin bir inventory-də görünməsi;
- serverə giriş və access request;
- bitmə/rotation xəbərdarlıqları;
- deployment və audit tarixçəsi;
- policy pozuntularının konkret izahı;
- owner və location axtarışı;
- bir click deyil, təhlükəsiz və sübut edilən workflow.

“Hamının sevdiyi alət” zəmanət edilə bilməz. Ölçülən məqsəd budur: ilk lokal
inspection saniyələr içində işləsin, setup aydın olsun, təhlükəsizlik istifadəçini
lazımsız addımlarla cəzalandırmasın və hər riskli əməliyyat izah edilə bilsin.

## 12. Qəti non-goal-lar

- universal password manager olmaq
- serverlərə private SSH key push etmək
- browser `localStorage`-da key saxlamaq
- öz kriptoqrafik primitive-imizi yazmaq
- agenti generic remote administration/RCE kanalına çevirmək
- root CA key-ni rahatlıq üçün həmişə online saxlamaq
- bütün PGP, SSH və X.509 obyektlərini eyni lifecycle məntiqinə salmaq
- feature sayını təhlükəsizlik invariant-larından üstün tutmaq

## 13. Bazar reallığı

Bu vizyon ayrı-ayrılıqda Teleport, Vault/OpenBao, Smallstep və certificate
lifecycle manager-lərin əhatə etdiyi sahələrə girir. Fərq “bizdə də browser
terminal var” olmamalıdır. Rootwell-in müdafiə edilə bilən fərqi:

- birləşdirilmiş, lakin ayrılmış trust boundary-ləri;
- local-first Workbench;
- key-local default;
- Porch ilə müstəqil post-deployment verification;
- aydın evidence və capability modeli;
- self-hosted, gündəlik istifadə üçün sadə UX;
- təhlükəsiz recovery və rollback

olmalıdır.

## 14. İstinad ediləcək standart və layihələr

- OpenSSH certificate və `TrustedUserCAKeys` davranışı
- RFC 4252 və əlaqəli SSH sənədləri
- WebAuthn Level 3
- RFC 8555 ACME
- RFC 5280 X.509
- OpenPGP Crypto Refresh, RFC 9580
- Vault signed SSH certificate modeli
- Smallstep SSH CA və short-lived identity modeli
- Teleport browser terminal, audit və session recording threat-ləri

Bu layihələrdən kod və ya arxitektura kor-koranə köçürülməyəcək. Onlar protocol
compatibility, threat model və gözlənilən istifadəçi davranışı üçün istinad nöqtəsidir.
