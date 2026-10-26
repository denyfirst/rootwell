# Rootwell — aktiv icra sırası

**Yenilənib:** 2026-10-26. Bu sənəd vaxt cədvəli və ya fon rejimində işləyən
avtomatlaşdırma deyil. Bir iş sessiyasında bir neçə uyğun increment ardıcıl
icra oluna bilər; hər increment ayrıca imzalı PR, test və self-review qapısından
keçir. Porch repository-si bu işin xaricindədir.

## Porch-dan uyğunlaşdırılan yanaşmalar — ADR 0055

2026-10-10 istifadəçi Porch-u dəyişmədən oxumağa icazə verdi. Ümumi quruluş,
DNS təlimatı, giriş UI-si və test/workflow prinsipləri read-only müqayisə edildi;
bu tam audit deyil. Rootwell giriş/parol dəyişmə/çıxış UI-sində 15 saniyəlik
tam sorğu limiti, 8 KiB login cavabı, gizlənəndə cancellation və gecikmiş
nəticənin rəddi əlavə olunur. İlkin parol loga verilmir; məcburi dəyişmə,
şifrəli custody və offline recovery sərhədləri qorunur.

Sonrakı manual DNS UI-si Porch-dakı sadə Type / Name / Value və optional kömək
yanaşmasını istifadə edəcək. Porch skan icazəsi ilə ACME təsdiqi eyni deyil:
yalnız CA order-dən gələn düzgün TXT və CA nəticəsi certificate issuance-a
əsas ola bilər. DNS provider API inteqrasiyası ayrıca mərhələ olaraq qalır.
Manual DNS hazırlığı PR #85-ə daxil deyildi; ayrıca ADR 0054 increment-i ilə
tamamlanır. Porch repository-sinə dəyişiklik yoxdur.

## Məhsul prinsipi

**Cari dalğa — 2026-10-26 istifadəçi qərarı:** avtomatlaşdırma işləri hər kiçik
addımdan sonra yeni “davam edək?” gözləmədən ardıcıl aparılır. Hazır sessiya
çərçivəsi seçilib: çıxış/kilid/restart dayandırır, maksimum 12 saat uzadılmır;
24/7 üçün diskə parol və ya müstəqil unlock açarı yazılmır. Real DNS/CA/domain/
terms əməliyyatı və production buraxılışı ayrıca operator səlahiyyəti olaraq qalır.
Hər increment-in imzalı PR/bütün CI/self-review qapısı dəyişmir.

**Cari increment — ADR 0074:** dəqiq saxlanmış staging sertifikatına bağlı şifrəli
renewal vaxtı, eyni window üçün dəyişməyən seçim, persisted error/provider wait,
intent-before-I/O və Linux writer/one-use lease. Pending read ayrıca lokal
retirement olmadan təkrarlanmır; wait/count qalır. Tam backup/parol bərpası,
DNS/issuance ilə toplanan ehtiyatlar və refusal/sabotage/fuzz yoxlanır. Hələ live
ARI adapter/route, yeni UI formu və worker yoxdur. Sonrakı increment bütün CA
əməliyyatlarına provider wait qapısı və fresh parol/razılıqla sadə UI-dir;
ardınca hazır sessiya worker/pause gəlir. Bütün avtomatlaşdırma bitmiş deyil.

**Sadəlik qəbul meyarı:** növbəti UI istifadəçidən ARI/window/lease anlayışı
tələb etməyəcək. Default görünüşdə yalnız növbəti yenilənmə vaxtı, varsa
gözləmə/dayanma səbəbi və bir uyğun növbəti addım olacaq; texniki detallar
bağlı Details altında qalacaq. Ayrı menyu və təkrar ayar formaları artırılmır.
Sadələşdirmə real trust/expiry/error vəziyyətini gizlətməyəcək.

**Tamamlanan increment — ADR 0073 (PR #104, 13/13 yoxlama, merge `863b2f9`):** daxili, unexported staging ARI iki-GET protokolu;
fixed source/path, public ID, pinned DNS/TLS, no proxy/redirect/retry/credentials,
8s/header/body/JSON və təkrar permission/expiry. Fake TLS/refusal/sabotage/fuzz;
runtime consumer/route hələ bağlıdır. Mövcud overview-da qeyri-adi imported DNS
adları bounded etiketə keçir, manual status/DER dəyişmir. Sonra source-bound
intent/result/selection/error-wait custody və explicit UI, ardınca session worker.

**Tamamlanan increment — ADR 0072 (PR #103, bütün 13 yoxlama, merge `82631eb`):** bounded offline ARI parsing/Retry-After və error
policy, standard ASN.1 ilə certificate ID, random half-open-window seçim və
mövcud backoff-un üstünlüyü. Actual lifetime/short-lived fallback, stale/expired/
future/entropy refusal və fuzz/sabotage. Hələ runtime consumer, live ARI, persisted
job/schedule və scheduler/UI authority yoxdur. Sonra pinned staging read və dəqiq
sertifikata bağlı şifrəli seçim; ardınca hazır-sessiya worker/pause/failure UI.

**Tamamlanan increment — ADR 0071 (PR #102, bütün 13 yoxlama):** eyni tam authenticated image-dən read-only renewal
overview: qalan və reserved capacity, DNS maintenance/unknown/wait/cleanup,
request növbəti addımı, lokal actual-lifetime reminder və superseded pair ayrılığı.
Bu, avtomatik yeniləmə, ARI provider sorğusu, retention/pruning və ya yeni retry
səlahiyyəti deyil. Ardınca bounded ARI/schedule policy, scoped session worker və
pause/failure UI ayrıca icra edilir; dalğa bu increment-lə tamamlanmış deyil.
Merge `ec0628d`, verified signature, actual Linux recovery/API smoke və tam
shuffled race keçib.

**Tamamlanan increment — ADR 0070:** PR #101 bütün 13 yoxlama ilə merge
edilib. Adi altı cəhddən sonra ayrıca, maksimum
altı read-only bərpa yoxlamasını eyni writer/intent/lease/UI axınına əlavə edir.
Hər phase üçün ayrı persisted wait/count, bütün qalan intent/outcome ehtiyatı;
heç bir POST/DELETE, reset və ownership abandonment yoxdur. Invalid provider-hint
ilə blocked scope, bərpa limitinin dolması və capacity çatışmazlığı fail-closed
qalır. Bu, operator recovery/history-capacity mərhələsinin ilk hissəsidir;
ümumi mərhələ, scheduler və production tamamlanmış deyil. Real DNS/CA və Porch
scope xaricindədir. Sonra blocked/indefinite unknown və retention siyasəti qalır.

**2026-10-13 visibility maneəsi aradan qalxdı:** istifadəçinin icazəsi ilə
yalnız `denyfirst/rootwell` yenidən public edildi. GitHub API-si PUBLIC statusunu,
ruleset 23751134-ün active/no-bypass/strict checks/required signatures/merge-only
qaydalarını və secret scanning/push protection enabled vəziyyətini təsdiqlədi.
Heç bir check silinmədi və ödənişli xidmət aktivləşmədi. Aşağıdakı private
məhdudiyyət tarixi qeyddir; ADR 0063 yeni exact-head CI nəticəsi olmadan merge
edilmir. Porch dəyişməz qalır.

**2026-10-12 istifadəçi visibility qərarı:** `denyfirst/rootwell` private edildi;
Porch dəyişmədi. GitHub Free private repo-da ruleset API-si 403 qaytarır və code
scanning entitlement yoxdur. Heç bir qayda/check silinmir və yoxlama keçilmiş
sayılmır. Məcburi exact-head CI/ruleset/CodeQL qapısı təmin edilmədən merge yoxdur;
uyğun GitHub imkanları və ya ayrıca təsdiqlənmiş workflow qərarı tələb edilir.

**Əvvəlki dalğa — retry + Cloudflare DNS:** istifadəçi hər ikisini təsdiqləyib,
ilk DNS provayderi kimi Cloudflare seçib. PR #97–100 tamamlanıb; sonrakı ADR 0070
read-only bərpa increment-i yuxarıda göstərilib.
Porch scope xaricindədir, real CA/DNS əməliyyatı və ya secret import icazəsi deyil.

**Tamamlanan increment — ADR 0069 (PR #100):** eyni Linux writer-lock altında credential/intent/
one-use lease/Cloudflare/result və ayrı cleanup retry transaction-ı; eyni Automation
kartında optional bir-domain add/check/cleanup UI. Fresh parol, explicit razılıq,
cleanup üçün exclusive editing, shared auth/provider/KDF budget, tam qalan
transition/byte/issuance ehtiyatı. Expiry yeni create-a icazə vermir, read/cleanup
dayanmır. Borrowed silinmir, creating/deleting replay olunmur; blocked/exhausted
reset yoxdur və manual provider/reviewed maintenance lazım ola bilər. Lokal
model/API/UI/negative/sabotage və read-only fake browser yoxlanır; actual Linux/
race/full recovery, bütün exact-head CI və ayrıca maintainer self-review merge
qapısıdır. Real token/DNS/CA, scheduler, production və Porch scope-da deyil.

2026-10-23 təkrar govulncheck Go 1.26.9-da crypto/x509 üçün reachable
GO-2026-6809 tapdı. Module minimum və digest-pinned official Docker build image
1.26.10-a keçirilir; bütün yoxlamalar patched toolchain ilə təkrarlanır. İstisna,
scan bypass və hostun global Go quraşdırmasını dəyişmək yoxdur.

### İlk certificate-lifecycle buraxılışına qədər qalan yaxın sıra

1. ADR 0069 tamamlanıb (PR #100, bütün 13 yoxlama). UI demo real provider sınağı deyil.
2. DNS-də blocked/exhausted və unknown nəticələr üçün ayrıca reviewed operator
   bərpa axını və history/capacity siyasəti. Ownership səssiz atılmır, POST/DELETE
   replay və köhnə backup-la reset yoxdur. Bu, scheduler-dən əvvəl həll olunur.
3. ARI renewal-window və hazır sessiya çərçivəsində bounded scheduler/pause/
   visible failure. Hazırkı 12 saatlıq açılma uzanmır; 24/7 unattended unlock
   ayrıca credential/authority qərarı olmadan əlavə edilmir.
4. Ayrı identity/trust və explicit səlahiyyətlə production ACME dəstəyi;
   operatorun xüsusi test domeni və məhdud tokeni ilə staging/provider real
   inteqrasiya sınaqları. EAB/başqa CA uyğunluğu ayrıca profil və test tələb edir;
   bu plan real customer DNS/production çağırışına icazə vermir.
5. Docker/quraşdırma/upgrade/HTTPS-access sərhədləri, tam backup/restore məşqi,
   istifadəçi təlimatı və release-candidate end-to-end yoxlaması. Sonra müstəqil
   audit, tapıntıların həlli və re-test; bundan əvvəl production release yoxdur.

Bu minimuma SSH/PGP/PAM, yeni CA yaratma və avtomatik server deployment agenti
qatılmır. Onlar bu buraxılışın bitmə meyarını sonsuz genişləndirmir; ayrı məhsul/
sonrakı capability mərhələləridir. Nüvənin hazır olması bütün platformanın və ya
production avtomatlaşdırmasının bitməsi demək deyil; dəqiq faiz/tarix vədi yoxdur.

**Tamamlanan increment — ADR 0068 (PR #99):** CA-nın saxlanmış sorğusundan və dəqiq Cloudflare
ayarından alınan şifrəli DNS planı; ayrı 128-bit owner marker-lər, persisted
attempt/wait, crypto jitter, exact-image bir dəfəlik handle və restartda read-only
istiqamət. Naməlum cəhd expiry/closure ilə itmir; cleanup minimum capacity və
issuance ehtiyatı toplanır. Tam backup/parol bərpası, Linux writer/fault/permission
və model/sabotage/fuzz/CI qapıları. Hələ token borrower/live connector/yeni DNS
düyməsi yoxdur. Növbəti: eyni lock altında connector/result/cleanup transaction,
sonra fresh parol/razılıqla sadə DNS əməliyyat UI-si. Porch-a toxunulmur.

**Tamamlanan increment — ADR 0067 (PR #98, 13 yoxlama keçib):** istifadəçi tokenin yalnız öz Rootwell-də şifrəli
saxlanmasını təsdiqlədi. Eyni Automation kartında optional Cloudflare ayarları:
status, fresh parol/razılıqla save/replace/remove, ayrı purpose encryption,
tam image/backup/parol bərpası və private writer. Token/digest/zone ID statusda
yoxdur; save Cloudflare-ə qoşulmur və DNS dəyişmir. Açıq certificate request
olanda mövcud token dəyişdirilmir/silinmir. Windows önbaxış fake/read-only-dir;
real Linux custody/API/race exact-head CI qapısındadır. DNS job/ownership/retry
intent və lease/cleanup transaction növbəti increment-dir; tam automation deyil.

**Tamamlanan increment — ADR 0066 (PR #97, 13 yoxlama keçib):** bounded retry siyasəti və daxili Cloudflare TXT
protocol nüvəsi. Exponential wait/jitter, provider Retry-After və attempt limit;
dəqiq zone/record, yalnız TXT, write-dan əvvəl intent callback, borrowed qeydi
silməmək, unknown create üçün yalnız read, owned cleanup və fake TLS/refusal/
sabotage/fuzz. Hələ exported/live route, token custody, durable retry/job, yeni
UI və scheduler yoxdur; runtime CA cooldown və V8 dəyişməzdir. Tam DNS
avtomatlaşdırması tamamlanmış deyil. İmzalı PR/CI/self-review/merge qapısı qalır.

**Ardınca dayanmadan görüləcək uyğun sıra:**

1. Şifrəli provider konfiqurasiyası və order-bound DNS ownership/retry intent;
   exact generation/writer/permission, reserve, tam backup/password recovery.
2. Opaque leased connector transaction: intent-before-I/O, uncertain read-only
   nəticə və atomik commit; bütün owned qeydlər üçün cleanup/closure siyasəti.
3. Eyni Automation UI-də sadə configure/add/check/cleanup, fresh parol/razılıq,
   manual alternativ və late/hidden/source/clock/limit refusal; browser demo.
4. ARI renewal-window/scheduler və scope-lu unlock ayrıca qərar; indiki 12 saatlıq
   ready sessiya uzadılmır. Hər increment ayrıca test/signed PR/all-CI/self-review.

**Əvvəlki increment — ADR 0065 (PR #96, bütün 13 yoxlama keçib):** manual test yeniləmənin nəticəsi eyni Automation
kartında: əvvəlki/yeni bitmə tarixləri, köhnə cütün/qeydlərin qaldığı və yeni
cütün ayrıca saxlandığı. Tam şifrəli image/revision/generation yoxlanır, public
Compare nüvəsi tarixləri hesablayır. Eyni/daha qısa ömür “əlavə vaxt” deyil;
current trust/revoke/deploy yoxlanmış sayılmır. V8 bounded read-only xülasə,
private data/endpoint/dependency/format dəyişmir. Pending/deleted/closed/ordinary
scope-da aktiv nəticə yoxdur. Local/model/VM/sabotage/browser → signed PR → bütün
exact-head CI → ayrıca self-review → merge. Sonra ARI/backoff siyasəti və scoped
DNS avtomatlaşdırması ayrıca qapılardır; prod/audit hələ yoxdur.

**Əvvəlki increment — ADR 0064 (PR #95, bütün 13 yoxlama keçib):** Certificates-də saxlanmış Rootwell staging
sertifikatından explicit manual yeniləmə. Server eyni domenləri yoxlanmış
completion-dan götürür; istifadəçi köhnə sorğunu ayrıca bağlayır, sonra fresh
parol/razılıqla yeni sorğu yaradır. Köhnə cüt/qeydlər qalır, yeni açar müstəqildir,
yeni sertifikat ayrıca yoxlanıb saxlanır. Source/link/clock/generation və tam
bərpa yoxlanır; aktiv source silinmir. V7 bir Automation kartı və read-only fake
browser nümunəsidir. Imported/production/başqa CA renewal, auto retry/scheduler/
ARI/DNS/deploy deyil. Model/VM/sabotage/fuzz və pinned gates → imzalı PR → bütün
exact-head CI → ayrıca self-review → merge. Sonra manual renewal nəticə UX-i,
ARI/backoff və ən sonra scoped DNS avtomatlaşdırması ayrıca qapılardır.

**Əvvəlki increment — ADR 0063 (PR #94, bütün 13 yoxlama keçib):** tamamlanmış və ya məlum müddəti bitmiş sorğunu
fresh parol/razılıqla lokal bağlayıb ayrıca yeni sorğuya yer açmaq. Pair/açar/
mənbə/qeydlər qorunur; naməlum və aktiv sorğu, köhnə URI və lease bloklanır.
32 məhdud şifrəli closed scope səssiz silinmir, tam bərpa və pair silmə ilə
uyğun qalır. V6 eyni kartda sadə “Prepare a new request” axınıdır; bu CA-da
cancel/revoke deyil. Model, VM, iki istiqamətli sabotage, fuzz və pinned local
qapılar keçib; Linux real storage/API/race və ayrı self-review exact-head CI/PR
qapısındadır. Browser nümunəsi read-only saxtadır, real CA əməliyyatı deyil.
Növbəti iş ayrıca manual yeniləmədir; avtomatik yeniləmə/DNS hələ hazır deyil.

**Cari dalğa — istifadəçi dörd hissəni təsdiqləyib:** CA domen yoxlaması →
sertifikat issuance və pair storage → manual yeniləmə → DNS avtomatlaşdırması.
Hər increment ayrıca test/imzalı PR/self-review/CI qapısından keçir; real CA/DNS
əməliyyatı və production icazəsi deyil. Bütün dalğa tamamlanmış sayılmır.

**Əvvəlki increment — ADR 0062 (PR #93):** Automation UI-də explicit fresh parol/razılıqla
test sertifikatı almaq və eyni sifarişin nəticəsini yalnız oxumaq. Bir writer-lock
altında intent → exact lease → bounded CA → pinned yoxlama → atomik pair.
V5 status müddət qısalmasını saxlayır; itmiş cavabda resend/new key yoxdur.
Windows browser nümunəsi fake/read-only-dir, real CA çağırışı edilmir.
Tam local/CI/self-review qapıları tələb edilir; renewal, DNS və production audit
sonrakıdır. Bitmiş/expired sifariş üçün ayrıca yeni sorğu ADR 0063-dədir.

**Əvvəlki increment — ADR 0061:** verilmiş staging sertifikatını pinned qəbul
nüvəsində yenidən yoxlayıb eyni private açarla atomik Certificates saxlamaq.
Açar hazırlıq qeydindən matched material-a keçir; immutable test-only mənbə,
metadata/export/deletion və tam bərpa sərhədi var. V4 status/UI pending, saved və
deleted vəziyyətlərini ayırır, test-only kartı real browser-də read-only saxta
nümunədə göstərilir. Hələ canlı connector/lease/fetch/commit inteqrasiyası və
issuance düyməsi yoxdur, can_issue false qalır. Növbəti increment həmin tam
axını fresh parol/razılıq/provider budget və sadə interactive UI ilə bağlamaqdır.
Tam issuance, manual renewal və DNS adapter-ləri bitmiş sayılmır.

**Tamamlanan increment — ADR 0060:** şifrəli issuance niyyəti və bir dəfəlik daxili
səlahiyyət. Linux writer-lock altında niyyət callback-dən əvvəl atomik yazılır;
yarımçıq nəticə, restart və tam bərpa eyni key/CSR/sifariş üçün yalnız oxuma
imkanı saxlayır. Sonrakı sertifikat üçün history/generation/record/byte ehtiyatı
qorunur. Hələ live CA çağırışı, yeni issuance düyməsi və atomik pair yoxdur;
can_issue false qalır. Növbəti increment receipt-in lock altında təkrar yoxlanması,
atomik Certificates pair və immutable test-only provenance; sonra fresh parol/
razılıqla sadə UI inteqrasiyası. Tam issuance və sonrakı renewal/DNS hazır deyil.

**Tamamlanan increment — ADR 0059:** eyni saved sifariş və exact CSR üçün bounded ACME
finalize/fetch protocol komponenti. Bir finalize, read-only reconciliation,
processing-də avtomatik polling-in I/O-dan əvvəl rəddi, strict public PEM və
sabit limitlər fake TLS CA ilə sınanır. Hələ daxili/unexported komponentdir;
live route, atomik pair və UI inteqrasiyası yoxdur. Durable intent ADR 0060-dadır.
can_issue false qalır. Sonra intent/locked lease, receipt recheck, atomik pair,
test-only provenance, full recovery və sadə UI birlikdə bağlanmalıdır. Issuance
dalğası, manual renewal və DNS avtomatlaşdırması tamamlanmış sayılmır.

**Tamamlanan increment — ADR 0058:** CA cavabını qəbul edən lokal daxili yoxlama nüvəsi:
eyni key/CSR və dəqiq domenlər, leaf/usage/time/algorithm və tam ordered chain.
Trust cavabdan və ya system store-dan deyil, ayrıca reviewed/pinned dörd staging
root-dan gəlir; test-only qalır. Şəbəkə, finalize, yazma və yeni UI düyməsi yoxdur;
can_issue false qalır. Bu issuance dalğasının yalnız receipt-validation hissəsidir.
Sonra durable intent, eyni CSR ilə bounded finalize/same-order reconciliation,
writer-lock altında təkrar yoxlama, atomik Certificates pair və aydın staging
etiketi birləşdiriləcək. Manual renewal və DNS avtomatlaşdırması bundan sonradır.

**Tamamlanan increment — ADR 0057:** CA-ready və bütün authorization-valid nəticələri
təsdiqləndikdən sonra, onların müddəti bitmədən fresh parol və ayrıca razılıqla
bir yeni P-256 certificate key və
dəqiq domenlərə bağlı imzalı CSR lokal hazırlanıb şifrəli saxlanır. Təkrar
klik açarı dəyişmir; tam password/recovery backup və parol bərpası eyni açar
və CSR-i qoruyur. Eyni Automation kartı, şəbəkə yoxdur, can_issue false qalır.
Bu issuance dalğasının custody hissəsidir, sertifikat hələ alınmır və
Certificates-də yeni qeyd yaranmır. Sonra eyni CSR ilə explicit CA finalize,
qeyri-müəyyən nəticənin eyni sifarişdən reconciliation-u, müstəqil staging trust,
key/name/time/policy yoxlamaları və atomik pair storage gəlir. UI VM sınağı
canlı browser QA deyil; production/müstəqil audit ayrıca qalır.

**Tamamlanan increment — ADR 0056:** eyni sifariş üçün fresh parol və açıq razılıqla
CA DNS yoxlaması; ayrıca read-only nəticə refresh-i. Hər cəhdin niyyəti əvvəl
şifrəli saxlanır, əvvəlki uğur nəticəsi səlahiyyət kimi qalmır. Bütün domen və
acknowledged TXT-lər uyğun gəlmədən heç bir challenge qəbul edilmir. Natamam
cavabdan sonra Accept təkrarlanmır; yalnız eyni sifariş oxunur. CA-ready və bütün
authorization-valid nəticələri birlikdə tələb edilir; issuance hələ yoxdur.
Sonra yeni certificate key/CSR, issuer/trust/time/key/name yoxlamaları və tam
atomik Certificates saxlanması; daha sonra köhnə cert-i qoruyan manual renewal.
DNS avtomatlaşdırması ümumi nüvə üzərində provider adapter-lərlə gələcək;
lego/dependency/provider scope ayrıca review tələb edir. Manual TXT alternativi
qalır. DenyFirst vasitəçi serveri yoxdur, hər outbound istifadəçinin öz instance-indəndir.

**Tamamlanan increment — ADR 0054:** bir staging DNS sifarişi, CA-dan gələn TXT
təlimatı və ayrıca istifadəçi təsdiqi. Domenlər yalnız açıq razılıq/fresh parol
ilə staging-ə gedir. Niyyət şəbəkədən əvvəl, sifariş ünvanı cavab gövdəsindən
əvvəl şifrəli saxlanır; yarımçıq nəticə yalnız eyni sifarişdən davam edir.
Ünvan alınmayıbsa yeni sifariş/təkrar cəhd bloklanır. Type / Name / Value;
apex və wildcard üçün eyni adda iki dəyər itmir. İstifadəçinin təsdiqi CA/DNS
verification deyil. Tam backup/bərpa sifariş və eyni hesab açarını qoruyur.
Linux/Docker development; testlər fake TLS CA + UI VM-dir, canlı browser QA
deyil. Növbəti increment CA yoxlamasını başlatmaq, nəticəni təhlükəsiz izləmək,
sonra yeni certificate key/CSR və verilmiş sertifikatı Certificates-də saxlamaqdır.
Production/müstəqil audit ayrıca qalır. Yeni/bitmiş sifariş siyasəti və itmiş
ünvanın reconciliation-u production-dan əvvəl tamamlanmalıdır.

**Tamamlanan increment — ADR 0053:** eyni şifrəli staging account açarı ilə cari
terms-link preview, explicit razılıq və fresh paroldan sonra registration.
Şəbəkədən əvvəl durable pending yazılır; qeyri-müəyyən nəticə yalnız həmin
açarla ayrıca reconciliation edilir. Certificate order/issuance hələ yoxdur.
Növbəti increment: manual DNS-01 order, domenə bağlı real TXT təlimatı və
istifadəçinin qeydi yerləşdirdiyini ayrıca təsdiqləməsi. Production və
müstəqil audit ayrıca qapıdır; aşağıdakı əvvəlki increment-lər tarixi sıradır.

**Tamamlanan increment — ADR 0050:** ayrıca explicit təsdiqlə staging directory-yə
bir təhlükəsiz GET. Domen/key göndərilmir, account/sertifikat yaradılmır, heç nə
saxlanmır. TLS, DNS/IP pinning, redirect/proxy/retry rəddi, limit/cooldown,
saxta TLS CA və UI/session refusal sınaqları. Real bağlantı Linux/Docker üçündür;
native Windows/macOS əlavə OS şəbəkə yoxlaması riski səbəbilə offline preview qalır.
Həmin mərhələnin növbəti işi Linux-da
şifrəli staging account custody + explicit ToS/reauth və qeyri-müəyyən
registration nəticəsinin təhlükəsiz reconciliation-u; sonra manual DNS issuance.

**Tamamlanan increment — ADR 0049:** Automation daxilində şəbəkəsiz ACME staging
setup yoxlaması: domenlər + manual DNS/HTTP üsulu. Heç nə saxlanmır, CA-ya
göndərilmir, account/key/challenge/sertifikat yaradılmır. Sadə UI, strict API,
sessiya/origin və gecikmiş cavab sərhədləri test olunur. Sonra ayrıca reviewed
client/transport + fake CA, encrypted account və manual DNS issuance mərhələləri
gəlir; [təhlükəsizlik planı](ACME-THREAT-MODEL.md) həmin qapıları müəyyən edir.

**Tamamlanan increment — ADR 0048:** açarsız saxlanmış sertifikata sonradan private
key əlavə etmək; optional Check, fresh Rootwell parolu və Save. Sertifikat,
bundle, qeydlər və import tarixi dəyişmir. Mövcud açar əvəz edilmir; mismatch
yalnız explicit təsdiqlə loose attachment olur. Details → Convert format
yalnız public sertifikatı mövcud Workbench Convert-ə açır. Secret avtomatik
ötürülmür; key/PFX üçün şifrəli key download və explicit seçim qalır. Linux
storage/restore, refusal, UI və sabotage sınaqları + bütün CI/self-review
qapılarından sonra növbəti iş ACME staging/account/challenge sərhədini
planlamaqdır; bu increment real CA/domain enrollment etmir.

**Əvvəlki UX increment — ADR 0047:** Inspect-də lokal certificate/key match;
Certificates-də bir sertifikat/bundle və ya eyni chain-in ayrı public faylları
+ optional key + qeyd + Save. Check optionaldır, Save həmişə yoxlayır. Mismatch
yalnız explicit təsdiqlə ayrı attachment olur; matching pair deyil. Əsas
sertifikat ambiguous olsa seçilir. Bulk unrelated import Advanced altındadır.
Public bundle və şifrəli key-only download əlavə olunur; Linux full restore
bundle, açar və hesablanmış statusu birlikdə saxlamalıdır. Əvvəlki ADR 0046
matched-only giriş məhdudiyyəti bu qərarla əvəzlənir.

Əvvəlki prioritet: **vahid Certificates kitabxanası** (ADR 0046). Certificate seç,
istəsən private açar seç, uyğunluğu yoxla, istəsən servis qeydi yaz və Save.
Siyahıda vaxt və key-present vəziyyəti; private download üçün fresh password.
İnventory/Vault ayrı istifadəçi bölmələri deyil. SSH/PGP/browser remote access
Rootwell-dən çıxarılıb; əvvəlki plan qeydləri tarixi kontekstdir.

Bu increment-də Linux custody/restore/API və UI refusal testləri, şifrəli pair
download, public-only compatibility və iki istiqamətli sabotage sübutu tələb
olunur. Native Windows yalnız read-only preview-dir. Növbəti uyğun mərhələ:
mövcud sertifikata sonradan açar əlavə etmə və Workbench download formatlarına
aydın handoff; daha sonra ACME account/challenge threat model. Production və
müstəqil audit ayrıca release qapısıdır; tamamlanmamış işi hazır saymaq olmaz.

Sertifikat terminlərini bilməyən istifadəçi üç suala cavab almalıdır:
**Nə yüklədim? Nə hələ sübut olunmayıb? İndi nə etməliyəm?** Sadə görünüş
texniki işi gizlətməməlidir: CA flag, imza əlaqəsi, etibar mənbəyi və real
verification ayrı vəziyyətlər olaraq qalır. Uğur hissi yaratmaq üçün sübut
olunmamış nəticəyə “verified” demək qadağandır.

## Tamamlanan və növbəti increment-lər

1. **Guided Certificate Health — tamamlanıb (PR #27).** Explore-da public fayllar
   üçün insan dilində xülasə; bir mümkün sayt sertifikatı olduqda istifadəçi
   klikiylə həmin faylların Verify Simple-a təhlükəsiz ötürülməsi; sıfır və ya
   birdən çox namizəd olduqda seçim etmədən yol göstərilməsi; Verify
   xətalarına sabit “növbəti addım” mesajları. Handoff faylları yenidən
   oxumalı, Explore fingerprint-ləri ilə müqayisə etməli, hostname və ayrıca
   root tələb etməlidir. Private key, PFX, upload, storage və avtomatik trust
   əlavə edilmir.
2. **Mümkün zənciri aydın göstər — tamamlanıb (PR #28).** Mövcud imza
   yoxlanmış issuer əlaqələrini “kim kimi imzalaya bilər?” şəklində göstər;
   birdən çox namizəd və çatmayan əlaqəni gizlətmə. Bu yalnız köməkçi vizual
   izahdır, verified path deyil.
   Çıxış meyarı: eyni fayllar başqa sırada verilsə də heç bir root özü-özünə
   trusted olmur; ambiguity və natamamlıq testlidir.
3. **Public health report — tamamlanıb (PR #29).** İstifadəçinin ayrıca
   klikiylə yalnız public metadata, vaxt pəncərəsi, certificate fingerprint-ləri
   və yoxlamanın sərhədləri olan lokal JSON hesabat. Secret və key export-u
   yoxdur; browser-managed download və input recheck testlərlə qorunur.
4. **Instance access təməli (PR #31) və lokal giriş qapısı (PR #32).** Hər qurulum üçün
   ayrıca təsadüfi ilkin parol yalnız setup üçündür; parol dəyişənə qədər data
   açarı və Workbench verilmir. `rootwelld init` parolu yalnız lokal interaktiv
   terminalda göstərir. `localhost` gateway setup-only sessiya verir; uğurlu
   dəyişmə bütün sessiyaları bağlayır və yeni parolla yenidən giriş tələb edir.
   Bu hələ production remote access və vault deyil. Access faylı kənardan
   dəyişəndə köhnə sessiyanın rəddi ayrıca sərtləşdirilib (PR #33).
   Daemon/Docker loguna parol yazılmır.
5. **Linux public inventory mərhələsi.** Public certificate üçün RAM modeli,
   şifrəli tam-image manifest, private-file transaction, access + inventory
   tam snapshot/restore və ayrıca self-hosted UI/API hazırlanıb. Import yalnız
   istifadəçi Save klikiylə öz lokal daemonuna gedir; offline Workbench
   sərhədi dəyişmir. Owner/location, import sırası, server saatına görə save
   vaxtı və browser saatına əsaslanan expiry göstərilir; bu audit log,
   bildiriş, trust və renewal deyil. Sərhəd
   [`INVENTORY-THREAT-MODEL.md`](INVENTORY-THREAT-MODEL.md) sənədindədir.
   Linux Docker üçün ayrı data/backup mount-ları, şəbəkəsiz interaktiv
   maintenance və disposable volume-dan təmiz volume-a CI bərpa məşqi əlavə
   edilib; bu avtomatik backup və production deployment deyil. Windows native
   support və müstəqil release auditi ayrıca qalır. Image-local generation
   xarici rollback anchor-u deyil.
   Eyni public certificate-ə duplicate DER yaratmadan 32-dək manual, ayrıca
   yoxlanılmamış istifadə yeri bağlamaq mümkündür. Stale generation, eyni yer
   və naməlum fingerprint rədd edilir; əvvəlki import tarixi/sırası qorunur.
   Bu canlı server yoxlaması və ya deployment sübutu deyil. Public metadata
   belə daxili adları aça bilər; network discovery yoxdur. Sonrakı UX
   increment-ləri təhlükəsiz metadata redaktəsi/silmə və expiry prioritetidir.
6. **Secret-bearing conversion / vault.** İlk qərar və təhlükə modeli
   [`ADR 0029`](adr/0029-secret-bearing-conversion-sequence.md) və
   [`SECRET-CONVERSION-THREAT-MODEL.md`](SECRET-CONVERSION-THREAT-MODEL.md)
   sənədlərindədir. Public-only CLI PEM/DER çevirməsi ayrıca sərhədlə
   tamamlanıb. [`ADR 0030`](adr/0030-pkcs12-dependency-and-profile.md)
   PKCS#12 dependency/profil qərarını və Linux offline PFX yaratma sərhədini
   qeyd edir. [`ADR 0031`](adr/0031-bounded-pfx-public-inspection.md) dar modern
   profil üçün yalnız public PFX xülasəsini əlavə edir; public hissələri
   fingerprint ilə ayrı PEM/DER faylına çıxarmaq və Linux offline CLI-da uyğun
   key-i yalnız yeni şifrəli PKCS#8 faylına çıxarmaq əlavə edilib. İlk UI
   private-key conversion increment-i [`ADR 0034`](adr/0034-browser-encrypted-private-key-conversion.md)
   ilə ayrıca sərhəddə başlayıb: unencrypted PKCS#8/PKCS#1/SEC1 PEM/DER qəbul edir.
   [`ADR 0035`](adr/0035-browser-encrypted-key-import-and-plaintext-export.md)
   limitli şifrəli PKCS#8 importunu və açıq təsdiqlə parolsuz uyğun formatları
   əlavə edir; default yenə şifrəli PKCS#8-dir. [`ADR 0037`](adr/0037-browser-pfx-worker-and-conversion.md)
   ilə dar modern profil üçün browser PFX yaratma, public hissələri çıxarma və
   uyğun private key-i yalnız şifrəli PKCS#8 kimi çıxarma əlavə edilib. Key
   reveal ADR 0039 ilə ayrıca, 30 saniyəlik görünüşdür; vault custody yoxdur.
   ADR 0038 şifrəli key-dən PFX yaratmanı tamamlayıb (PR #69).
   Müstəqil xarici audit
   development-i saxlayan qapı yox, ilk release/real-user istifadəsi üçün
   son qapıdır; hər increment-in daxili təhlükəsizlik yoxlamaları qalır.

   **Növbəti funksional sıra:** ADR 0036 worker/deadline sərtləşməsi və ADR 0037
   dar modern browser PFX axını tamamlanıb. ADR 0038 PFX yaratmaq üçün şifrəli
   PKCS#8 giriş key-ini parolla birbaşa qəbul edib uyğunluğunu worker-də yoxlayır;
   aralıq parolsuz fayl endirməsi tələb edilmir. ADR 0039 əvvəlcədən
   razılaşdırılmış məhdud **gözlə göstərmə** axınıdır və PR #70 ilə tamamlanıb.
   ADR 0040 browser-də key + CSR yaratma, imzalı CSR PEM/DER açma/çevirmə və
   geri gələn sertifikatı həmin public key/CSR adları ilə müqayisə etmə
   axınıdır. Bu dalğanın yoxlamaları bitmədən növbəti məhsul bölməsinə keçmirik.
   Müəyyən məhsul/versiya reseptləri ümumi format
   mühərrikinin üzərində ayrıca gələcək; heç bir universal vendor rejimi yoxdur.
   Browser reveal hər dəfə PFX parolunu yenidən istəməli, saxlanmış key üçün
   əlavə instance reauthentication tələb etməli, qısa müddətdən sonra mətn
   sahəsini təmizləməli və heç nəyi log/history/URL/localStorage-a qoymamalıdır.
   Bu tədbirlər zərərli browser extension və komprometasiya olunmuş hostdan
   tam müdafiə vədi deyil. Hər real browser increment-i istifadəyə yararlı
   sintetik demo faylı ilə göstərilməlidir; CLI xüsusiyyəti web-də varmış
   kimi təqdim edilməyəcək.

### Növbəti funksional dalğanın qəbul meyarları

İcra vəziyyəti: şifrəli key-dən PFX (PR #69) və məhdud reveal (PR #70)
tamamlanıb. Key + CSR wizard üçün ADR 0040, unit/refusal/fuzz, WASM, worker/UI
və müstəqil Node/OpenSSL interop yoxlamaları əlavə edilib. Windows browserdə
sintetik yeni RSA key + CSR, mövcud CSR importu və eyni/fərqli sertifikat
müqayisəsi sınanıb; bütün tələb olunan CI yoxlamaları keçib və PR #71 merge
olunub. Bu sübut Linux-da faktiki browser sessiyası və ya universal
sertifikat formatı uyğunluğu demək deyil. CLI CSR, geniş vendor/legacy profil,
vault, issuance və renewal ayrıca qalır.

1. **Şifrəli key-dən PFX.** Browser UI mövcud dəstəklənən şifrəli PKCS#8
   private key, onun parolu, uyğun public sertifikat və istəyə bağlı issuer-ləri
   qəbul edir; key/cert uyğunluğu yoxlanır. Yanlış parol, uyğun olmayan key,
   qarışıq chain və limitdən böyük/malformed giriş aydın rədd olunur. PFX
   parolu ayrıca seçilir; private key aralıq parolsuz fayl kimi endirilmir.
   Mövcud dar modern profil qorunur və real interop fixture-ləri ilə sərhəd
   ayrıca ölçülür; hər PFX vendor variantına dəstək iddia edilmir.
2. **Məhdud key reveal.** Yalnız istifadəçinin açıq istəyi ilə, uyğun fresh
   parol/reauth-dan sonra qısa müddətli göstərmə; avtomatik gizlətmə və
   navigation/selection dəyişəndə təmizləmə. Heç bir secret log, history,
   URL və ya localStorage-a düşmür. PFX və gələcək saxlanan vault key-i üçün
   authentication qaydaları qarışdırılmır.
3. **Key + CSR wizard.** UI-da dəstəklənən RSA/ECDSA key yaratmaq, key-i
   şifrəli formada endirmək, SAN/subject seçib imzalı CSR almaq və CSR-i
   parse/signature qaydaları ilə yenidən yoxlamaq. CA-dan gələn sertifikatı
   həmin public key-ə uyğunlaşdırmaq; CSR yaratma issuance və ya trust deyil.
4. **Real istifadə matrix-i.** Bu axınlar üçün müstəqil alətlərlə açılıb
   yoxlanan fixture-lər, yanlış/korrupt/parol/limit sınaqları, Windows/Linux
   browser yoxlaması və istifadəçinin izləyə biləcəyi sintetik demo. Dəstəklənən
   və dəstəklənməyən formatlar UI və format cədvəlində eyni göstərilir.

Bu dalğa private-key vault, ACME renewal, deployment agent, SSH/PGP və geniş
vendor reseptlərini səssizcə əlavə etmir. Onlar ayrıca trust boundary və
məhsul mərhələləridir. Hər increment öz test/CI/self-review qapısından keçir;
müstəqil dərin audit ilk production/real-user release-dən əvvəl ayrıca qalır.

Workbench-də **Inspect** tək public sertifikatı və ya PEM bundle/çoxfayllı
kolleksiyanı eyni yerdə açır. Hər kartdan seçilmiş sertifikatın geniş
inspection sahələri mənbə yenidən yoxlanaraq göstərilir. **Convert** ayrıca
görünüşdə həmin sessiyada açılmış public sertifikatın PEM/DER endirilməsini
və seçilmiş public PEM bundle yaratmağı təklif edir; faylı birbaşa Convert-də
seçmək də eyni bounded public inspection yolundan keçir. Yeni fayl seçimi köhnə
convert seçimlərini silir. Texniki imza əlaqələri və JSON report Inspect-də
istəyə bağlı detallardadır. Public certificate axını private-key seçimindən
ayrıdır; private conversion yalnız yuxarıdakı dar sərhəddədir.

İstifadəçi inventory üçün self-hosted, lokal şifrəli saxlanma seçib: məlumat
onun öz qurulumunda, özü silənədək qalacaq; avtomatik köhnə qeydləri silmək
olmaz. İlk access modeli bir qurulumun tək operatorudur. Çoxistifadəçi rolu,
backup/recovery, disk limitində yeni yazının təhlükəsiz rəddi və audit izi
ayrıca dizayn və test tələb edir. Bu seçim persistent database, notification
və ya network discovery-ni avtomatik icazəli etmir.

## Inventory üçün yaxın icra planı

Bu, məhsulun **Mərhələ 3 — Inventory və monitoring** hissəsidir. Hər sıra
ayrıca imzalı PR və CI qapısından keçəcək; növbəti sıraya yalnız əvvəlki
sərhəd sübut edildikdən sonra keçirik.

1. **Owner qeydini düzəltmək — birinci increment.** Mövcud fingerprint üçün
   owner-i dəyişmək və ya açıq şəkildə boşaltmaq; köhnə import vaxtı/sırası,
   DER və yerlər sabit qalır. Stale tab, eyni owner, malformed input və
   icazəsiz sorğu yazmır. Dəyişiklikdən sonra yeni tam backup operatora
   xatırladılır; köhnə snapshot köhnə qeydi saxlaya bilər.
2. **Yer qeydlərini düzəltmək və silmək.** Bir manual etiketi dəqiq seçərək
   rename/remove; sertifikat və digər yerlər qorunur. Sonuncu yer silinəndə
   “unknown” açıq göstərilir. Bu serverdən certificate-i silmir və deploy
   əməliyyatı deyil. Yanlış seçimi və köhnə tabı rədd edən testlər lazımdır.
3. **Expiry prioritet görünüşü — tamamlanıb.** Browser saatının etibarsızlığını göstərərək
   expired/30/90 gün filtrləri, unknown owner/location göstəricisi və aydın
   “indi nə etməli” yönləndirməsi. Bu notification, renewal və trust hökmü
   deyil; avtomatik səssiz qərar vermir.
4. **Explicit silmə — tamamlanıb; inventory JSON export-u UI-dan çıxarılıb.**
   İstifadəçi rəyinə əsasən public metadata JSON export-u certificate export-u
   ilə qarışdığı və səhifəni ağırlaşdırdığı üçün Inventory-dən götürüldü.
   Sertifikat endirmə Workbench Explore/Verify, şifrəli tam backup isə offline
   maintenance axınında qalır. Köhnə backup-dan silinmiş data qayıda bildiyinə
   görə “tam silindi” vədi verilməyəcək.

### Server əsaslı monitoring — ADR 0041

Mövcud şifrəli public Inventory üzərində server saatına əsaslanan vahid expiry
hesablaması, oxunaqlı qalan günlər, 7/14/30/90 günlük tətbiqdaxili xatırlatma
seçimi və görünən səhifədə məhdud avtomatik yenilənmə tamamlanıb. Köhnəlmiş
nəticə, saat fərqi, giriş/şəbəkə xətası aydın göstərilir; yanlış nəticə kartları
saxlanmır. Bu fonda bildiriş xidməti deyil: səhifə bağlı olanda xəbərdarlıq
göndərilmir. Preference və axtarış yaddaşda qalır, serverdə key və alert bazası
yaradılmır. Qəbul meyarları və testlər ADR 0041/C64-dədir.

ADR 0044-dəki növbəti lifecycle dalğası hazır sessiya açıqkən server fon
yoxlamasını əlavə edir. 12 saatlıq limit, logout/restart və unlock tələbini
qoruyur; bu əvvəlki page-only increment-i 24/7 xidmətə çevirmir.

### Saxlanmış sertifikatı açmaq — ADR 0042

Inventory kartında Inspect/Verify düymələri yalnız həmin public sertifikatı
Workbench-ə açır; URL, application browser storage, popup və ikinci convert/
export UI yoxdur. Seçilən generation/fingerprint serverdə yoxlanır, DER browser
nüvəsində yenidən açılır və kimliyi müqayisə edilir. Köhnə/uyğunsuz seçim rədd
olur. Verify üçün sayt adı və müstəqil trust/root yenə ayrıca seçilir;
CA-nın verdiyi issuer fayllarını istəyə bağlı əlavə etmək olur. Bu, chain,
deployment və ya revocation-u avtomatik təsdiqləmir. Qəbul meyarları ADR 0042/C65.

### Toplu public import — ADR 0043

1–8 public PEM/DER faylını browser-də Preview edib, bütün tapılmış sertifikatları
bir Save ilə atomik saxlamaq. Dublikatlar açıq bildirilir, heç nə səssiz
atlanmır; private/mixed/malformed fayl bütün batch-i rədd edir. Save mənbələri
yenidən oxuyub fingerprint-ləri müqayisə edir; server öz parser/auth/atomic
append qaydalarını ayrıca tətbiq edir. Preview trust və ya renewal deyil.
Səhifə bağlı olanda işləyən monitoring və köhnə/yeni sertifikat müqayisəsi
bu increment-ə daxil deyil. Qəbul meyarları ADR 0043/C66-dadır.

Canlı endpoint discovery, Porch nəticələrinin importu və xarici alert-lər ayrıca
network/evidence/operational threat model-dən sonra gəlir. ACME, PFX/private
key vault, SSH/PGP və agent deployment bu mərhələyə qarışdırılmır.

## ACME-dən əvvəl public lifecycle dalğası — development implementation hazır

İstifadəçi 2026-10-06-da bu dörd işi birlikdə tamamlamağı təsdiqləyib:

1. Saxlanmış köhnə sertifikatla yeni public sertifikatın lokal müqayisəsi;
   avtomatik replacement/trust yoxdur.
2. Mövcud encrypted image və tam backup daxilində məhdud dəyişiklik tarixçəsi;
   köhnə versiyada edilməyən əməliyyatları uydurmamaq, limitdə yazını rədd etmək.
3. Daemon-da browser bağlıykən lokal expiry yoxlaması. Mövcud ready sessiyanın
   12 saatlıq açarı istifadə edilir, müddət uzanmır; logout/restart/expiry və ya
   storage xətası açıq paused/unavailable vəziyyətidir. Parol diskə yazılmır,
   email/webhook və 24/7 unattended unlock bu dalğaya daxil deyil.
4. Public-only inteqrasiya, backup/restore və UI sınağı, sintetik real browser
   nümayişi, mənfi/sabotage, platform/race və CI qapıları. ACME yalnız bu
   dalğadan sonra ayrıca qərar və implementation mərhələsidir.

Bu qarşılıqlı bağlı dəyişikliklər bir purpose-specific lifecycle increment-də
ADR 0044, imzalı PR və ayrıca adversarial self-review ilə yoxlanacaq.

Kod və local unit/refusal/sabotage/WASM/UI sınaqları hazırdır. Linux-da real
şifrəli saxlanma, browserdən asılı olmayan daemon, history full restore və race
qapısı CI-də yoxlanır; Windows browser nümayişində real WASM, sintetik read-only
history və açıq `not-running` statusu var. Merge yalnız bütün tələb olunan
yoxlamalardan sonra. Müstəqil release auditi, 24/7 unlock və history retention/
archive siyasəti ayrıca açıqdır. İstifadəçi bu dalğanı gördükdən sonra növbəti
iş ACME-nin əvvəlcə staging issuance və explicit səlahiyyət sərhədini planlamaqdır.

## Hər increment üçün dəyişməz qapılar

ACME dalğasında ADR 0049 setup, ADR 0050 optional directory connection və
ADR 0051 lokal şifrəli account-key hazırlığı ayrıdır. Sonuncu fresh parol,
bir dəfəlik təsdiq, tam backup/bərpa və mövcud açarın qorunmasını təmin edir;
CA registration/terms/issuance olduğunu iddia etmir. Sonra eyni saxlanmış açar
ilə staging registration/reconciliation, daha sonra manual DNS-01 order gəlir.

ADR 0053 registration/reconciliation increment-i eyni açar, cari terms-link
preview, fresh parol, durable pending və full restore ilə həyata keçirir.
Hələ certificate issuance deyil. Növbəti ayrıca increment manual DNS-01 order,
domain-bound challenge təlimatı və explicit provisioned acknowledgement-dır.

- Dəqiq trust boundary və “nəyi sübut etmir” qeydi.
- Uğur, rədd, malformed, stale-selection və abuse sınaqları; iki istiqamətli
  qəsdən pozma testi.
- Offline Workbench-də network/storage/secret capability artımı yoxdur;
  fərqli capability istənərsə ayrıca qərar və review.
- İmzalı commit, bütün tələb olunan CI yoxlamaları, adversarial self-review,
  merge commit. İlk public release-dən əvvəl ayrıca xarici audit.

İstifadəçidən yalnız sərhədi dəyişən qərarlar (məsələn, private key custody,
server bağlantısı, saxlanma siyasəti və ya avtomatik deployment səlahiyyəti)
üçün yeni istiqamət tələb olunur. Adi public-only UX increment-ləri bu sırayla
davam etdirilə bilər.
