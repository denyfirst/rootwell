# Rootwell — aktiv icra sırası

**Yenilənib:** 2026-10-09. Bu sənəd vaxt cədvəli və ya fon rejimində işləyən
avtomatlaşdırma deyil. Bir iş sessiyasında bir neçə uyğun increment ardıcıl
icra oluna bilər; hər increment ayrıca imzalı PR, test və self-review qapısından
keçir. Porch repository-si bu işin xaricindədir.

## Məhsul prinsipi

**Cari increment — ADR 0053:** eyni şifrəli staging account açarı ilə cari
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
