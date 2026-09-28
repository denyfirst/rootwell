# Rootwell — aktiv icra sırası

**Yenilənib:** 2026-09-29. Bu sənəd vaxt cədvəli və ya fon rejimində işləyən
avtomatlaşdırma deyil. Bir iş sessiyasında bir neçə uyğun increment ardıcıl
icra oluna bilər; hər increment ayrıca imzalı PR, test və self-review qapısından
keçir. Porch repository-si bu işin xaricindədir.

## Məhsul prinsipi

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
   qeyd edir; PFX oxuma, public hissələri çıxarma və sonra key extraction
   ayrıca increment-lərdir. Browser/server PFX və private key-ləri yalnız
   ayrıca dependency review, memory/output/file-permission testləri və daxili
   təhlükəsizlik qapılarından sonra qəbul edə bilər. Müstəqil xarici audit
   development-i saxlayan qapı yox, ilk release/real-user istifadəsi üçün
   son qapıdır; hər increment-in daxili təhlükəsizlik yoxlamaları qalır.

Workbench-də **Inspect** tək public sertifikatı və ya PEM bundle/çoxfayllı
kolleksiyanı eyni yerdə açır. Hər kartdan seçilmiş sertifikatın geniş
inspection sahələri mənbə yenidən yoxlanaraq göstərilir. **Convert** ayrıca
görünüşdə həmin sessiyada açılmış public sertifikatın PEM/DER endirilməsini
və seçilmiş public PEM bundle yaratmağı təklif edir; faylı birbaşa Convert-də
seçmək də eyni bounded public inspection yolundan keçir. Yeni fayl seçimi köhnə
convert seçimlərini silir. Texniki imza əlaqələri və JSON report Inspect-də
istəyə bağlı detallardadır. Bu yeni PFX/private-key capability-si deyil.

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

Canlı endpoint discovery, Porch nəticələrinin importu və alert-lər ayrıca
network/evidence/operational threat model-dən sonra gəlir. ACME, PFX/private
key vault, SSH/PGP və agent deployment bu mərhələyə qarışdırılmır.

## Hər increment üçün dəyişməz qapılar

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
