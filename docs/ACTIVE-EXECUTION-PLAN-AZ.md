# Rootwell — aktiv icra sırası

**Yenilənib:** 2026-09-25. Bu sənəd vaxt cədvəli və ya fon rejimində işləyən
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
4. **Inventory mərhələsinin dizaynı — növbəti iş.** Şirkət üçün owner,
   host/location, expiry, dəyişiklik tarixçəsi və bildiriş axınını threat model və
   data-retention qərarı ilə layihələndir. Public metadata belə daxili adları
   aça bilər. Gizli, davamlı yaddaş və network discovery bu addımlardan
   avtomatik yaranmır.
5. **Secret-bearing conversion / vault.** PFX və private key-lər yalnız ayrıca
   təhlükə modeli, dependency review, memory/output/file permission testləri
   və müstəqil audit qapısından sonra browser və ya server scope-una girə bilər.

Inventory koduna başlamazdan əvvəl üç qərar açıq saxlanılır: metadata harada
saxlanacaq (yalnız browser, yoxsa self-hosted server), nə qədər saxlanacaq və
kim onu oxuya/dəyişə biləcək. Bu qərarlar verilmədən persistent database,
notification və ya network discovery capability əlavə edilmir. Dizayn
variantları threat model ilə hazırlana bilər; yekun seçim istifadəçinindir.

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
