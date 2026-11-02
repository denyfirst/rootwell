# Rootwell — upgrade, bərpa və release hazırlığı

**2026-11-02 · Development.** İlk public release-dən əvvəl müstəqil audit
tələb olunur. Bu təlimat audit nəticəsi və ya production hazır sertifikatı
deyil. Porch bu işin xaricindədir. İlk qurulum və konkret interaktiv əmrlər
[Docker/Linux və tam bərpa](CONTAINER-RECOVERY-AZ.md) sənədindədir.

## Hansı sübut var?

- Hər PR-da Linux container volume restart, busy-writer rəddi, ayrıca boş
  volume-a tam bərpa, şəbəkəsiz maintenance və məxfi maintenance output-un
  Docker loglarına yazılmaması yoxlanır.
- Upgrade drill platformun göstərdiyi dəqiq protected-base commit-in test
  binary-si ilə sintetik volume/backup yaradır; namizəd onu açır, daemonla
  xidmət edir və təmiz volume-a bərpa edir. Bu yalnız göstərilən iki commit
  arasındakı fixture uyğunluğudur; istənilən köhnə versiya və real data iddiası deyil.
- Yeni build qapısı eyni Git commit-dən iki ayrı source/build cache ilə CLI,
  Linux daemon, browser WASM və WASM runtime yığır, baytları müqayisə edir.
  Nəticə dəyişdirilsə və ya çıxış faylı itərsə müqayisə rədd etməlidir.
  Yalnız həmin final commit-də yaşıl CI nəticəsi sübutdur.
- Mövcud tam suite Linux storage/restore, mənfi hallar, race, statik analiz,
  signature və təhlükəsizlik invariantlarını yoxlayır.

Bu, real operator hostunda cross-version upgrade, canlı CA/Cloudflare və
müstəqil audit sübutu deyil. Docker/WSL olmayan Windows development hostuna
səssiz quraşdırma edilmir. Sintetik browser demo-da token/parol daxil etməyin.

## Upgrade-dən əvvəl

1. Cari source commit-i və işləyən binary/container image ID-ni qeyd edin.
   Köhnə image-i və onun uyğun Compose faylını saxlayın; mutable `local` və ya
   `latest` tag-ı geri dönüş üçün tək sübut saymayın. Yeni namizədin imzasını,
   dəqiq commit üzrə bütün tələb olunan yoxlamaları və build sübutunu yoxlayın.
2. Automation-da işləyən işi dayandırın, çıxış edin, daemonu dayandırın. Artıq
   göndərilmiş CA/DNS sorğusu cancellation ilə geri çağırılmır. Pending/unknown
   vəziyyəti qeyd edin; retry/reset/cleanup uğuru uydurmayın.
3. **Yeni, bənzərsiz adlı tam şifrəli backup** yaradın və offline recovery
   kodu ilə yoxlayın. `access-snapshot` certificate/key anbarını daşımır.
   Kod backup-dan ayrı yerdə qalsın; argv/env/log/chat/git-ə yazılmasın.
4. Mövcud data qovluğunu toxunulmaz saxlayın. Başqa, boş, `0700`, düzgün UID-li
   qovluğa həmin backup-ı bərpa edin. Yeni namizədi əvvəl bu nüsxədə sınayın.
   Daemon-a backup mount etməyin. Eyni volume-da iki daemon işlətməyin.

## Bərpa edilmiş namizəddə yoxlama

Əvvəl avtomatlaşdırma başlatmadan, yalnız lokal yoxlama edin:

| Səhifə/iş | Gözlənilən nəticə |
| --- | --- |
| Sign in və Access | Backup-a uyğun parol, normal giriş və çıxış; setup yarımçıqdırsa məcburi dəyişmə |
| Certificates | Eyni fingerprint-lər, uyğun private key statusu, optional bundle və servis qeydləri |
| Expiry | Cari server vaxtından yenilənən tarixlər; bu trust/revocation hökmü deyil |
| Change history | Aktiv və saxlanmış tarixçə/sorğu səhifələri, silinmə və renewal əlaqələri itmir |
| Inspect/Convert | Yalnız sintetik faylla inspect və seçilmiş formatın düzgün download-u |
| Automation | Eyni hesab/order/DNS ownership/wait/attempt/unknown vəziyyətləri; köhnə sessiya işi avtomatik başlamır |
| Tam backup | Namizəddən yeni backup və ayrıca boş qovluğa yenidən bərpa mümkündür |

İnsan parolu və açarı yoxlayarkən screen recording/screenshot paylaşmasın.
Private export yalnız məqsədli testdirsə, ayrıca output parolu və təhlükəsiz
fayl yeri seçsin. Xəta olduqda orijinalı dəyişməyin. Namizəd köhnə backup-ı
oxuya bilmirsə, onu uyğun hesab etməyin. UI-də yaşıl kart özü kriptoqrafik
sübut və ya canlı serverə deploy nəticəsi deyil.

Bütün lokal yoxlamalar keçəndən sonra orijinal qurulum üçün eyni dayandırma →
yeni tam backup → yoxlama → namizəd binary/image ardıcıllığını tətbiq edin.
Yeni giriş tələb olunur. Fon işi üçün köhnə grant daşınmır; istifadəçi yenidən
dəqiq certificate/DNS scope-u təsdiqləməlidir. Test sorğusunu avtomatik olaraq
production hesabına və ya production renewal mənbəyinə çevirməyin.

## Geri dönüş

Yeni namizəd heç nə yazmayıbsa belə, köhnə binary ilə uyğunluğu fərz etməyin.
Ən etibarlı geri dönüş köhnə binary/image + upgrade-dən əvvəl yoxlanmış tam
backup + **başqa boş data qovluğu** ilə bərpadır. Yeni image-in dəyişdirdiyi
volume-u köhnə binary-yə verməyin; saxlanmış yeni data-nı silməyin.

Backup-a qayıtmaq sonrakı import, note, key və ACME/DNS nəticələrini qaytarmır.
CA/DNS-də artıq baş vermiş əməliyyat disk rollback-i ilə geri alınmır.
Köhnə pending yazını təkrarlamaq ikiqat/naməlum iş yarada bilər. Operator
əvvəl cari provider vəziyyətini exact-scope read-only axınla reconcile etməlidir;
Rootwell bunu sıfırlayıb uğur kimi göstərməməlidir.

## Müstəqil auditə təhvil

Audit üçün bir namizəd commit seçin və dəyişiklik olarsa sübutu yeniləyin:

- Dəqiq commit, imza yoxlaması, PR-lar və həmin başlıq üzrə bütün CI linkləri.
- [Engineering](ENGINEERING.md), [təhlükə modeli](THREAT-MODEL.md),
  [access](INSTANCE-ACCESS-THREAT-MODEL.md),
  [custody](CERTIFICATE-CUSTODY-THREAT-MODEL.md),
  [ACME](ACME-THREAT-MODEL.md) və [invariantlar](SECURITY-INVARIANTS.md).
- Sabotage/refusal/fuzz/race, reproducible-build və tam restore nəticələri.
- Açıq məhdudiyyətlər: tək operator, Linux loopback, original sessiya ≤12 saat,
  disk rollback aşkarlanmır, runtime/process və host administrator sərhədi,
  canlı provider sınağının və production inteqrasiyasının faktiki statusu.

Bu siyahıya secret, real backup, token, password, recovery kodu və private key
əlavə edilmir. Auditorun tapıntılarını izləyin, düzəlişdən sonra aid yoxlamaları
təkrar keçirin və ciddi dəyişiklikləri yenidən auditə verin. Açıq material
tapıntı ilə release-i “audited” adlandırmaq və yayımlamaq olmaz.
