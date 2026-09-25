# Certificate import, bundle explorer və Verify UX planı

**Status:** 1–8 public faylı birlikdə göstərən browser explorer və seçilmiş
bir public certificate-in PEM/DER download-u işləkdir; mümkün issuer
əlaqələri göstərilir və seçilmiş public PEM bundle export-u işləkdir;
avtomatik fullchain sırası və qəti rol/chain təyini hələ plan mərhələsindədir.
Browser Verify ayrıca seçilmiş PEM trust anchor və hostname ilə işləyir.

## İstifadəçinin yolu

Əsas ekran texniki rollarla başlamır: **"CA-nın verdiyi faylları əlavə et"**.
İstifadəçi bir `.crt`/`.cer` və ya PEM bundle, yaxud bir neçə public
certificate faylı seçə bilər. Fayl uzantısı yalnız köməkçi ipucudur;
format məhdud ölçüdə məzmundan müəyyən edilir. İlk addım faylların nə
olduğunu göstərir, hələ **Verified** hökmü vermir.

Növbəti import mərhələsində Rootwell hər certificate-i fingerprint ilə ayırır
və istifadəçiyə sadə dildə göstərir: "saytın certificate-i", "aralıq CA",
"root namizədi".
Bu rollar issuer/subject, CA məhdudiyyətləri və imza əlaqəsi kimi
evidence-lə izah edilir. Birdən çox mümkün leaf, natamam chain və ya
uyğunsuz fayl varsa, sistem səssiz seçim etmir; hansı məlumatın
çatmadığını deyir və lazım olduqda Advanced düzəlişinə yönləndirir.

TLS server üçün Verify istənəndə hostname soruşulur. Sonra ayrıca
**etibar mənbəyi** seçilir: istifadəçinin müstəqil təqdim etdiyi şirkət
root-u; gələcəkdə isə yalnız versiyalanmış və ayrıca review edilmiş
public-root profili. Göndərilən bundle içində root namizədi tapmaq
onu avtomatik etibarlı etmir. Etibar mənbəyi yoxdursa, nəticə
"hələ yoxlanmayıb" olur, "verified" və ya "failed" yox.

Nəticə dörd vəziyyəti qarışdırmır: **oxundu** (metadata), **yoxlandı**
(seçilmiş etibar mənbəyi və hostname ilə), **yoxlamadan keçmədi**
(səbəbi göstərilir), **tamamlanmayıb** (məlumat/etibar mənbəyi çatmır).
Offline nəticə revocation, canlı endpoint və private-key possession
iddiası etmir. Inspect mövcud tək-certificate funksiyasıdır; aşağıdakı
import axını onun artıq hazır olduğu mənasına gəlmir.

## Sadə və Advanced eyni qərarı verir

Sadə görünüş faylları təhlil edib mümkün leaf və intermediates-ləri
təklif edir; istifadəçi etibar mənbəyini ayrıca seçir. Advanced görünüş
leaf, intermediates, trust anchors, hostname, evaluation time və policy
parametrlərini açıq göstərir və lazım gəlsə əl ilə düzəltməyə imkan
verir. Hər ikisi eyni Go verification core-una və eyni policy versiyasına
eyni tipli explicit input verir; görünüşün dəyişməsi hökmü dəyişmir.
Sadə görünüşdə təhlükəsizlik yoxlamalarını azaltmaq qadağandır.

## Bundle explorer və download

Hazırkı public explorer 1–8 PEM bundle və ya tək DER faylındakı certificate-ləri
ayrıca kartlarda göstərir: subject/issuer, expiry, CA flag, encoding və
fingerprint. Ümumi 16 MiB/64 certificate limiti var, eyni certificate müxtəlif
fayllarda təkrarlandısa bütün nəticə rədd olunur; qismən nəticə göstərilmir.
Fayllararası dublikat xəbərdarlığı hər iki faylın seçilmə sırasını, təhlükəsiz
göstərilən adını və certificate-in tam SHA-256 fingerprint-ini bildirir.
Bir faylın daxilindəki dublikatda isə yalnız həmin fayl göstərilir; konkret
PEM blokunu seçmək hələ mümkün deyil. Avtomatik dublikat silinmir.
Mümkün issuer əlaqəsi eyni ad və imza yoxlaması ilə göstərilir; bu nə qəti
chain, nə də trust hökmüdür. Birdən çox namizəd səssiz seçilmir.
İndi istifadəçi kartda seçdiyi bir **public certificate**-i PEM və ya DER
kimi ayrıca endirməyi tələb edə bilər. `.crt` və `.cer` ayrıca format deyil:
istifadəçi iç məzmunu (PEM text və ya DER binary) və fayl uzantısını birlikdə
seçir. `.pem` yalnız PEM-ə, `.der` yalnız DER-ə uyğundur; `.crt`/`.cer` isə
hər iki variantla mümkündür. Fayl adı certificate məzmunundan
birbaşa götürülmür; sabit prefiks, fingerprint hissəsi və random nonce
istifadə olunur. Export-dan əvvəl mənbə, sonra çıxış təkrar parse edilir;
DER byte uyğunluğu və fingerprint yoxlanılır. Rootwell fayl sisteminə
birbaşa yazmır; browser download manager-in save/overwrite davranışına
tam nəzarət edə bilmir. Seçilmiş public sertifikatlar göstərilən sırada PEM
bundle kimi endirilə bilir; Rootwell sıranı avtomatik dəyişmir və bunu
verified fullchain saymır.
Heç bir private key bu axının parçası deyil.

`PFX`/`P12` və private key ehtiva edə bilən digər materiallar public
import sahəsində qəbul edilmir. Onlar üçün ayrıca secret-bearing threat
model, təhlükəsiz passphrase girişi, memory/output davranışı və
conversion review tələb olunur. Bir faylı əvvəlcə converter-dən
keçirmək Verify üçün məcburi deyil; lazımsız yenidən kodlama və fayla
yazma risk yaratmamalıdır.

## Nümunə: `.crt` + `bundle`

1. İstifadəçi CA-dan aldığı iki faylı birlikdə əlavə edir.
2. Rootwell məzmuna görə public certificate-ləri ayırır və ehtimal
   olunan chain-i göstərir; anlaşılmayan və ya artıq obyektləri gizlətmir.
3. İstifadəçi yoxlanacaq hostname-i və müstəqil etibar mənbəyini seçir.
4. Eyni core imza, zaman, hostname, usage, chain və algorithm policy-ni
   yoxlayır; çatışmayan materialı açıq bildirir.
5. İstifadəçi istəsə, yalnız seçdiyi public certificate hissələrini
   ayrıca və ya açıq seçilmiş sırada bir PEM bundle kimi endirir.

## İcra sırası və qəbul meyarları

1. Mövcud Verify preview-də işləməyən fayl seçicilərini çıxar, sadə
   gələcək yolu və preview sərhədini açıq göstər.
2. Public-only, bounded bundle parser və bir-fayllı browser explorer qur:
   malformed, mixed, duplicate, trailing, həddən artıq böyük və
   secret-bearing input rədd edilir; fuzz və neqativ testlər əlavə olunur.
   **İşləkdir.** Çoxfayllı public metadata görünüşü də işləkdir; rol/chain
   təyini ayrıca incrementdir.
3. Seçilən public certificate-lərin təhlükəsiz export-u: yeni fayl adı,
   no-overwrite, təkrar parse, byte/semantik uyğunluq testləri.
   **Bir public certificate və seçilmiş public PEM bundle üçün browser download işləkdir.** Rootwell
   birbaşa diskə yazmır və random ad yaradır; browserin son save qərarı
   Rootwell-in nəzarətində deyil. Fayl sistemində qəti no-overwrite və
   avtomatik fullchain sırası ayrıca mərhələdə qalır.
4. Browser Verify-ni mövcud CLI Go core-u ilə bağla; explicit trust
   mənbəyi, hostname və policy olmadan hökm vermə. **İşləkdir.**
5. Advanced görünüşü və Simple/Advanced parity testlərini əlavə et.
   **İşləkdir:** eyni explicit trust və policy ilə Go nüvəsində parity
   testi var; Simple birdən çox leaf olduqda səssiz seçim etmir.
6. PFX/secret conversion-u yalnız ayrıca threat-model və dependency
   review-dan sonra planlaşdır.

Qəbul zamanı certificate terminlərini bilməyən şəxs CA-nın verdiyi
fayllarla haradan başlayacağını başa düşməlidir. Yanlış və ya
çatışmayan trust mənbəyi heç vaxt verified nəticəsinə çevrilməməlidir.
UI network və gizli upload yaratmamalıdır; certificate metadata-sının
özünün də həssas ola biləcəyi nəzərə alınmalıdır. Hər yeni parser/export
path-i uğur, rədd, malformed və abuse testləri və iki istiqamətli
sabotaj yoxlaması ilə release edilməlidir.
