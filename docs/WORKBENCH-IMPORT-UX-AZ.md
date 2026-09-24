# Certificate import, bundle explorer və Verify UX planı

**Status:** bir fayllı public browser explorer işləkdir; çoxfayllı import,
rol/chain təyini, export və browser Verify hələ plan mərhələsindədir.

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

Hazırkı public explorer bir PEM bundle və ya tək DER faylındakı certificate-ləri
ayrıca kartlarda göstərir: subject/issuer, expiry, CA flag, encoding və
fingerprint. Rol namizədi və chain əlaqəsi hələ göstərilmir.
Gələcək export mərhələsində istifadəçi seçdiyi **public certificate**-ləri PEM
və ya DER kimi ayrıca və ya public-only bundle olaraq endirə bilər. Endirilən fayl adı
certificate məzmunundan birbaşa götürülmür; sabit prefiks və qısa
fingerprint əsasında təhlükəsiz ad seçilir. Export-dan sonra təkrar
parse və semantik bərabərlik yoxlanılır. Heç bir private key bu axının
parçası deyil.

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
   ayrıca endirir.

## İcra sırası və qəbul meyarları

1. Mövcud Verify preview-də işləməyən fayl seçicilərini çıxar, sadə
   gələcək yolu və preview sərhədini açıq göstər.
2. Public-only, bounded bundle parser və bir-fayllı browser explorer qur:
   malformed, mixed, duplicate, trailing, həddən artıq böyük və
   secret-bearing input rədd edilir; fuzz və neqativ testlər əlavə olunur.
   **İşləkdir.** Çoxfayllı import və rol/chain təyini ayrıca incrementdir.
3. Seçilən public certificate-lərin təhlükəsiz export-u: yeni fayl adı,
   no-overwrite, təkrar parse, byte/semantik uyğunluq testləri.
4. Browser Verify-ni mövcud CLI Go core-u ilə bağla; explicit trust
   mənbəyi, hostname və policy olmadan hökm vermə.
5. Advanced görünüşü və Simple/Advanced parity testlərini əlavə et.
6. PFX/secret conversion-u yalnız ayrıca threat-model və dependency
   review-dan sonra planlaşdır.

Qəbul zamanı certificate terminlərini bilməyən şəxs CA-nın verdiyi
fayllarla haradan başlayacağını başa düşməlidir. Yanlış və ya
çatışmayan trust mənbəyi heç vaxt verified nəticəsinə çevrilməməlidir.
UI network və gizli upload yaratmamalıdır; certificate metadata-sının
özünün də həssas ola biləcəyi nəzərə alınmalıdır. Hər yeni parser/export
path-i uğur, rədd, malformed və abuse testləri və iki istiqamətli
sabotaj yoxlaması ilə release edilməlidir.
