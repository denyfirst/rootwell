# Rootwell access bərpası — Linux terminal mərasimi

**Status:** inkişaf mərhələsi. Access-only prosedur yalnız `access.json` üçündür.
Yeni Linux public-certificate inventory üçün ayrıca tam snapshot proseduru
aşağıdadır; vault və gələcək başqa məlumatlar ora daxil deyil. İlk
public/production istifadə üçün müstəqil təhlükəsizlik
auditi və real restore drill tələb olunur. Windows-da bu əmrlər qəsdən bağlıdır.

Parol və recovery kodunu heç vaxt komanda argumenti, environment variable,
shell history, chat, ticket və ya loga yazmayın. Əmrlər onları gizli lokal
terminal girişində soruşur. Terminal scrollback-u və hostu da qoruyun.

1. `rootwelld serve` prosesini dayandırın. Linux əməliyyat kilidi işləyən
   daemonla offline bərpanın eyni vaxtda aparılmasını rədd edir.
2. Ready v2 qurulumda kodu bir dəfə yaradın:

   ```text
   rootwelld recovery-enroll /private/rootwell-data
   ```

   Çıxan kodu access faylından, backup-dan və həmin hostdan **ayrı offline**
   yerdə saxlayın. Kodu itirsəniz və parolu hələ bilirsinizsə,
   `recovery-rotate` ilə yenisini yaradın. Kod dəyişəndə köhnə backup-lardakı
   köhnə kod səlahiyyəti avtomatik silinmir.
3. Ayrı, sahibi tərəfindən idarə olunan `0700` backup qovluğu hazırlayın və
   access-only snapshot yaradın:

   ```text
   rootwelld access-snapshot /private/rootwell-data /private/backup/rootwell-access.rwab
   rootwelld access-verify /private/backup/rootwell-access.rwab code
   ```

   Export həm cari parolu, həm recovery kodunu yoxlayır; yeni backup faylı
   `0600` olur və mövcud faylın üzərinə yazılmır. Faylı ayrıca/offsite və
   redundansla saxlayın. Kodla snapshot-u eyni yerdə saxlamayın.
4. Bərpa sınağı üçün mövcud, boş və `0700` yeni qovluq hazırlayın. **Canlı
   qovluqdan istifadə etməyin.** Əvvəl snapshot-u `access-verify` ilə yoxlayın,
   sonra:

   ```text
   rootwelld access-restore /private/backup/rootwell-access.rwab /private/fresh-rootwell-data code
   rootwelld recovery-reset /private/fresh-rootwell-data
   ```

   Restore köhnə parolu dəyişmir; parol itibsə ikinci əmr yeni parol və yeni
   recovery kodu yaradır. Yeni kodu ayrıca saxlayın, sonra yeni snapshot
   hazırlayın. Restore mövcud qurulumu əvəz etmir.

Parol və kodun ikisi də itibsə, şifrəli məlumatı bərpa etmək mümkün deyil.
Fayl/volume korlanması, enerji kəsilməsi və ya `uncertain` nəticəsi zamanı
əmri kor-koranə təkrarlamayın; cari faylın vəziyyətini yoxlayın. Köhnə,
amma düzgün snapshot geri qaytarıla bilər — bu format rollback hücumunu
aşkar etmir. Inventory aktivdirsə access-only snapshot onun qeydlərini
qaytarmır; onu tam backup əvəzi kimi istifadə etməyin.

## Linux public inventory: tam snapshot və bərpa

Bu əmrlər yalnız Linux-da və daemon dayandırıldıqda işləyir. Əvvəl
`recovery-enroll` ilə kod yaradılmalı, ayrıca owner-private (`0700`) backup
qovluğu hazırlanmalıdır. İlk aktivləşmə planlanan boş inventory-nin tam
snapshot-unu **əvvəl** yazır, sonra inventory faylını yaradır:

```text
rootwelld inventory-init /private/rootwell-data /private/backup/initial.rwfull
rootwelld inventory-verify /private/backup/initial.rwfull code
```

Bundan sonra daemonu başlatmaq və giriş etmək olar. Ayrı `/inventory`
səhifəsində Save istifadəçinin seçdiyi yalnız public sertifikatı özünün
loopback Rootwell serverinə göndərir; offline Workbench bunu etmir. Bu səhifə
Linux-da işləyir. Duplicate import rədd olunur, expiry brauzer saatına görə
göstərilir və trust hökmü deyil.

Export cari parolu və ayrıca recovery kodunu terminalda soruşur. Sertifikat
importundan və parol/kod dəyişməsindən sonra yeni, fərqli adla tam snapshot
yaradın; köhnə faylın üzərinə yazılmır:

```text
rootwelld inventory-snapshot /private/rootwell-data /private/backup/dated.rwfull
rootwelld inventory-verify /private/backup/dated.rwfull password
```

Təzə, boş və `0700` qovluqda bərpa məşqi:

```text
rootwelld inventory-restore /private/backup/dated.rwfull /private/fresh-rootwell-data code
rootwelld recovery-reset /private/fresh-rootwell-data
```

`inventory-restore` həm access envelope-u, həm inventory image-ni birlikdə
autentifikasiya edir və heç bir mövcud qurulumu əvəz etmir. Restore-un yarıda
qalması mümkün olduqda həmin qovluğu əllə araşdırın; təkrar sınaq üçün **yeni**
boş qovluq seçin. Snapshot-un özündə olan köhnə parol/kod qüvvədə qala bilər;
restore-dan sonra kodu və parolu dəyişib yeni snapshot alın. Snapshot da
inventory kimi daxili host/owner adları haqqında metadata sızdıra bilər.
Tam köhnə, autentik snapshot geri qaytarıla bilər; ayrıca etibarlı monotonic
anchor olmadan bu rollback aşkarlanmır. Backup-ı və recovery kodunu ayrı,
offsite yerlərdə saxlayın. Docker/Linux üçün ayrıca istifadə və disposable
volume bərpa sınağı [`CONTAINER-RECOVERY-AZ.md`](CONTAINER-RECOVERY-AZ.md)
sənədindədir. Windows native inventory storage və müstəqil release auditi
hələ açıqdır.
