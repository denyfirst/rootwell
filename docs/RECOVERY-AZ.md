# Rootwell access bərpası — Linux terminal mərasimi

**Status:** inkişaf mərhələsi. Bu prosedur yalnız `access.json` üçün nəzərdə
tutulub; certificate inventory, vault və serverdəki başqa məlumatların tam
backup-u deyil. İlk public/production istifadə üçün müstəqil təhlükəsizlik
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
aşkar etmir. Daha sonra yaradılacaq inventory qeydləri bu snapshot-a daxil
olmadığı üçün hələ qalıcı inventory aktiv edilməyib.
