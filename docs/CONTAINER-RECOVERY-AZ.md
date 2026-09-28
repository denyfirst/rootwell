# Rootwell Docker/Linux: private volume və tam bərpa

**Status:** inkişaf mərhələsi. `compose.yaml` yalnız Linux hostda lokal
istifadə/sınaq üçündür; production remote access, Windows Docker Desktop,
avtomatik backup və ya təhlükəsizlik auditi iddiası deyil. Daemon qəsdən yalnız
hostun `127.0.0.1:4180` ünvanına bağlanır. `network_mode: host` bu loopback
ünvanını host brauzerinə çatdırır, amma konteynerin şəbəkə izolyasiyasını
azaldır. Rootwell-i internetə çıxarmayın; ayrıca TLS/reverse-proxy sərhədi
review edilməyib.

## İlk qurulum

Yalnız özünüzün idarə etdiyiniz Linux hostda **iki fərqli** absolute qovluq
seçin. Data və backup eyni bind mount, eyni qovluq və ya eyni Docker named
volume olmamalıdır. Backup-ın offsite nüsxəsini ayrıca saxlayın. Buradakı
yollar nümunədir; canlı data yolunu bərpa hədəfi kimi işlətməyin.

```sh
export ROOTWELL_UID="$(id -u)" ROOTWELL_GID="$(id -g)"
export ROOTWELL_DATA_DIR=/srv/rootwell-private/data
export ROOTWELL_BACKUP_DIR=/srv/rootwell-backup/private
install -d -m 0700 "$ROOTWELL_DATA_DIR" "$ROOTWELL_BACKUP_DIR"
docker compose build rootwell
docker compose run --rm maintenance init /data
```

İlkin parol yalnız interaktiv terminalda görünür. `SAVED` təsdiqini verin,
`docker compose up -d rootwell` ilə servisi başladın, eyni hostun
`http://localhost:4180` səhifəsində ilkin parolu **məcburi dəyişin**, sonra
servisi dayandırın. Parolu, recovery kodunu və ya private key-i argv, env,
`.env`, chat, ticket və loga yazmayın. Bütün maintenance əmrləri interaktiv
TTY tələb edir və şəbəkəsiz konteynerdə işləyir.

```sh
docker compose stop rootwell
docker compose run --rm maintenance recovery-enroll /data
docker compose run --rm maintenance inventory-init /data /backup/initial.rwfull
docker compose run --rm maintenance inventory-verify /backup/initial.rwfull code
docker compose up -d rootwell
```

Recovery kodunu data volume, backup qovluğu və həmin hostdan ayrı offline
yerdə saxlayın. Daemon konteynerinə backup mount edilmir. `inventory-init`
boş inventory-ni aktivləşdirməzdən **əvvəl** tam snapshot yaradır. `init` və
`inventory-init` təkrar işlədilərək mövcud qurulum əvəz edilmir.

## Hər dəyişiklikdən sonra backup

Import, manual istifadə yeri, parol və ya recovery kodu dəyişəndən sonra daemonu dayandırın.
Yeni, bənzərsiz ad seçin; mövcud backup overwrite edilmir.

```sh
docker compose stop rootwell
docker compose run --rm maintenance inventory-snapshot /data /backup/2026-09-28-01.rwfull
docker compose run --rm maintenance inventory-verify /backup/2026-09-28-01.rwfull code
docker compose up -d rootwell
```

`inventory-snapshot` cari parol və ayrıca recovery kodunu terminaldan soruşur.
`access-snapshot` inventory-ni ehtiva **etmir**. Daemon işləyərkən offline
snapshot əməliyyat kilidi ilə rədd olunur. Backup və onu açan recovery kodu
eyni yerdə qalmamalıdır. Fayl host storage-u da sıradan çıxara bilər: snapshot-u
ayrıca/offsite daşıyın və dövri bərpa məşqi edin. Rootwell avtomatik backup
etmir; serverə parol və recovery kodunu daimi vermirik. Köhnə autentik backup
sonrakı importları və owner/location qeydlərindəki düzəlişləri qaytarmır;
köhnə backup əvvəlki qeydləri ehtiva edə bilər və rollback-i aşkarlamır.

## Təmiz volume-a bərpa məşqi

Daemonu dayandırın. Yeni, boş, `0700`, eyni UID-ə məxsus data qovluğu
hazırlayın. `ROOTWELL_DATA_DIR` dəyişənini **yalnız yeni qovluğa** yönəldin;
köhnə volume-u silməyin. Backup qovluğu yalnız maintenance konteynerində
görünür. Aşağıdakı bərpa kod və ya parolla mümkündür; kod seçilibsə köhnə
parol itəndə ayrıca `recovery-reset` edin.

```sh
docker compose stop rootwell
export ROOTWELL_DATA_DIR=/srv/rootwell-private/fresh-drill
install -d -m 0700 "$ROOTWELL_DATA_DIR"
docker compose run --rm maintenance inventory-verify /backup/2026-09-28-01.rwfull code
docker compose run --rm maintenance inventory-restore /backup/2026-09-28-01.rwfull /data code
docker compose up -d rootwell
```

Brauzerdə yeni volume-dakı qeydlərin göründüyünü yoxlayın. Köhnə parol
itibsə servisi yenidən dayandırıb `docker compose run --rm maintenance
recovery-reset /data` işlədin; sonra yeni kodu ayrı saxlayıb yeni tam snapshot
alın. Bərpa köhnə qurulumu overwrite etmir. Yarımçıq/`uncertain` nəticədə
qovluğu araşdırın, kor-koranə eyni hədəfə təkrar etməyin.

## CI-də həqiqi volume məşqi

`scripts/test-container-volume.sh` yalnız CI-nin disposable `RUNNER_TEMP`
qovluğunda dörd ayrı bind mount (data, backup, fresh, test recovery) yaradır.
Ayrı konteyner proseslərində import, dayanma/yenidən açılma, tam snapshot,
yanlış kod və zədələnmiş backup rəddi, işləyən daemonla offline backup rəddi,
icazəsi açılmış data qovluğunun rəddi və təmiz volume-a bərpanı yoxlayır.
Server konteynerinə yalnız `/data` mount edildiyini və restore edilmiş
volume-dan UI-nin açıldığını da yoxlayır. Test parolu və kodu yalnız həmin
disposable testdə mövcuddur; real istifadəçi volume-u sınağa daxil edilmir.
Bu sınaq bütün storage/snapshot fault-larını, host compromise-u, offsite
dayanıqlığını və audit ehtiyacını aradan qaldırmır.
