# LockBox — GitHub és kiadás (magyar útmutató)

Ez a repó mappája. Az alap beállítás már kész; itt az látszik, hogyan frissíts
és hogyan adj ki egy új verziót.

## Build helyben

A `lockbox` mappában (ahol az `application.fam` is van), PowerShellben:

```powershell
pip install ufbt
ufbt            # build -> dist/lockbox.fap
ufbt launch     # build + feltöltés a csatlakoztatott Flipperre
```

## Változás feltöltése

```powershell
git add -A
git commit -m "Rövid leírás a változásról"
git push
```

## Kiadás (release) — ez építi meg a .fap-ot és csatolja

A GitHub Actions a `v`-vel kezdődő tagre lefordítja a `lockbox.fap`-ot és
felteszi a release-hez (`.github/workflows/build.yml`):

```powershell
git tag v2.0.0
git push origin v2.0.0
```

Pár perc múlva a repó **Releases** fülén ott lesz a `lockbox.fap`, letölthetően.

## Build-állapot

A README tetején a zöld **Build FAP** jelvény mutatja, hogy fordul-e a kód.
Az **Actions** fülön látod a logokat.

## Fájlszerkezet

```
lockbox/
├── application.fam
├── lockbox.c
├── lockbox_icon.png
├── images/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── Makefile
├── .gitignore
├── GITHUB_SETUP_HU.md
└── .github/
    └── workflows/
        └── build.yml
```
