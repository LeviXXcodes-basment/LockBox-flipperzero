/*
 * LockBox — PIN-protected, device-bound vault for NFC & RFID cards.
 * Author: LeviXX
 *
 * Security model (v0.4):
 *   - A direction-button PIN (Up/Down/Left/Right/Back sequence, like the Momentum
 *     lock code) gates the app (stored only as a djb2 hash in pin.dat).
 *   - The encryption key is DERIVED, never stored: it comes from this Flipper's
 *     unique hardware serial (UID) + the entered PIN, run through a slow SHA-256
 *     key-derivation with a random per-file salt.
 *   - Cipher: SHA-256 keystream (hash-CTR). Real cryptographic primitive, not XOR.
 *   - Because the key needs BOTH the device serial (not on the SD card) and the
 *     PIN, a copied .lbx file cannot be decrypted off this device or without the
 *     PIN. Changing the PIN re-keys: decrypt your cards before changing it.
 */

#include <furi.h>
#include <furi_hal_version.h>
#include <furi_hal_random.h>
#include <furi_hal_rtc.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/view.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <notification/notification_messages.h>

#define APP_VERSION "v2.1"

#define LOCKBOX_DIR      "/ext/apps_data/lockbox"
#define LOCKBOX_PIN_PATH  "/ext/apps_data/lockbox/pin.dat"
#define LOCKBOX_LOCK_PATH "/ext/apps_data/lockbox/lock.dat"
#define LOCKBOX_CFG_PATH  "/ext/apps_data/lockbox/cfg.dat"
#define LOCKOUT_START_FAILS 2 /* ennyi rossz probalkozas utan jon az elso timeout */
#define PANIC_WIPE_MIN     3  /* a panic-wipe kuszob also hatara */
#define PANIC_WIPE_MAX     20 /* a panic-wipe kuszob felso hatara */
#define PANIC_WIPE_DEFAULT 10 /* alap panic-wipe kuszob */
#define LOCKBOX_CFG_MAGIC  0x4C425347u /* "LBSG" - config fajl fejlec */
#define LOCKBOX_NFC_DIR      "/ext/apps_data/lockbox/nfc"
#define LOCKBOX_RFID_DIR     "/ext/apps_data/lockbox/rfid"
#define LOCKBOX_SUBGHZ_DIR   "/ext/apps_data/lockbox/subghz"
#define LOCKBOX_IBTN_DIR     "/ext/apps_data/lockbox/ibutton"
#define LOCKBOX_INFRARED_DIR "/ext/apps_data/lockbox/infrared"
#define LOCKBOX_NOTES_DIR    "/ext/apps_data/lockbox/notes"
#define LOCKBOX_NOTE_TITLE_LEN 40
#define LOCKBOX_NOTE_TEXT_LEN  512
#define NFC_SRC_DIR        "/ext/nfc"
#define RFID_SRC_DIR       "/ext/lfrfid"
#define SUBGHZ_SRC_DIR     "/ext/subghz"
#define IBTN_SRC_DIR       "/ext/ibutton"
#define INFRARED_SRC_DIR   "/ext/infrared"
/* A PIN mostantol IRANYGOMB-sorozat (Fel/Le/Balra/Jobbra/Vissza), mint a
 * Momentum zarkod. PIN_MAX a max hossz, PIN_MIN a minimum. */
#define PIN_MAX            10
#define PIN_MIN            4
#define LOCKBOX_MAX_FILE (32768) /* max importalhato fajlmeret (bajt) */
#define LOCKBOX_MAGIC    "LBX1" /* 4 bajtos fejlec a helyes-kulcs ellenorzeshez */
#define LOCKBOX_MAGIC_LEN 4
#define LOCKBOX_SALT_LEN  16 /* fajlonkenti veletlen so */
#define LOCKBOX_KDF_ROUNDS 8000 /* lassu kulcs-szarmaztatas (brute-force lassitas) */
#define LOCKBOX_MAX_ITEMS  64 /* a szef-listaban megjeleno max kartyaszam */
#define LOCKBOX_PATH_LEN   256

/* ====================================================================== *
 *                        SHA-256 (onallo, kanonikus)                     *
 * ====================================================================== */

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

#define SHR(x, n)    ((x) >> (n))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BSIG0(x)     (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BSIG1(x)     (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SSIG0(x)     (ROTR32(x, 7) ^ ROTR32(x, 18) ^ SHR(x, 3))
#define SSIG1(x)     (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR(x, 10))
#define CHfn(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJfn(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

typedef struct {
    uint32_t h[8];
    uint64_t len; /* osszes bajt */
    uint8_t buf[64];
    size_t buflen;
} Sha256;

static void sha256_block(Sha256* c, const uint8_t* p) {
    uint32_t w[64];
    for(int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | ((uint32_t)p[i * 4 + 3]);
    }
    for(int i = 16; i < 64; i++) {
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], hh = c->h[7];
    for(int i = 0; i < 64; i++) {
        uint32_t t1 = hh + BSIG1(e) + CHfn(e, f, g) + SHA256_K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJfn(a, b, cc);
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += hh;
}

static void sha256_init(Sha256* c) {
    c->h[0] = 0x6a09e667;
    c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372;
    c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f;
    c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab;
    c->h[7] = 0x5be0cd19;
    c->len = 0;
    c->buflen = 0;
}

static void sha256_update(Sha256* c, const uint8_t* data, size_t len) {
    c->len += len;
    while(len) {
        size_t n = 64 - c->buflen;
        if(n > len) n = len;
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n;
        data += n;
        len -= n;
        if(c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(Sha256* c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    c->buf[c->buflen++] = 0x80;
    if(c->buflen > 56) {
        while(c->buflen < 64) c->buf[c->buflen++] = 0;
        sha256_block(c, c->buf);
        c->buflen = 0;
    }
    while(c->buflen < 56) c->buf[c->buflen++] = 0;
    for(int i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_block(c, c->buf);
    for(int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

/* ---- Nezet-azonositok ---- */
typedef enum {
    ViewIdPin,
    ViewIdMenu,
    ViewIdVault,
    ViewIdItem,
    ViewIdNotes,
    ViewIdNoteItem,
    ViewIdNoteView,
    ViewIdTitleInput,
    ViewIdNoteInput,
    ViewIdRecoverPin,
    ViewIdRekey,
    ViewIdSettings,
    ViewIdRenameInput,
    ViewIdAbout,
    ViewIdResult,
} ViewId;

/* ---- PIN nezet modjai ---- */
typedef enum {
    PinModeSet,
    PinModeConfirm,
    PinModeVerify,
    PinModeRecover, /* regi PIN bevitele visszafejtes-helyreallitashoz */
} PinMode;

/* ---- Fomenu elemek ---- */
typedef enum {
    MenuIndexNfc,
    MenuIndexRfid,
    MenuIndexSubghz,
    MenuIndexIbtn,
    MenuIndexInfrared,
    MenuIndexVault,
    MenuIndexNotes,
    MenuIndexSettings,
    MenuIndexChangePin,
    MenuIndexAbout,
} MenuIndex;

/* ---- Kartya-muvelet almenu ---- */
typedef enum {
    ItemActionDecrypt,
    ItemActionOldPin,
    ItemActionRename,
    ItemActionDelete,
} ItemAction;

/* ---- Settings almenu elemek ---- */
typedef enum {
    SettingsPanicToggle,
    SettingsPanicLess,
    SettingsPanicMore,
    SettingsBack,
} SettingsAction;

/* ---- Jegyzet-muvelet almenu ---- */
typedef enum {
    NoteActionView,
    NoteActionOldPin,
    NoteActionDelete,
} NoteAction;

/* ---- PIN-valtas utani ujratitkositas almenu ---- */
typedef enum {
    RekeyActionYes,
    RekeyActionNo,
} RekeyAction;

/* ---- PIN-szimbolumok (iranygombok) ---- */
typedef enum {
    PinSymUp = 0,
    PinSymDown = 1,
    PinSymLeft = 2,
    PinSymRight = 3,
    PinSymBack = 4,
} PinSym;

/* Egy PIN-ertek: iranygomb-szimbolumok sorozata + hossz. */
typedef struct {
    uint8_t s[PIN_MAX];
    uint8_t len;
} PinVal;

typedef struct {
    PinVal cur; /* aktualisan bevitt sorozat */
    PinMode mode;
    PinVal first; /* a Set lepesben megadott sorozat (Confirm-hoz) */
    bool error;
    bool locked; /* epp zarolva van-e (brute-force vedelem) */
    uint32_t remaining; /* hatralevo masodpercek a zarolasbol */
    uint32_t anim; /* animacios keptszamlalo (uszkalo delfin) */
} PinModel;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    NotificationApp* notifications;
    Storage* storage;
    DialogsApp* dialogs;

    View* pin_view;
    Submenu* menu;
    Submenu* vault_menu;
    Submenu* item_menu;
    Submenu* notes_menu;
    Submenu* note_item_menu;
    TextBox* about_box;
    TextBox* result_box;
    TextBox* note_view;
    TextInput* title_input;
    TextInput* note_input;
    TextInput* rename_input; /* szef-tetel atnevezese */
    Submenu* settings_menu; /* panic-wipe beallitasok */

    FuriTimer* lock_timer; /* a zarolas-visszaszamlalo frissitese */
    FuriTimer* anim_timer; /* a delfin-animacio frissitese (~100ms) */

    char about_buffer[768];
    char result_buffer[512];
    char menu_header[32];
    bool pin_is_set;
    PinVal session_pin; /* a belepeskor megadott PIN (a kulcshoz, csak RAM) */

    /* Brute-force vedelem (lemezre mentve, hogy ujrainditas ne nullazza) */
    uint32_t fail_count; /* egymas utani rossz PIN-ek szama */
    uint32_t lock_until; /* eddig a RTC-idopontig zarolva (masodperc) */

    /* Panic-wipe: ennyi egymas utani rossz PIN utan torli a szefet (ha be van kapcsolva) */
    bool panic_enabled;
    uint32_t panic_threshold;

    /* Recovery: regi PIN-nel probalt visszafejtes */
    View* recover_view; /* kulon PIN-pad a regi PIN beviteléhez */
    PinVal recovery_pin; /* a megadott regi PIN (csak RAM) */
    bool use_recovery_pin; /* a derive_key a recovery_pin-t hasznalja-e */
    bool recover_is_note; /* jegyzetet (true) vagy kartyat (false) allitunk vissza */

    /* PIN-valtas (Change PIN) + ujratitkositas az uj kulccsal */
    bool changing_pin; /* a PIN-pad epp Change PIN folyamatban van-e */
    PinVal old_pin_for_rekey; /* a valtas elotti PIN (ujratitkositashoz) */
    Submenu* rekey_menu; /* "Encrypt all with new key?" almenu */

    /* Szef-lista allapota */
    char vault_paths[LOCKBOX_MAX_ITEMS][LOCKBOX_PATH_LEN];
    uint8_t vault_count;
    uint8_t selected_index; /* a kivalasztott kartya a listaban */

    /* Jegyzetek allapota */
    char note_paths[LOCKBOX_MAX_ITEMS][LOCKBOX_PATH_LEN];
    uint8_t note_count;
    uint8_t note_selected;
    char note_title[LOCKBOX_NOTE_TITLE_LEN]; /* uj jegyzet cime (bevitel) */
    char note_text[LOCKBOX_NOTE_TEXT_LEN]; /* uj jegyzet szovege (bevitel) */
    char note_display[LOCKBOX_NOTE_TEXT_LEN + 128]; /* megtekintett jegyzet (cim+szoveg) */

    /* Atnevezes allapota */
    char rename_buf[LOCKBOX_NOTE_TITLE_LEN]; /* szerkesztheto nev (tipus-suffix nelkul) */
    char rename_suffix[16]; /* az eredeti tipus-vegzodes (.nfc/.sub/...) visszafuzeshez */
} LockBoxApp;

/* ====================================================================== *
 *                        PIN tarolas (hashelt)                           *
 * ====================================================================== */

static uint32_t pin_hash(const PinVal* p) {
    uint32_t h = 5381;
    h = ((h << 5) + h) + (uint32_t)(p->len + 1); /* a hossz is szamit */
    for(uint8_t i = 0; i < p->len; i++) {
        h = ((h << 5) + h) + (uint32_t)(p->s[i] + 1);
    }
    return h;
}

static bool pin_equal(const PinVal* a, const PinVal* b) {
    if(a->len != b->len) return false;
    return memcmp(a->s, b->s, a->len) == 0;
}

/* A pin.dat formatuma: [magic(4)][hash(4)]. A magic kuloniti el az irany-gombos
 * (v2) PIN-t a regi szamjegyes formatumtol -> a regi fajl ervenytelen, igy az app
 * uj PIN-t ker (nem zar ki a nem beuthetо regi PIN miatt). */
#define LOCKBOX_PIN_MAGIC 0x4C425032u /* "LBP2" */

/* Akkor "van PIN", ha a fajl a mi (v2) magicunkkal kezdodik. */
static bool lockbox_pin_exists(LockBoxApp* app) {
    bool valid = false;
    File* file = storage_file_alloc(app->storage);
    if(storage_file_open(file, LOCKBOX_PIN_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint32_t magic = 0;
        if(storage_file_read(file, &magic, sizeof(magic)) == sizeof(magic) &&
           magic == LOCKBOX_PIN_MAGIC) {
            valid = true;
        }
        storage_file_close(file);
    }
    storage_file_free(file);
    return valid;
}

static bool lockbox_pin_save(LockBoxApp* app, const PinVal* pin) {
    storage_common_mkdir(app->storage, LOCKBOX_DIR);
    uint32_t buf[2] = {LOCKBOX_PIN_MAGIC, pin_hash(pin)};
    File* file = storage_file_alloc(app->storage);
    bool ok = false;
    if(storage_file_open(file, LOCKBOX_PIN_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = storage_file_write(file, buf, sizeof(buf)) == sizeof(buf);
        storage_file_close(file);
    }
    storage_file_free(file);
    return ok;
}

static bool lockbox_pin_check(LockBoxApp* app, const PinVal* pin) {
    uint32_t buf[2] = {0, 0};
    File* file = storage_file_alloc(app->storage);
    bool read_ok = false;
    if(storage_file_open(file, LOCKBOX_PIN_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        read_ok = storage_file_read(file, buf, sizeof(buf)) == sizeof(buf);
        storage_file_close(file);
    }
    storage_file_free(file);
    if(!read_ok) return false;
    if(buf[0] != LOCKBOX_PIN_MAGIC) return false; /* regi formatum -> ervenytelen */
    return buf[1] == pin_hash(pin);
}

/* ====================================================================== *
 *                  Brute-force zarolas (lemezre mentve)                  *
 * ====================================================================== */

static uint32_t lockbox_now(void) {
    return furi_hal_rtc_get_timestamp();
}

static void lockbox_lock_load(LockBoxApp* app) {
    app->fail_count = 0;
    app->lock_until = 0;
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, LOCKBOX_LOCK_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint32_t buf[2] = {0, 0};
        if(storage_file_read(f, buf, sizeof(buf)) == sizeof(buf)) {
            app->fail_count = buf[0];
            app->lock_until = buf[1];
        }
        storage_file_close(f);
    }
    storage_file_free(f);
}

static void lockbox_lock_save(LockBoxApp* app) {
    storage_common_mkdir(app->storage, LOCKBOX_DIR);
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, LOCKBOX_LOCK_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        uint32_t buf[2] = {app->fail_count, app->lock_until};
        storage_file_write(f, buf, sizeof(buf));
        storage_file_close(f);
    }
    storage_file_free(f);
}

/* A zarolas hossza masodpercben, a hibaszamlalobol (eszkalalodva). */
static uint32_t lockbox_lock_seconds(uint32_t fails) {
    if(fails < LOCKOUT_START_FAILS) return 0;
    if(fails == 2) return 30;
    if(fails == 3) return 60;
    if(fails == 4) return 120;
    if(fails == 5) return 300;
    return 600; /* 6+ rossz probalkozas -> 10 perc */
}

/* A brute-force letra teljes nullazasa (sikeres belepes utan, vagy ha egy
 * lejart zarolas utan tiszta lappal indulunk). */
static void lockbox_lock_reset(LockBoxApp* app) {
    app->fail_count = 0;
    app->lock_until = 0;
    lockbox_lock_save(app);
}

/* ====================================================================== *
 *                  Beallitasok (panic-wipe) - lemezre mentve             *
 * ====================================================================== */

static void lockbox_cfg_load(LockBoxApp* app) {
    app->panic_enabled = false;
    app->panic_threshold = PANIC_WIPE_DEFAULT;
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, LOCKBOX_CFG_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint32_t buf[3] = {0, 0, 0};
        if(storage_file_read(f, buf, sizeof(buf)) == sizeof(buf) && buf[0] == LOCKBOX_CFG_MAGIC) {
            app->panic_enabled = (buf[1] != 0);
            uint32_t th = buf[2];
            if(th < PANIC_WIPE_MIN) th = PANIC_WIPE_MIN;
            if(th > PANIC_WIPE_MAX) th = PANIC_WIPE_MAX;
            app->panic_threshold = th;
        }
        storage_file_close(f);
    }
    storage_file_free(f);
}

static void lockbox_cfg_save(LockBoxApp* app) {
    storage_common_mkdir(app->storage, LOCKBOX_DIR);
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, LOCKBOX_CFG_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        uint32_t buf[3] = {LOCKBOX_CFG_MAGIC, app->panic_enabled ? 1u : 0u, app->panic_threshold};
        storage_file_write(f, buf, sizeof(buf));
        storage_file_close(f);
    }
    storage_file_free(f);
}

/* Egy mappa osszes .lbx fajljanak torlese (panic-wipe). Visszaadja a torolt db-ot.
 * Keves stacket hasznal: koronkent megkeresi az elso .lbx-et, bezarja a mappat,
 * torli, majd ujra -> nincs nagy, stacken fekvo nevtomb. */
static uint32_t lockbox_wipe_dir(LockBoxApp* app, const char* dir) {
    uint32_t removed = 0;
    for(uint32_t guard = 0; guard < LOCKBOX_MAX_ITEMS; guard++) {
        char found[160];
        found[0] = '\0';
        File* d = storage_file_alloc(app->storage);
        if(storage_dir_open(d, dir)) {
            FileInfo info;
            char name[160];
            while(storage_dir_read(d, &info, name, sizeof(name))) {
                if(info.flags & FSF_DIRECTORY) continue;
                size_t nlen = strlen(name);
                if(nlen >= 4 && strcmp(name + nlen - 4, ".lbx") == 0) {
                    snprintf(found, sizeof(found), "%s", name);
                    break;
                }
            }
            storage_dir_close(d);
        }
        storage_file_free(d);
        if(found[0] == '\0') break; /* nincs tobb .lbx */

        char path[LOCKBOX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", dir, found);
        if(storage_common_remove(app->storage, path) == FSE_OK)
            removed++;
        else
            break; /* ne porogjon vegtelenbe, ha nem torolheto */
    }
    return removed;
}

/* Panic-wipe: minden titkositott tetel torlese a szefbol (NFC/RFID/SubGHz/
 * iButton/Infrared/Notes). A PIN megmarad, igy a kovetkezo belepes mukodik. */
static uint32_t lockbox_panic_wipe(LockBoxApp* app) {
    uint32_t n = 0;
    n += lockbox_wipe_dir(app, LOCKBOX_NFC_DIR);
    n += lockbox_wipe_dir(app, LOCKBOX_RFID_DIR);
    n += lockbox_wipe_dir(app, LOCKBOX_SUBGHZ_DIR);
    n += lockbox_wipe_dir(app, LOCKBOX_IBTN_DIR);
    n += lockbox_wipe_dir(app, LOCKBOX_INFRARED_DIR);
    n += lockbox_wipe_dir(app, LOCKBOX_NOTES_DIR);
    return n;
}

/* ====================================================================== *
 *             Kulcs-szarmaztatas (eszkoz UID + PIN) es rejtjel           *
 * ====================================================================== */

/* A titkositasi kulcs = lassu SHA-256 KDF( so || eszkoz-UID || PIN ).
 * Az UID a chipben van (nem az SD-n), a PIN csak a memoriaban -> a kulcs sehol
 * nincs eltarolva, es csak EZEN a Flipperen, a HELYES PIN-nel all elo. */
static void lockbox_derive_key(LockBoxApp* app, const uint8_t* salt, uint8_t out_key[32]) {
    const uint8_t* uid = furi_hal_version_uid();
    size_t uid_len = furi_hal_version_uid_size();

    /* Alaphelyzetben a belepesi (session) PIN; recovery modban a megadott regi PIN. */
    const PinVal* pin = app->use_recovery_pin ? &app->recovery_pin : &app->session_pin;
    uint8_t plen = pin->len; /* a hossz is a kulcs resze */

    Sha256 c;
    sha256_init(&c);
    sha256_update(&c, salt, LOCKBOX_SALT_LEN);
    sha256_update(&c, uid, uid_len);
    sha256_update(&c, &plen, 1);
    sha256_update(&c, pin->s, pin->len);
    uint8_t h[32];
    sha256_final(&c, h);

    for(uint32_t i = 0; i < LOCKBOX_KDF_ROUNDS; i++) {
        Sha256 c2;
        sha256_init(&c2);
        sha256_update(&c2, h, sizeof(h));
        sha256_update(&c2, salt, LOCKBOX_SALT_LEN);
        sha256_final(&c2, h);
    }
    memcpy(out_key, h, 32);
}

/* SHA-256 kulcsfolyam (hash-CTR): blokk_i = SHA256(key || LE64(i)); XOR.
 * Szimmetrikus: ugyanaz titkosit es fejt vissza. */
static void lockbox_cipher(const uint8_t key[32], uint8_t* data, size_t len) {
    uint8_t block[32];
    uint64_t counter = 0;
    size_t off = 0;
    while(off < len) {
        Sha256 c;
        sha256_init(&c);
        sha256_update(&c, key, 32);
        uint8_t ctr[8];
        for(int b = 0; b < 8; b++) ctr[b] = (uint8_t)(counter >> (8 * b));
        sha256_update(&c, ctr, sizeof(ctr));
        sha256_final(&c, block);

        size_t n = (len - off < 32) ? (len - off) : 32;
        for(size_t i = 0; i < n; i++) data[off + i] ^= block[i];
        off += n;
        counter++;
    }
}

/* Egy memoria-buffer titkositott fajlba irasa (jegyzetekhez).
 * Formatum: [so(16)] [ rejtjel( MAGIC(4) || plain ) ]. */
static bool lockbox_encrypt_to_file(
    LockBoxApp* app,
    const char* path,
    const uint8_t* plain,
    size_t len) {
    bool ok = false;
    uint8_t* buf = NULL;
    File* f = storage_file_alloc(app->storage);
    do {
        size_t total = len + LOCKBOX_MAGIC_LEN;
        buf = malloc(total);
        if(!buf) break;
        memcpy(buf, LOCKBOX_MAGIC, LOCKBOX_MAGIC_LEN);
        memcpy(buf + LOCKBOX_MAGIC_LEN, plain, len);

        uint8_t salt[LOCKBOX_SALT_LEN];
        furi_hal_random_fill_buf(salt, sizeof(salt));
        uint8_t key[32];
        lockbox_derive_key(app, salt, key);
        lockbox_cipher(key, buf, total);

        if(!storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) break;
        if(storage_file_write(f, salt, sizeof(salt)) != sizeof(salt)) break;
        if(storage_file_write(f, buf, total) != total) break;
        ok = true;
    } while(false);
    storage_file_close(f);
    storage_file_free(f);
    if(buf) free(buf);
    return ok;
}

/* Titkositott fajl visszafejtese memoria-bufferbe (jegyzetekhez). A kimenet
 * nullal lezart C-string lesz. Rossz PIN/eszkoz -> MAGIC nem egyezik -> false. */
static bool lockbox_decrypt_from_file(
    LockBoxApp* app,
    const char* path,
    char* out,
    size_t out_cap) {
    bool ok = false;
    uint8_t* buf = NULL;
    File* f = storage_file_alloc(app->storage);
    do {
        if(!storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) break;
        uint64_t size = storage_file_size(f);
        if(size <= (uint64_t)(LOCKBOX_SALT_LEN + LOCKBOX_MAGIC_LEN)) break;
        if(size > (uint64_t)(LOCKBOX_SALT_LEN + LOCKBOX_MAGIC_LEN + LOCKBOX_MAX_FILE)) break;

        uint8_t salt[LOCKBOX_SALT_LEN];
        if(storage_file_read(f, salt, sizeof(salt)) != sizeof(salt)) break;

        size_t body = (size_t)size - LOCKBOX_SALT_LEN;
        buf = malloc(body);
        if(!buf) break;
        if(storage_file_read(f, buf, body) != body) break;

        uint8_t key[32];
        lockbox_derive_key(app, salt, key);
        lockbox_cipher(key, buf, body);

        if(memcmp(buf, LOCKBOX_MAGIC, LOCKBOX_MAGIC_LEN) != 0) break;

        size_t plain = body - LOCKBOX_MAGIC_LEN;
        if(plain > out_cap - 1) plain = out_cap - 1;
        memcpy(out, buf + LOCKBOX_MAGIC_LEN, plain);
        out[plain] = '\0';
        ok = true;
    } while(false);
    storage_file_close(f);
    storage_file_free(f);
    if(buf) free(buf);
    return ok;
}

/* Titkositott fajl visszafejtese NYERS bajtokba (barmilyen tartalom, nem csak
 * szoveg). A hivo szabaditja fel a *out buffert. */
static bool
    lockbox_decrypt_raw(LockBoxApp* app, const char* path, uint8_t** out, size_t* out_len) {
    *out = NULL;
    *out_len = 0;
    bool ok = false;
    uint8_t* buf = NULL;
    File* f = storage_file_alloc(app->storage);
    do {
        if(!storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) break;
        uint64_t size = storage_file_size(f);
        if(size <= (uint64_t)(LOCKBOX_SALT_LEN + LOCKBOX_MAGIC_LEN)) break;
        if(size > (uint64_t)(LOCKBOX_SALT_LEN + LOCKBOX_MAGIC_LEN + LOCKBOX_MAX_FILE)) break;

        uint8_t salt[LOCKBOX_SALT_LEN];
        if(storage_file_read(f, salt, sizeof(salt)) != sizeof(salt)) break;
        size_t body = (size_t)size - LOCKBOX_SALT_LEN;
        buf = malloc(body);
        if(!buf) break;
        if(storage_file_read(f, buf, body) != body) break;

        uint8_t key[32];
        lockbox_derive_key(app, salt, key);
        lockbox_cipher(key, buf, body);
        if(memcmp(buf, LOCKBOX_MAGIC, LOCKBOX_MAGIC_LEN) != 0) break;

        size_t plain = body - LOCKBOX_MAGIC_LEN;
        uint8_t* p = malloc(plain ? plain : 1);
        if(!p) break;
        memcpy(p, buf + LOCKBOX_MAGIC_LEN, plain);
        *out = p;
        *out_len = plain;
        ok = true;
    } while(false);
    storage_file_close(f);
    storage_file_free(f);
    if(buf) free(buf);
    return ok;
}

/* Megnyithato-e az elem a JELENLEGI (session) PIN-nel? (Nem ir ki semmit.)
 * Ennek alapjan dontjuk el, kell-e a "Try old PIN" menupont. */
static bool lockbox_can_decrypt(LockBoxApp* app, const char* path) {
    bool saved = app->use_recovery_pin;
    app->use_recovery_pin = false; /* a session PIN-nel probaljuk */
    uint8_t* plain = NULL;
    size_t len = 0;
    bool ok = lockbox_decrypt_raw(app, path, &plain, &len);
    app->use_recovery_pin = saved;
    if(plain) free(plain);
    return ok;
}

/* Lentebb (a PIN szekcioban) definialva; a fomenu darabszamat frissiti. */
static void lockbox_update_menu_header(LockBoxApp* app);

/* ====================================================================== *
 *                 Import (titkositva a szefbe, AThelyezes)               *
 * ====================================================================== */

/* Formatum a .lbx fajlban: [so(16)] [ rejtjel( MAGIC(4) || eredeti ) ].
 * Sikeres iras utan TORLI a forrast -> eltunik a regi helyerol (es az appbol). */
static bool lockbox_import(
    LockBoxApp* app,
    const char* src_path,
    const char* vault_dir,
    bool* out_removed) {
    bool ok = false;
    if(out_removed) *out_removed = false;
    uint8_t* buf = NULL;
    File* src = storage_file_alloc(app->storage);
    File* dst = storage_file_alloc(app->storage);

    do {
        storage_common_mkdir(app->storage, LOCKBOX_DIR);
        storage_common_mkdir(app->storage, vault_dir);

        if(!storage_file_open(src, src_path, FSAM_READ, FSOM_OPEN_EXISTING)) break;
        uint64_t size = storage_file_size(src);
        if(size == 0 || size > LOCKBOX_MAX_FILE) break;

        size_t total = (size_t)size + LOCKBOX_MAGIC_LEN;
        buf = malloc(total);
        if(!buf) break;
        memcpy(buf, LOCKBOX_MAGIC, LOCKBOX_MAGIC_LEN);
        if(storage_file_read(src, buf + LOCKBOX_MAGIC_LEN, (size_t)size) != (size_t)size) break;

        /* Veletlen so + kulcs + titkositas. */
        uint8_t salt[LOCKBOX_SALT_LEN];
        furi_hal_random_fill_buf(salt, sizeof(salt));
        uint8_t key[32];
        lockbox_derive_key(app, salt, key);
        lockbox_cipher(key, buf, total);

        const char* name = strrchr(src_path, '/');
        name = name ? name + 1 : src_path;
        char dst_path[256];
        snprintf(dst_path, sizeof(dst_path), "%s/%s.lbx", vault_dir, name);

        if(!storage_file_open(dst, dst_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) break;
        if(storage_file_write(dst, salt, sizeof(salt)) != sizeof(salt)) break;
        if(storage_file_write(dst, buf, total) != total) break;

        ok = true;
    } while(false);

    storage_file_close(src);
    storage_file_free(src);
    storage_file_close(dst);
    storage_file_free(dst);
    if(buf) free(buf);

    if(ok) {
        FS_Error err = storage_common_remove(app->storage, src_path);
        if(out_removed) *out_removed = (err == FSE_OK || err == FSE_NOT_EXIST);
    }
    return ok;
}

/* ====================================================================== *
 *                 Decrypt (visszafejtes a helyere)                      *
 * ====================================================================== */

static bool lockbox_decrypt(
    LockBoxApp* app,
    const char* lbx_path,
    char* out_dest,
    size_t out_dest_sz) {
    bool ok = false;
    uint8_t* buf = NULL;
    File* src = storage_file_alloc(app->storage);
    File* dst = storage_file_alloc(app->storage);

    do {
        if(!storage_file_open(src, lbx_path, FSAM_READ, FSOM_OPEN_EXISTING)) break;
        uint64_t size = storage_file_size(src);
        if(size <= (uint64_t)(LOCKBOX_SALT_LEN + LOCKBOX_MAGIC_LEN)) break;
        if(size > (uint64_t)(LOCKBOX_SALT_LEN + LOCKBOX_MAGIC_LEN + LOCKBOX_MAX_FILE)) break;

        uint8_t salt[LOCKBOX_SALT_LEN];
        if(storage_file_read(src, salt, sizeof(salt)) != sizeof(salt)) break;

        size_t body = (size_t)size - LOCKBOX_SALT_LEN;
        buf = malloc(body);
        if(!buf) break;
        if(storage_file_read(src, buf, body) != body) break;

        uint8_t key[32];
        lockbox_derive_key(app, salt, key);
        lockbox_cipher(key, buf, body);

        /* Helyes PIN/eszkoz ellenorzese a MAGIC fejlec alapjan. */
        if(memcmp(buf, LOCKBOX_MAGIC, LOCKBOX_MAGIC_LEN) != 0) break;

        /* Eredeti nev: '/'-utani resz, vegerol a ".lbx" levagva. */
        const char* base = strrchr(lbx_path, '/');
        base = base ? base + 1 : lbx_path;
        char inner[200];
        snprintf(inner, sizeof(inner), "%s", base);
        char* dot = strrchr(inner, '.');
        if(dot && strcmp(dot, ".lbx") == 0) *dot = '\0';

        const char* dest_dir = NFC_SRC_DIR;
        size_t ilen = strlen(inner);
        if(ilen >= 5 && strcmp(inner + ilen - 5, ".rfid") == 0) {
            dest_dir = RFID_SRC_DIR;
        } else if(ilen >= 4 && strcmp(inner + ilen - 4, ".sub") == 0) {
            dest_dir = SUBGHZ_SRC_DIR;
        } else if(ilen >= 5 && strcmp(inner + ilen - 5, ".ibtn") == 0) {
            dest_dir = IBTN_SRC_DIR;
        } else if(ilen >= 3 && strcmp(inner + ilen - 3, ".ir") == 0) {
            dest_dir = INFRARED_SRC_DIR;
        }
        snprintf(out_dest, out_dest_sz, "%s/%s", dest_dir, inner);

        if(!storage_file_open(dst, out_dest, FSAM_WRITE, FSOM_CREATE_ALWAYS)) break;
        size_t plain = body - LOCKBOX_MAGIC_LEN;
        if(storage_file_write(dst, buf + LOCKBOX_MAGIC_LEN, plain) != plain) break;

        ok = true;
    } while(false);

    storage_file_close(src);
    storage_file_free(src);
    storage_file_close(dst);
    storage_file_free(dst);
    if(buf) free(buf);

    if(ok) storage_common_remove(app->storage, lbx_path);
    return ok;
}

/* ====================================================================== *
 *                         Folyamatok (tallozo)                          *
 * ====================================================================== */

static void lockbox_import_flow(
    LockBoxApp* app,
    const char* start_dir,
    const char* ext,
    const char* vault_dir,
    const char* type_label) {
    FuriString* path = furi_string_alloc_set(start_dir);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, ext, NULL);

    bool picked = dialog_file_browser_show(app->dialogs, path, path, &opts);
    if(picked) {
        bool removed = false;
        bool ok = lockbox_import(app, furi_string_get_cstr(path), vault_dir, &removed);
        const char* name = strrchr(furi_string_get_cstr(path), '/');
        name = name ? name + 1 : furi_string_get_cstr(path);
        const char* body;
        if(!ok) {
            body = "Could not import (too big\nor read/write error).";
        } else if(removed) {
            body = "Encrypted (device-bound)\nand the original was removed\nfrom its app.";
        } else {
            body = "Encrypted into the vault,\nbut the ORIGINAL could NOT\nbe deleted. Delete it\nmanually.";
        }
        snprintf(
            app->result_buffer,
            sizeof(app->result_buffer),
            "%s encrypt %s\n"
            "----------------\n"
            "File: %s\n\n"
            "%s",
            type_label,
            ok ? "OK" : "FAILED",
            name,
            body);
        /* A fomenu darabszama azonnal frissuljon (ne csak ujrainditas utan). */
        if(ok) lockbox_update_menu_header(app);
        text_box_set_text(app->result_box, app->result_buffer);
        notification_message(app->notifications, ok ? &sequence_success : &sequence_error);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdResult);
    }
    furi_string_free(path);
}

/* ====================================================================== *
 *                    My Vault — a tarolt kartyak listaja                 *
 * ====================================================================== */

static void vault_menu_callback(void* context, uint32_t index);
static void item_menu_callback(void* context, uint32_t index);
static void lockbox_start_rename(LockBoxApp* app);
static void rename_done(void* context);

/* Recovery PIN-pad megnyitasa (regi PIN bevitele). is_note dönti el, kartya
 * vagy jegyzet visszafejtesehez probaljuk. */
static void lockbox_start_recover(LockBoxApp* app, bool is_note) {
    app->recover_is_note = is_note;
    app->use_recovery_pin = false;
    with_view_model(
        app->recover_view,
        PinModel * m,
        {
            memset(m, 0, sizeof(PinModel));
            m->mode = PinModeRecover;
        },
        true);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdRecoverPin);
}

/* Egy mappa .lbx fajljainak felvetele a listaba (teljes utvonallal). */
static void lockbox_scan_dir(LockBoxApp* app, const char* dir) {
    File* d = storage_file_alloc(app->storage);
    if(storage_dir_open(d, dir)) {
        FileInfo info;
        /* Kisebb, mint a cel-utvonal (LOCKBOX_PATH_LEN), hogy a "<dir>/<name>"
         * osszefuzes biztosan beleferjen -> nincs format-truncation figyelmeztetes. */
        char name[160];
        while(app->vault_count < LOCKBOX_MAX_ITEMS &&
              storage_dir_read(d, &info, name, sizeof(name))) {
            if(info.flags & FSF_DIRECTORY) continue;
            size_t nlen = strlen(name);
            if(nlen >= 4 && strcmp(name + nlen - 4, ".lbx") == 0) {
                snprintf(
                    app->vault_paths[app->vault_count],
                    LOCKBOX_PATH_LEN,
                    "%s/%s",
                    dir,
                    name);
                app->vault_count++;
            }
        }
        storage_dir_close(d);
    }
    storage_file_free(d);
}

static void lockbox_scan_vault(LockBoxApp* app) {
    app->vault_count = 0;
    lockbox_scan_dir(app, LOCKBOX_NFC_DIR);
    lockbox_scan_dir(app, LOCKBOX_RFID_DIR);
    lockbox_scan_dir(app, LOCKBOX_SUBGHZ_DIR);
    lockbox_scan_dir(app, LOCKBOX_IBTN_DIR);
    lockbox_scan_dir(app, LOCKBOX_INFRARED_DIR);
}

/* A megjelenitett nev: '/'-utani resz, a ".lbx" levagva. */
static void lockbox_display_name(const char* path, char* out, size_t out_sz) {
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(out, out_sz, "%s", base);
    size_t ll = strlen(out);
    if(ll >= 4 && strcmp(out + ll - 4, ".lbx") == 0) out[ll - 4] = '\0';
}

static void lockbox_build_vault_menu(LockBoxApp* app) {
    lockbox_scan_vault(app);
    submenu_reset(app->vault_menu);

    char hdr[32];
    snprintf(hdr, sizeof(hdr), "My Vault  (%u)", app->vault_count);
    submenu_set_header(app->vault_menu, hdr);

    if(app->vault_count == 0) {
        submenu_add_item(app->vault_menu, "(vault is empty)", 0xFF, vault_menu_callback, app);
    } else {
        for(uint8_t i = 0; i < app->vault_count; i++) {
            char label[64];
            lockbox_display_name(app->vault_paths[i], label, sizeof(label));
            submenu_add_item(app->vault_menu, label, i, vault_menu_callback, app);
        }
    }
}

static void lockbox_build_item_menu(LockBoxApp* app) {
    submenu_reset(app->item_menu);
    char hdr[32];
    lockbox_display_name(app->vault_paths[app->selected_index], hdr, sizeof(hdr));
    submenu_set_header(app->item_menu, hdr);
    submenu_add_item(
        app->item_menu, "Decrypt (restore)", ItemActionDecrypt, item_menu_callback, app);
    /* "Try old PIN" csak akkor kell, ha a JELENLEGI PIN-nel nem nyithato. */
    if(!lockbox_can_decrypt(app, app->vault_paths[app->selected_index])) {
        submenu_add_item(
            app->item_menu, "Try old PIN", ItemActionOldPin, item_menu_callback, app);
    }
    submenu_add_item(app->item_menu, "Rename", ItemActionRename, item_menu_callback, app);
    submenu_add_item(
        app->item_menu, "Delete from vault", ItemActionDelete, item_menu_callback, app);
}

static void vault_menu_callback(void* context, uint32_t index) {
    LockBoxApp* app = context;
    if(index == 0xFF) return; /* ures-placeholder */
    app->selected_index = (uint8_t)index;
    lockbox_build_item_menu(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdItem);
}

static void item_menu_callback(void* context, uint32_t index) {
    LockBoxApp* app = context;
    const char* path = app->vault_paths[app->selected_index];

    if(index == ItemActionOldPin) {
        /* Regi PIN-nel probaljuk visszafejteni ezt a kartyat. */
        lockbox_start_recover(app, false);
        return;
    }

    if(index == ItemActionRename) {
        lockbox_start_rename(app);
        return;
    }

    if(index == ItemActionDecrypt) {
        char dest[256] = {0};
        bool ok = lockbox_decrypt(app, path, dest, sizeof(dest));
        if(ok) {
            snprintf(
                app->result_buffer,
                sizeof(app->result_buffer),
                "Decrypt OK\n"
                "----------------\n"
                "Restored to:\n%s\n\n"
                "Back in its app and\nremoved from the vault.",
                dest);
        } else {
            snprintf(
                app->result_buffer,
                sizeof(app->result_buffer),
                "Decrypt FAILED\n"
                "----------------\n"
                "Wrong PIN, wrong Flipper,\n"
                "or a read/write error.\n\n"
                "The vault file was kept.");
        }
        notification_message(app->notifications, ok ? &sequence_success : &sequence_error);
    } else { /* ItemActionDelete */
        FS_Error err = storage_common_remove(app->storage, path);
        bool ok = (err == FSE_OK);
        char nm[64];
        lockbox_display_name(path, nm, sizeof(nm));
        snprintf(
            app->result_buffer,
            sizeof(app->result_buffer),
            "Delete %s\n"
            "----------------\n"
            "Card: %s\n\n"
            "%s",
            ok ? "OK" : "FAILED",
            nm,
            ok ? "Removed from the vault.\nThe encrypted copy is gone\nfor good." :
                 "Could not delete the file.");
        notification_message(app->notifications, ok ? &sequence_success : &sequence_error);
    }

    /* A lista es a fomenu darabszama frissuljon a muvelet utan. */
    lockbox_build_vault_menu(app);
    lockbox_update_menu_header(app);
    text_box_set_text(app->result_box, app->result_buffer);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdResult);
}

/* ====================================================================== *
 *                    Secure Notes — titkos jegyzetek                     *
 * ====================================================================== */

static void notes_menu_callback(void* context, uint32_t index);
static void note_item_menu_callback(void* context, uint32_t index);
static void note_title_done(void* context);
static void note_text_done(void* context);
static void lockbox_build_notes_menu(LockBoxApp* app);

/* Fajlnevbe nem valo karakterek cserelese. */
static void lockbox_note_sanitize(const char* in, char* out, size_t out_sz) {
    size_t j = 0;
    for(size_t i = 0; in[i] && j < out_sz - 1; i++) {
        char ch = in[i];
        if(ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?' || ch == '"' ||
           ch == '<' || ch == '>' || ch == '|') {
            ch = '_';
        }
        out[j++] = ch;
    }
    out[j] = '\0';
}

static void lockbox_scan_notes(LockBoxApp* app) {
    app->note_count = 0;
    File* d = storage_file_alloc(app->storage);
    if(storage_dir_open(d, LOCKBOX_NOTES_DIR)) {
        FileInfo info;
        char name[160];
        while(app->note_count < LOCKBOX_MAX_ITEMS &&
              storage_dir_read(d, &info, name, sizeof(name))) {
            if(info.flags & FSF_DIRECTORY) continue;
            size_t nlen = strlen(name);
            if(nlen >= 4 && strcmp(name + nlen - 4, ".lbx") == 0) {
                snprintf(
                    app->note_paths[app->note_count],
                    LOCKBOX_PATH_LEN,
                    "%s/%s",
                    LOCKBOX_NOTES_DIR,
                    name);
                app->note_count++;
            }
        }
        storage_dir_close(d);
    }
    storage_file_free(d);
}

static void lockbox_build_notes_menu(LockBoxApp* app) {
    lockbox_scan_notes(app);
    submenu_reset(app->notes_menu);
    char hdr[32];
    snprintf(hdr, sizeof(hdr), "Secure Notes  (%u)", app->note_count);
    submenu_set_header(app->notes_menu, hdr);
    submenu_add_item(app->notes_menu, "+ New note", 0xFE, notes_menu_callback, app);
    for(uint8_t i = 0; i < app->note_count; i++) {
        char label[64];
        lockbox_display_name(app->note_paths[i], label, sizeof(label));
        submenu_add_item(app->notes_menu, label, i, notes_menu_callback, app);
    }
}

static void lockbox_build_note_item_menu(LockBoxApp* app) {
    submenu_reset(app->note_item_menu);
    char hdr[32];
    lockbox_display_name(app->note_paths[app->note_selected], hdr, sizeof(hdr));
    submenu_set_header(app->note_item_menu, hdr);
    submenu_add_item(app->note_item_menu, "View", NoteActionView, note_item_menu_callback, app);
    /* "View with old PIN" csak akkor kell, ha a JELENLEGI PIN-nel nem nyithato. */
    if(!lockbox_can_decrypt(app, app->note_paths[app->note_selected])) {
        submenu_add_item(
            app->note_item_menu,
            "View with old PIN",
            NoteActionOldPin,
            note_item_menu_callback,
            app);
    }
    submenu_add_item(
        app->note_item_menu, "Delete", NoteActionDelete, note_item_menu_callback, app);
}

static void lockbox_start_new_note(LockBoxApp* app) {
    app->note_title[0] = '\0';
    text_input_reset(app->title_input);
    text_input_set_header_text(app->title_input, "Note title");
    text_input_set_result_callback(
        app->title_input,
        note_title_done,
        app,
        app->note_title,
        sizeof(app->note_title),
        true);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdTitleInput);
}

static void note_title_done(void* context) {
    LockBoxApp* app = context;
    if(strlen(app->note_title) == 0) {
        lockbox_build_notes_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdNotes);
        return;
    }
    app->note_text[0] = '\0';
    text_input_reset(app->note_input);
    text_input_set_header_text(app->note_input, "Note text");
    text_input_set_result_callback(
        app->note_input, note_text_done, app, app->note_text, sizeof(app->note_text), true);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdNoteInput);
}

static void note_text_done(void* context) {
    LockBoxApp* app = context;
    char safe[LOCKBOX_NOTE_TITLE_LEN];
    lockbox_note_sanitize(app->note_title, safe, sizeof(safe));

    storage_common_mkdir(app->storage, LOCKBOX_DIR);
    storage_common_mkdir(app->storage, LOCKBOX_NOTES_DIR);
    char path[LOCKBOX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.lbx", LOCKBOX_NOTES_DIR, safe);

    bool ok = lockbox_encrypt_to_file(
        app, path, (const uint8_t*)app->note_text, strlen(app->note_text));
    snprintf(
        app->result_buffer,
        sizeof(app->result_buffer),
        "Note %s\n"
        "----------------\n"
        "Title: %s\n\n"
        "%s",
        ok ? "saved" : "FAILED",
        app->note_title,
        ok ? "Encrypted and stored in\nthe vault (device-bound)." :
             "Could not save the note.");
    notification_message(app->notifications, ok ? &sequence_success : &sequence_error);

    lockbox_build_notes_menu(app);
    text_box_set_text(app->result_box, app->result_buffer);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdResult);
}

static void notes_menu_callback(void* context, uint32_t index) {
    LockBoxApp* app = context;
    if(index == 0xFE) {
        lockbox_start_new_note(app);
        return;
    }
    app->note_selected = (uint8_t)index;
    lockbox_build_note_item_menu(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdNoteItem);
}

static void note_item_menu_callback(void* context, uint32_t index) {
    LockBoxApp* app = context;
    const char* path = app->note_paths[app->note_selected];

    if(index == NoteActionOldPin) {
        /* Regi PIN-nel probaljuk megnyitni ezt a jegyzetet. */
        lockbox_start_recover(app, true);
        return;
    }

    if(index == NoteActionView) {
        char title[64];
        lockbox_display_name(path, title, sizeof(title));
        char body[LOCKBOX_NOTE_TEXT_LEN] = {0};
        bool ok = lockbox_decrypt_from_file(app, path, body, sizeof(body));
        if(ok) {
            snprintf(
                app->note_display,
                sizeof(app->note_display),
                "%s\n----------------\n%s",
                title,
                body);
        } else {
            snprintf(
                app->note_display,
                sizeof(app->note_display),
                "%s\n----------------\nCannot decrypt (wrong PIN\nor wrong Flipper).",
                title);
        }
        text_box_set_text(app->note_view, app->note_display);
        text_box_set_focus(app->note_view, TextBoxFocusStart);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdNoteView);
    } else { /* NoteActionDelete */
        FS_Error err = storage_common_remove(app->storage, path);
        bool ok = (err == FSE_OK);
        char nm[64];
        lockbox_display_name(path, nm, sizeof(nm));
        snprintf(
            app->result_buffer,
            sizeof(app->result_buffer),
            "Delete %s\n"
            "----------------\n"
            "Note: %s\n\n"
            "%s",
            ok ? "OK" : "FAILED",
            nm,
            ok ? "Removed from the vault." : "Could not delete.");
        notification_message(app->notifications, ok ? &sequence_success : &sequence_error);
        lockbox_build_notes_menu(app);
        text_box_set_text(app->result_box, app->result_buffer);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdResult);
    }
}

/* ====================================================================== *
 *                    Szef-tetel atnevezese                               *
 * ====================================================================== */

/* A szerkesztheto nev elokeszitese: levagjuk a ".lbx"-et es a tipus-vegzodest
 * (.nfc/.rfid/.sub/.ibtn/.ir), hogy a felhasznalo csak a "cimet" szerkessze; a
 * tipus-suffixet mentve, hogy visszafejteskor a helyere keruljon a fajl. */
static void lockbox_start_rename(LockBoxApp* app) {
    const char* path = app->vault_paths[app->selected_index];
    char disp[LOCKBOX_NOTE_TITLE_LEN];
    lockbox_display_name(path, disp, sizeof(disp)); /* pl. "mycard.nfc" */

    app->rename_suffix[0] = '\0';
    static const char* const sufs[] = {".rfid", ".ibtn", ".nfc", ".sub", ".ir"};
    size_t dl = strlen(disp);
    for(unsigned i = 0; i < 5; i++) {
        size_t sl = strlen(sufs[i]);
        if(dl > sl && strcmp(disp + dl - sl, sufs[i]) == 0) {
            snprintf(app->rename_suffix, sizeof(app->rename_suffix), "%s", sufs[i]);
            disp[dl - sl] = '\0';
            break;
        }
    }
    snprintf(app->rename_buf, sizeof(app->rename_buf), "%s", disp);

    text_input_reset(app->rename_input);
    text_input_set_header_text(app->rename_input, "New name");
    text_input_set_result_callback(
        app->rename_input, rename_done, app, app->rename_buf, sizeof(app->rename_buf), false);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdRenameInput);
}

static void rename_done(void* context) {
    LockBoxApp* app = context;
    const char* oldpath = app->vault_paths[app->selected_index];

    /* A mappa resz (az utolso '/' elotti). */
    char dir[LOCKBOX_PATH_LEN];
    const char* slash = strrchr(oldpath, '/');
    size_t dirlen = slash ? (size_t)(slash - oldpath) : 0;
    if(dirlen >= sizeof(dir)) dirlen = sizeof(dir) - 1;
    memcpy(dir, oldpath, dirlen);
    dir[dirlen] = '\0';

    char safe[LOCKBOX_NOTE_TITLE_LEN];
    lockbox_note_sanitize(app->rename_buf, safe, sizeof(safe));
    if(strlen(safe) == 0) snprintf(safe, sizeof(safe), "renamed");

    char newpath[LOCKBOX_PATH_LEN + 64];
    snprintf(newpath, sizeof(newpath), "%s/%s%s.lbx", dir, safe, app->rename_suffix);

    bool ok;
    if(strcmp(newpath, oldpath) == 0) {
        ok = true; /* nincs valtozas */
    } else {
        ok = (storage_common_rename(app->storage, oldpath, newpath) == FSE_OK);
    }

    snprintf(
        app->result_buffer,
        sizeof(app->result_buffer),
        "Rename %s\n"
        "----------------\n"
        "New name:\n%s%s\n\n"
        "%s",
        ok ? "OK" : "FAILED",
        safe,
        app->rename_suffix,
        ok ? "The encrypted file was\nrenamed in the vault." :
             "Could not rename (name in\nuse or write error).");
    notification_message(app->notifications, ok ? &sequence_success : &sequence_error);

    lockbox_build_vault_menu(app);
    text_box_set_text(app->result_box, app->result_buffer);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdResult);
}

/* ====================================================================== *
 *                            PIN nezet                                   *
 * ====================================================================== */

static void pin_view_reset_entry(PinModel* m) {
    m->cur.len = 0;
}

/* Egy iranygomb-szimbolum kirajzolasa egy w x h cellaba, kozepre. */
static void draw_pin_symbol(Canvas* canvas, int cx, int cy, uint8_t sym) {
    /* cx,cy = a cella kozeppontja; ~7px meretu nyil. */
    switch(sym) {
    case PinSymUp:
        canvas_draw_line(canvas, cx, cy - 3, cx, cy + 3);
        canvas_draw_line(canvas, cx, cy - 3, cx - 2, cy - 1);
        canvas_draw_line(canvas, cx, cy - 3, cx + 2, cy - 1);
        break;
    case PinSymDown:
        canvas_draw_line(canvas, cx, cy - 3, cx, cy + 3);
        canvas_draw_line(canvas, cx, cy + 3, cx - 2, cy + 1);
        canvas_draw_line(canvas, cx, cy + 3, cx + 2, cy + 1);
        break;
    case PinSymLeft:
        canvas_draw_line(canvas, cx - 3, cy, cx + 3, cy);
        canvas_draw_line(canvas, cx - 3, cy, cx - 1, cy - 2);
        canvas_draw_line(canvas, cx - 3, cy, cx - 1, cy + 2);
        break;
    case PinSymRight:
        canvas_draw_line(canvas, cx - 3, cy, cx + 3, cy);
        canvas_draw_line(canvas, cx + 3, cy, cx + 1, cy - 2);
        canvas_draw_line(canvas, cx + 3, cy, cx + 1, cy + 2);
        break;
    case PinSymBack:
    default:
        /* Vissza: egy kis "U" nyil balra. */
        canvas_draw_line(canvas, cx - 3, cy, cx + 2, cy);
        canvas_draw_line(canvas, cx + 2, cy, cx + 2, cy + 3);
        canvas_draw_line(canvas, cx - 3, cy, cx - 1, cy - 2);
        canvas_draw_line(canvas, cx - 3, cy, cx - 1, cy + 2);
        break;
    }
}

/* Egy kis uszkalo delfin (Flipper-hangulat). x,y = a test kozeppontja; jobbra
 * nez, ~20px szeles, ~10px magas. frame alapjan bukdacsol es csapkod a farka. */
static void draw_dolphin(Canvas* c, int x, int y, uint32_t frame) {
    int bobtab[4] = {0, -1, 0, 1};
    y += bobtab[(frame >> 1) & 3];
    int tail = (frame & 2) ? 1 : -1;

    /* Hat (farok -> orr), felfele ivelve. */
    canvas_draw_line(c, x - 8, y + 2, x - 3, y - 2);
    canvas_draw_line(c, x - 3, y - 2, x + 3, y - 3);
    canvas_draw_line(c, x + 3, y - 3, x + 9, y + 1);
    /* Has (orr -> farok). */
    canvas_draw_line(c, x + 9, y + 1, x + 4, y + 3);
    canvas_draw_line(c, x + 4, y + 3, x - 2, y + 3);
    canvas_draw_line(c, x - 2, y + 3, x - 8, y + 2);
    /* Hatuszony. */
    canvas_draw_line(c, x, y - 3, x + 2, y - 6);
    canvas_draw_line(c, x + 2, y - 6, x + 4, y - 3);
    /* Farokuszony (csapkod). */
    canvas_draw_line(c, x - 8, y + 2, x - 11, y + tail);
    canvas_draw_line(c, x - 8, y + 2, x - 11, y + 3 + tail);
    /* Szem. */
    canvas_draw_dot(c, x + 6, y);
}

static void pin_view_draw_callback(Canvas* canvas, void* model) {
    PinModel* m = model;
    canvas_clear(canvas);

    /* Vizszintesen uszkalo delfin-pozicio (loop a kepernyon at). */
    int dolph_x = (int)((m->anim * 2u) % 168u) - 20;

    /* Zarolt allapot: a brute-force vedelem miatt vissza kell szamolni. */
    if(m->locked) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, 64, 20, AlignCenter, AlignBottom, "Locked");
        char line[32];
        unsigned s = (unsigned)m->remaining;
        if(s >= 60) {
            snprintf(line, sizeof(line), "Try again in %um %us", s / 60, s % 60);
        } else {
            snprintf(line, sizeof(line), "Try again in %us", s);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 38, AlignCenter, AlignBottom, line);
        canvas_draw_str_aligned(
            canvas, 64, 52, AlignCenter, AlignBottom, "Too many wrong PINs");
        draw_dolphin(canvas, dolph_x, 60, m->anim); /* a delfin orjarja a zarat */
        return;
    }

    const char* title = "Enter PIN";
    if(m->mode == PinModeSet)
        title = "Set a new PIN";
    else if(m->mode == PinModeConfirm)
        title = "Confirm PIN";
    else if(m->mode == PinModeRecover)
        title = "Enter OLD PIN";

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 10, AlignCenter, AlignBottom, title);

    /* Uszkalo delfin a cim es a PIN-cellak kozotti savban. */
    draw_dolphin(canvas, dolph_x, 17, m->anim);

    /* A bevitt sorozat: PIN_MAX kis cella, a betoltotteket nyil tolti ki. */
    const int cw = 11; /* cella szelesseg */
    const int ch = 15; /* cella magassag */
    const int gap = 1;
    int total = PIN_MAX * cw + (PIN_MAX - 1) * gap;
    int x0 = (128 - total) / 2;
    int y0 = 23;
    for(uint8_t i = 0; i < PIN_MAX; i++) {
        int x = x0 + i * (cw + gap);
        bool filled = i < m->cur.len;
        canvas_draw_rframe(canvas, x, y0, cw, ch, 2);
        if(filled) {
            draw_pin_symbol(canvas, x + cw / 2, y0 + ch / 2, m->cur.s[i]);
        }
    }

    canvas_set_font(canvas, FontSecondary);

    /* Kozepso sor: hiba / instrukcio. */
    const char* mid;
    if(m->error) {
        mid = (m->mode == PinModeConfirm) ? "Does not match" : "Wrong PIN, try again";
    } else if(m->cur.len == 0) {
        mid = "Arrows + Back = PIN";
    } else {
        mid = "OK to confirm";
    }
    canvas_draw_str_aligned(canvas, 64, 49, AlignCenter, AlignBottom, mid);

    /* Also sor: belepeskor "Hold [<-] to close app" rajzolt vissza-nyillal. */
    if(m->mode == PinModeVerify) {
        const char* a = "Hold ";
        const char* b = " to close app";
        uint16_t wa = canvas_string_width(canvas, a);
        uint16_t wb = canvas_string_width(canvas, b);
        const uint16_t warrow = 8;
        int sx = (128 - (int)(wa + warrow + wb)) / 2;
        if(sx < 0) sx = 0;
        canvas_draw_str(canvas, sx, 63, a);
        int ax = sx + wa + 1;
        int ay = 60;
        canvas_draw_line(canvas, ax, ay, ax + 5, ay);
        canvas_draw_line(canvas, ax, ay, ax + 2, ay - 2);
        canvas_draw_line(canvas, ax, ay, ax + 2, ay + 2);
        canvas_draw_str(canvas, sx + wa + warrow, 63, b);
    } else {
        canvas_draw_str_aligned(canvas, 64, 62, AlignCenter, AlignBottom, "Hold Back to cancel");
    }
}

/* 2x masodpercenkent frissiti a zarolas-visszaszamlalot a PIN nezeten. */
static void lockbox_lock_timer_callback(void* context) {
    LockBoxApp* app = context;
    uint32_t now = lockbox_now();
    with_view_model(
        app->pin_view,
        PinModel * m,
        {
            uint32_t rem = (app->lock_until > now) ? (app->lock_until - now) : 0;
            m->locked = (m->mode == PinModeVerify) && (rem > 0);
            m->remaining = rem;
        },
        true);
}

/* A delfin-animacio lepteto idozitoje (~120ms). A PIN- es a recovery-nezet
 * keptszamlalojat is novel, igy mindket helyen uszik a delfin. */
static void lockbox_anim_timer_callback(void* context) {
    LockBoxApp* app = context;
    with_view_model(app->pin_view, PinModel * m, { m->anim++; }, true);
    with_view_model(app->recover_view, PinModel * m, { m->anim++; }, true);
}

/* A fomenu fejlecenek frissitese az elo kartyaszammal. Barmely muvelet utan
 * meghivhato, hogy a "LockBox - N cards" azonnal helyes legyen. */
static void lockbox_update_menu_header(LockBoxApp* app) {
    lockbox_scan_vault(app);
    snprintf(
        app->menu_header, sizeof(app->menu_header), "LockBox  -  %u cards", app->vault_count);
    submenu_set_header(app->menu, app->menu_header);
}

static void lockbox_show_menu(LockBoxApp* app) {
    lockbox_update_menu_header(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);
}

static void lockbox_show_rekey(LockBoxApp* app); /* lentebb definialva */

/* Egy iranygomb -> PIN-szimbolum, vagy -1 ha nem iranygomb. */
static int pin_key_to_sym(InputKey key) {
    switch(key) {
    case InputKeyUp:
        return PinSymUp;
    case InputKeyDown:
        return PinSymDown;
    case InputKeyLeft:
        return PinSymLeft;
    case InputKeyRight:
        return PinSymRight;
    case InputKeyBack:
        return PinSymBack;
    default:
        return -1;
    }
}

static bool pin_view_input_callback(InputEvent* event, void* context) {
    LockBoxApp* app = context;

    /* HOSSZU Back = kilepes (belepeskor) vagy megse (Change PIN -> menu). */
    if(event->key == InputKeyBack && event->type == InputTypeLong) {
        PinMode mode;
        with_view_model(app->pin_view, PinModel * m, { mode = m->mode; }, false);
        if(app->changing_pin && (mode == PinModeSet || mode == PinModeConfirm)) {
            app->changing_pin = false;
            lockbox_show_menu(app);
        } else {
            view_dispatcher_stop(app->view_dispatcher);
        }
        return true;
    }

    /* Csak rovid nyomasokat dolgozunk fel (nincs auto-ismetles a PIN-nel). */
    if(event->type != InputTypeShort) {
        return false;
    }

    /* Zarolas CSAK a belepesnel (Verify) ervenyes. Uj PIN beallitasakor (Set/
     * Confirm) soha nem zar ki. */
    PinMode cur_mode;
    with_view_model(app->pin_view, PinModel * m, { cur_mode = m->mode; }, false);
    if(cur_mode == PinModeVerify && lockbox_now() < app->lock_until) {
        return true;
    }

    /* Iranygomb (Fel/Le/Balra/Jobbra/Vissza) -> szimbolum hozzaadasa. */
    int sym = pin_key_to_sym(event->key);
    if(sym >= 0) {
        with_view_model(
            app->pin_view,
            PinModel * m,
            {
                m->error = false;
                if(m->cur.len < PIN_MAX) m->cur.s[m->cur.len++] = (uint8_t)sym;
            },
            true);
        return true;
    }

    /* OK -> megerosites. Minden mas gombot elnyelunk. */
    if(event->key != InputKeyOk) {
        return true;
    }

    PinVal entered, first;
    PinMode mode;
    with_view_model(
        app->pin_view,
        PinModel * m,
        {
            mode = m->mode;
            entered = m->cur;
            first = m->first;
        },
        false);

    /* Tul rovid PIN -> hiba. */
    if(entered.len < PIN_MIN) {
        with_view_model(
            app->pin_view,
            PinModel * m,
            {
                m->error = true;
                pin_view_reset_entry(m);
            },
            true);
        notification_message(app->notifications, &sequence_error);
        return true;
    }

    if(mode == PinModeSet) {
        with_view_model(
            app->pin_view,
            PinModel * m,
            {
                m->first = entered;
                m->mode = PinModeConfirm;
                pin_view_reset_entry(m);
            },
            true);
    } else if(mode == PinModeConfirm) {
        if(pin_equal(&entered, &first)) {
            bool was_changing = app->changing_pin;
            bool pin_changed = was_changing && !pin_equal(&entered, &app->old_pin_for_rekey);
            lockbox_pin_save(app, &entered);
            app->session_pin = entered;
            app->changing_pin = false;
            /* Uj PIN -> a hibaszamlalo es a zarolas nullazodik. */
            app->fail_count = 0;
            app->lock_until = 0;
            lockbox_lock_save(app);
            notification_message(app->notifications, &sequence_success);
            if(pin_changed) {
                lockbox_show_rekey(app);
            } else {
                lockbox_show_menu(app);
            }
        } else {
            with_view_model(
                app->pin_view,
                PinModel * m,
                {
                    m->mode = PinModeSet;
                    m->error = true;
                    pin_view_reset_entry(m);
                },
                true);
            notification_message(app->notifications, &sequence_error);
        }
    } else { /* PinModeVerify */
        if(lockbox_pin_check(app, &entered)) {
            /* Sikeres belepes -> a brute-force letra TELJESEN nullazodik, igy
             * egy kesobbi rossz PIN megint elolrol kezdi a zarolas-idozitest. */
            lockbox_lock_reset(app);
            app->session_pin = entered;
            notification_message(app->notifications, &sequence_success);
            lockbox_show_menu(app);
        } else {
            app->fail_count++;

            /* Panic-wipe: ha be van kapcsolva es elertuk a kuszobot, csendben
             * toroljuk a szefet. (Nem jelezzuk kulon -> letagadhato.) A letra
             * nullazodik, hogy a tamado ne lasson gyanus viselkedest. */
            if(app->panic_enabled && app->fail_count >= app->panic_threshold) {
                lockbox_panic_wipe(app);
                lockbox_lock_reset(app);
                with_view_model(
                    app->pin_view,
                    PinModel * m,
                    {
                        m->error = true;
                        m->locked = false;
                        m->remaining = 0;
                        pin_view_reset_entry(m);
                    },
                    true);
                notification_message(app->notifications, &sequence_error);
                return true;
            }

            uint32_t secs = lockbox_lock_seconds(app->fail_count);
            if(secs > 0) {
                app->lock_until = lockbox_now() + secs;
            }
            lockbox_lock_save(app);
            with_view_model(
                app->pin_view,
                PinModel * m,
                {
                    m->error = true;
                    pin_view_reset_entry(m);
                    if(secs > 0) {
                        m->locked = true;
                        m->remaining = secs;
                    }
                },
                true);
            notification_message(app->notifications, &sequence_error);
        }
    }

    return true;
}

/* ====================================================================== *
 *                    Recovery — visszafejtes regi PIN-nel                *
 * ====================================================================== */

/* A recover_view-ban megadott regi PIN-nel megprobalja visszafejteni a kivalasztott
 * kartyat vagy jegyzetet. Siker -> helyreallitas/megtekintes; hiba -> "wrong PIN". */
static void lockbox_try_recover(LockBoxApp* app, const PinVal* oldpin) {
    app->recovery_pin = *oldpin;
    app->use_recovery_pin = true;

    bool ok = false;
    if(app->recover_is_note) {
        const char* path = app->note_paths[app->note_selected];
        char title[64];
        lockbox_display_name(path, title, sizeof(title));
        char body[LOCKBOX_NOTE_TEXT_LEN] = {0};
        ok = lockbox_decrypt_from_file(app, path, body, sizeof(body));
        if(ok) {
            snprintf(
                app->note_display,
                sizeof(app->note_display),
                "%s\n----------------\n%s",
                title,
                body);
        }
        app->use_recovery_pin = false;
        if(ok) {
            text_box_set_text(app->note_view, app->note_display);
            text_box_set_focus(app->note_view, TextBoxFocusStart);
            notification_message(app->notifications, &sequence_success);
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdNoteView);
            return;
        }
    } else {
        const char* path = app->vault_paths[app->selected_index];
        char dest[256] = {0};
        ok = lockbox_decrypt(app, path, dest, sizeof(dest));
        app->use_recovery_pin = false;
        if(ok) {
            snprintf(
                app->result_buffer,
                sizeof(app->result_buffer),
                "Recovered with old PIN\n"
                "----------------\n"
                "Restored to:\n%s\n\n"
                "Back in its app and\nremoved from the vault.",
                dest);
            lockbox_build_vault_menu(app);
            lockbox_update_menu_header(app);
            text_box_set_text(app->result_box, app->result_buffer);
            notification_message(app->notifications, &sequence_success);
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdResult);
            return;
        }
    }

    /* Nem sikerult -> hiba a recovery paden, ujra lehet probalni. */
    with_view_model(
        app->recover_view,
        PinModel * m,
        {
            m->error = true;
            pin_view_reset_entry(m);
        },
        true);
    notification_message(app->notifications, &sequence_error);
}

static bool recover_pin_input_callback(InputEvent* event, void* context) {
    LockBoxApp* app = context;

    /* HOSSZU Back = megse (vissza a muvelet-menube). A rovid Back viszont PIN-
     * szimbolum, mert a regi PIN tartalmazhat Back-et. */
    if(event->key == InputKeyBack && event->type == InputTypeLong) {
        view_dispatcher_switch_to_view(
            app->view_dispatcher, app->recover_is_note ? ViewIdNoteItem : ViewIdItem);
        return true;
    }

    if(event->type != InputTypeShort) {
        return false;
    }

    int sym = pin_key_to_sym(event->key);
    if(sym >= 0) {
        with_view_model(
            app->recover_view,
            PinModel * m,
            {
                m->error = false;
                if(m->cur.len < PIN_MAX) m->cur.s[m->cur.len++] = (uint8_t)sym;
            },
            true);
        return true;
    }

    if(event->key != InputKeyOk) {
        return true;
    }

    PinVal entered;
    with_view_model(app->recover_view, PinModel * m, { entered = m->cur; }, false);
    if(entered.len < PIN_MIN) {
        with_view_model(
            app->recover_view,
            PinModel * m,
            {
                m->error = true;
                pin_view_reset_entry(m);
            },
            true);
        notification_message(app->notifications, &sequence_error);
        return true;
    }
    lockbox_try_recover(app, &entered);
    return true;
}

/* ====================================================================== *
 *                 *bullshit ass  
 * ====================================================================== */

/* Egy fajl ujrakulcsolasa: visszafejtes a REGI PIN-nel, ujratitkositas az UJ
 * (session) PIN-nel, ugyanabba a fajlba. */
static bool lockbox_rekey_file(LockBoxApp* app, const char* path) {
    uint8_t* plain = NULL;
    size_t len = 0;

    app->use_recovery_pin = true;
    app->recovery_pin = app->old_pin_for_rekey;
    bool ok = lockbox_decrypt_raw(app, path, &plain, &len);
    app->use_recovery_pin = false; /* innentol a session (uj) PIN-nel titkositunk */

    if(ok) ok = lockbox_encrypt_to_file(app, path, plain, len);
    if(plain) free(plain);
    return ok;
}

static void lockbox_rekey_all(LockBoxApp* app, uint32_t* done, uint32_t* fail) {
    *done = 0;
    *fail = 0;
    /* A listakat memoriaba olvassuk, igy a fajlok felulirasa nem zavarja a
     * konyvtar-bejarast. */
    lockbox_scan_vault(app);
    for(uint8_t i = 0; i < app->vault_count; i++) {
        if(lockbox_rekey_file(app, app->vault_paths[i]))
            (*done)++;
        else
            (*fail)++;
    }
    lockbox_scan_notes(app);
    for(uint8_t i = 0; i < app->note_count; i++) {
        if(lockbox_rekey_file(app, app->note_paths[i]))
            (*done)++;
        else
            (*fail)++;
    }
}

static void rekey_menu_callback(void* context, uint32_t index) {
    LockBoxApp* app = context;
    if(index == RekeyActionYes) {
        uint32_t done = 0, fail = 0;
        lockbox_rekey_all(app, &done, &fail);
        memset(&app->old_pin_for_rekey, 0, sizeof(app->old_pin_for_rekey));
        snprintf(
            app->result_buffer,
            sizeof(app->result_buffer),
            "Re-encrypt %s\n"
            "----------------\n"
            "%u item(s) re-keyed\n"
            "%u failed\n\n"
            "Items now open with the\nnew PIN.",
            fail ? "done" : "OK",
            (unsigned)done,
            (unsigned)fail);
        notification_message(app->notifications, fail ? &sequence_error : &sequence_success);
        lockbox_update_menu_header(app);
        text_box_set_text(app->result_box, app->result_buffer);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdResult);
    } else {
        memset(&app->old_pin_for_rekey, 0, sizeof(app->old_pin_for_rekey));
        lockbox_show_menu(app);
    }
}

static void lockbox_show_rekey(LockBoxApp* app) {
    submenu_reset(app->rekey_menu);
    submenu_set_header(app->rekey_menu, "PIN changed");
    submenu_add_item(
        app->rekey_menu, "Encrypt all with new key", RekeyActionYes, rekey_menu_callback, app);
    submenu_add_item(
        app->rekey_menu, "Skip (keep old key)", RekeyActionNo, rekey_menu_callback, app);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdRekey);
}

/* ====================================================================== *
 *                    Settings — panic-wipe beallitasok                   *
 * ====================================================================== */

static void settings_menu_callback(void* context, uint32_t index);

static void lockbox_build_settings_menu(LockBoxApp* app) {
    submenu_reset(app->settings_menu);
    submenu_set_header(app->settings_menu, "Panic Wipe");
    char l1[40], l2[40], l3[40];
    snprintf(l1, sizeof(l1), "Panic wipe: %s", app->panic_enabled ? "ON" : "OFF");
    snprintf(l2, sizeof(l2), "Wipe after  -   (%u)", (unsigned)app->panic_threshold);
    snprintf(l3, sizeof(l3), "Wipe after  +   (%u)", (unsigned)app->panic_threshold);
    submenu_add_item(app->settings_menu, l1, SettingsPanicToggle, settings_menu_callback, app);
    submenu_add_item(app->settings_menu, l2, SettingsPanicLess, settings_menu_callback, app);
    submenu_add_item(app->settings_menu, l3, SettingsPanicMore, settings_menu_callback, app);
    submenu_add_item(app->settings_menu, "Back", SettingsBack, settings_menu_callback, app);
}

static void settings_menu_callback(void* context, uint32_t index) {
    LockBoxApp* app = context;
    switch(index) {
    case SettingsPanicToggle:
        app->panic_enabled = !app->panic_enabled;
        break;
    case SettingsPanicLess:
        if(app->panic_threshold > PANIC_WIPE_MIN) app->panic_threshold--;
        break;
    case SettingsPanicMore:
        if(app->panic_threshold < PANIC_WIPE_MAX) app->panic_threshold++;
        break;
    case SettingsBack:
    default:
        lockbox_show_menu(app);
        return;
    }
    lockbox_cfg_save(app);
    lockbox_build_settings_menu(app);
    submenu_set_selected_item(app->settings_menu, index);
}

/* ====================================================================== *
 *                            Fomenu                                      *
 * ====================================================================== */

static void menu_callback(void* context, uint32_t index) {
    LockBoxApp* app = context;
    switch(index) {
    case MenuIndexNfc:
        lockbox_import_flow(app, NFC_SRC_DIR, ".nfc", LOCKBOX_NFC_DIR, "NFC");
        break;
    case MenuIndexRfid:
        lockbox_import_flow(app, RFID_SRC_DIR, ".rfid", LOCKBOX_RFID_DIR, "RFID");
        break;
    case MenuIndexSubghz:
        lockbox_import_flow(app, SUBGHZ_SRC_DIR, ".sub", LOCKBOX_SUBGHZ_DIR, "SubGHz");
        break;
    case MenuIndexIbtn:
        lockbox_import_flow(app, IBTN_SRC_DIR, ".ibtn", LOCKBOX_IBTN_DIR, "iButton");
        break;
    case MenuIndexInfrared:
        lockbox_import_flow(app, INFRARED_SRC_DIR, ".ir", LOCKBOX_INFRARED_DIR, "Infrared");
        break;
    case MenuIndexVault:
        lockbox_build_vault_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdVault);
        break;
    case MenuIndexNotes:
        lockbox_build_notes_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdNotes);
        break;
    case MenuIndexSettings:
        lockbox_build_settings_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdSettings);
        break;
    case MenuIndexChangePin:
        /* Jeloljuk, hogy PIN-valtas folyik, es elmentjuk a mostani (regi) PIN-t
         * az esetleges ujratitkositashoz. */
        app->changing_pin = true;
        app->old_pin_for_rekey = app->session_pin;
        with_view_model(
            app->pin_view,
            PinModel * m,
            {
                m->mode = PinModeSet;
                m->error = false;
                pin_view_reset_entry(m);
            },
            true);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdPin);
        break;
    case MenuIndexAbout:
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdAbout);
        break;
    default:
        break;
    }
}

/* ====================================================================== *
 *                            Navigacio                                   *
 * ====================================================================== */

static uint32_t view_to_menu(void* context) {
    UNUSED(context);
    return ViewIdMenu;
}

static uint32_t view_to_vault(void* context) {
    UNUSED(context);
    return ViewIdVault;
}

static uint32_t view_to_notes(void* context) {
    UNUSED(context);
    return ViewIdNotes;
}

static uint32_t view_to_note_item(void* context) {
    UNUSED(context);
    return ViewIdNoteItem;
}

/* A recovery padrol a Back a megfelelo muvelet-menure visz vissza. */
static uint32_t view_recover_previous(void* context) {
    LockBoxApp* app = context;
    return app->recover_is_note ? ViewIdNoteItem : ViewIdItem;
}

static bool lockbox_navigation_callback(void* context) {
    LockBoxApp* app = context;
    view_dispatcher_stop(app->view_dispatcher);
    return true;
}

/* ====================================================================== *
 *                            Eletciklus                                  *
 * ====================================================================== */

static LockBoxApp* lockbox_app_alloc(void) {
    LockBoxApp* app = malloc(sizeof(LockBoxApp));
    memset(app, 0, sizeof(LockBoxApp));

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dialogs = furi_record_open(RECORD_DIALOGS);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, lockbox_navigation_callback);

    /* Brute-force zarolas-visszaszamlalo timer (2x masodpercenkent). */
    app->lock_timer =
        furi_timer_alloc(lockbox_lock_timer_callback, FuriTimerTypePeriodic, app);
    app->anim_timer = furi_timer_alloc(lockbox_anim_timer_callback, FuriTimerTypePeriodic, app);

    /* PIN nezet */
    app->pin_view = view_alloc();
    view_set_context(app->pin_view, app);
    view_allocate_model(app->pin_view, ViewModelTypeLocking, sizeof(PinModel));
    view_set_draw_callback(app->pin_view, pin_view_draw_callback);
    view_set_input_callback(app->pin_view, pin_view_input_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdPin, app->pin_view);

    /* Recovery PIN-pad (regi PIN) — ugyanaz a rajzolo, sajat input + model */
    app->recover_view = view_alloc();
    view_set_context(app->recover_view, app);
    view_allocate_model(app->recover_view, ViewModelTypeLocking, sizeof(PinModel));
    view_set_draw_callback(app->recover_view, pin_view_draw_callback);
    view_set_input_callback(app->recover_view, recover_pin_input_callback);
    view_set_previous_callback(app->recover_view, view_recover_previous);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdRecoverPin, app->recover_view);

    /* Fomenu */
    app->menu = submenu_alloc();
    submenu_set_header(app->menu, "LockBox");
    submenu_add_item(app->menu, "Encrypt NFC Card", MenuIndexNfc, menu_callback, app);
    submenu_add_item(app->menu, "Encrypt RFID Tag", MenuIndexRfid, menu_callback, app);
    submenu_add_item(app->menu, "Encrypt SubGHz", MenuIndexSubghz, menu_callback, app);
    submenu_add_item(app->menu, "Encrypt iButton", MenuIndexIbtn, menu_callback, app);
    submenu_add_item(app->menu, "Encrypt Infrared", MenuIndexInfrared, menu_callback, app);
    submenu_add_item(app->menu, "My Vault", MenuIndexVault, menu_callback, app);
    submenu_add_item(app->menu, "Secure Notes", MenuIndexNotes, menu_callback, app);
    submenu_add_item(app->menu, "Settings", MenuIndexSettings, menu_callback, app);
    submenu_add_item(app->menu, "Change PIN", MenuIndexChangePin, menu_callback, app);
    submenu_add_item(app->menu, "About", MenuIndexAbout, menu_callback, app);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdMenu, submenu_get_view(app->menu));

    /* My Vault lista (dinamikusan tolt) */
    app->vault_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->vault_menu), view_to_menu);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdVault, submenu_get_view(app->vault_menu));

    /* Kartya-muvelet almenu (Decrypt / Delete) */
    app->item_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->item_menu), view_to_vault);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdItem, submenu_get_view(app->item_menu));

    /* PIN-valtas utani ujratitkositas almenu */
    app->rekey_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->rekey_menu), view_to_menu);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdRekey, submenu_get_view(app->rekey_menu));

    /* Secure Notes: lista */
    app->notes_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->notes_menu), view_to_menu);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdNotes, submenu_get_view(app->notes_menu));

    /* Jegyzet-muvelet almenu (View / Delete) */
    app->note_item_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->note_item_menu), view_to_notes);
    view_dispatcher_add_view(
        app->view_dispatcher, ViewIdNoteItem, submenu_get_view(app->note_item_menu));

    /* Jegyzet megtekinto (visszafejtett szoveg) */
    app->note_view = text_box_alloc();
    view_set_previous_callback(text_box_get_view(app->note_view), view_to_note_item);
    view_dispatcher_add_view(
        app->view_dispatcher, ViewIdNoteView, text_box_get_view(app->note_view));

    /* Jegyzet cim + szoveg bevitel */
    app->title_input = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->title_input), view_to_notes);
    view_dispatcher_add_view(
        app->view_dispatcher, ViewIdTitleInput, text_input_get_view(app->title_input));

    app->note_input = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->note_input), view_to_notes);
    view_dispatcher_add_view(
        app->view_dispatcher, ViewIdNoteInput, text_input_get_view(app->note_input));

    /* Atnevezes bevitel (a szef-tetel muvelet-menujebol) */
    app->rename_input = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->rename_input), view_to_vault);
    view_dispatcher_add_view(
        app->view_dispatcher, ViewIdRenameInput, text_input_get_view(app->rename_input));

    /* Settings (panic-wipe) */
    app->settings_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->settings_menu), view_to_menu);
    view_dispatcher_add_view(
        app->view_dispatcher, ViewIdSettings, submenu_get_view(app->settings_menu));

    /* About */
    app->about_box = text_box_alloc();
    snprintf(
        app->about_buffer,
        sizeof(app->about_buffer),
        "LockBox %s\n"
        "----------------\n"
        "Device-bound vault for NFC,\n"
        "RFID, SubGHz, iButton & IR,\n"
        "plus Secure Notes.\n\n"
        "Key = THIS Flipper's serial\n"
        "+ your PIN (SHA-256 KDF).\n"
        "Never stored. A copied .lbx\n"
        "won't open on another\n"
        "Flipper or without the PIN.\n\n"
        "Encrypt: pick a file; it is\n"
        "locked into the vault and\n"
        "removed from its app.\n\n"
        "My Vault: decrypt, rename\n"
        "or delete stored items.\n\n"
        "Secure Notes: store text or\n"
        "passwords, encrypted too.\n\n"
        "Settings - Panic Wipe erases\n"
        "the vault after N wrong PINs\n"
        "(OFF by default).\n\n"
        "Wrong PIN locks you out,\n"
        "longer each time.\n\n"
        "Decrypt items BEFORE\n"
        "changing the PIN.\n\n"
        "Author: LeviXX\n",
        APP_VERSION);
    text_box_set_text(app->about_box, app->about_buffer);
    view_set_previous_callback(text_box_get_view(app->about_box), view_to_menu);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdAbout, text_box_get_view(app->about_box));

    /* Eredmeny */
    app->result_box = text_box_alloc();
    view_set_previous_callback(text_box_get_view(app->result_box), view_to_menu);
    view_dispatcher_add_view(
        app->view_dispatcher, ViewIdResult, text_box_get_view(app->result_box));

    return app;
}

static void lockbox_app_free(LockBoxApp* app) {
    /* Erzekeny adatok torlese a memoriabol. */
    memset(&app->session_pin, 0, sizeof(app->session_pin));
    memset(&app->recovery_pin, 0, sizeof(app->recovery_pin));
    memset(&app->old_pin_for_rekey, 0, sizeof(app->old_pin_for_rekey));
    memset(app->note_title, 0, sizeof(app->note_title));
    memset(app->note_text, 0, sizeof(app->note_text));
    memset(app->note_display, 0, sizeof(app->note_display));

    view_dispatcher_remove_view(app->view_dispatcher, ViewIdPin);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdRecoverPin);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdMenu);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdVault);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdItem);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdRekey);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdNotes);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdNoteItem);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdNoteView);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdTitleInput);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdNoteInput);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdRenameInput);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdSettings);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdAbout);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdResult);

    view_free(app->pin_view);
    view_free(app->recover_view);
    submenu_free(app->menu);
    submenu_free(app->vault_menu);
    submenu_free(app->item_menu);
    submenu_free(app->rekey_menu);
    submenu_free(app->notes_menu);
    submenu_free(app->note_item_menu);
    submenu_free(app->settings_menu);
    text_box_free(app->about_box);
    text_box_free(app->result_box);
    text_box_free(app->note_view);
    text_input_free(app->title_input);
    text_input_free(app->note_input);
    text_input_free(app->rename_input);

    furi_timer_stop(app->lock_timer);
    furi_timer_free(app->lock_timer);
    furi_timer_stop(app->anim_timer);
    furi_timer_free(app->anim_timer);

    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_DIALOGS);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);

    free(app);
}

int32_t lockbox_app(void* p) {
    UNUSED(p);
    LockBoxApp* app = lockbox_app_alloc();

    app->pin_is_set = lockbox_pin_exists(app);
    lockbox_cfg_load(app); /* panic-wipe beallitasok */
    lockbox_lock_load(app); /* egy korabbi zarolas tulelje az ujrainditast */

    uint32_t now = lockbox_now();
    /* Ha egy korabbi zarolas mar teljesen lejart, a letra nullazodik -> a
     * kovetkezo rossz PIN megint elolrol kezdi a zarolas-idozitest. */
    if(app->lock_until != 0 && now >= app->lock_until) {
        lockbox_lock_reset(app);
    }
    uint32_t rem = (app->lock_until > now) ? (app->lock_until - now) : 0;
    with_view_model(
        app->pin_view,
        PinModel * m,
        {
            memset(m, 0, sizeof(PinModel));
            m->mode = app->pin_is_set ? PinModeVerify : PinModeSet;
            m->locked = app->pin_is_set && (rem > 0);
            m->remaining = rem;
        },
        true);

    /* A visszaszamlalo-timer inditasa (frissiti a zarolas allapotat). */
    furi_timer_start(app->lock_timer, furi_ms_to_ticks(500));
    /* A delfin-animacio idozitoje (~120ms). */
    furi_timer_start(app->anim_timer, furi_ms_to_ticks(120));

    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdPin);
    view_dispatcher_run(app->view_dispatcher);

    lockbox_app_free(app);
    return 0;
}
