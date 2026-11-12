// registry.c - the guest's registry (moved from boot.c unchanged, then extended for ProStreet): a fixed set of known
// keys with their values in memory, the game's own key kept in USERDATA/registry.txt. host_import routes the ADVAPI32
// Reg* calls here (boot.c's dispatch); boot.c calls registry_load() at start-up.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "durable.h"
#include "host.h"

// ---- registry: the game's own key, kept in USERDATA/registry.txt between runs ----
// The file is written on every RegSetValueEx ("dword <name>=<n>" or "sz <name>=<text>" lines). There is no FirstTime
// value until the game writes one, so the first run auto-detects the video settings for the reported GPU and saves
// them; later runs (and the in-game options menu) use the saved ones. BOOT_REG=name=value[,name=value...] overrides
// DWORD values for one run without saving them (e.g. BOOT_REG=g_RacingResolution=3).
// The processor key is there as on any Windows machine: its ~MHz matches rdtsc (3 GHz). Without it EA's movie
// library calibrates rdtsc at the first movie by busy-waiting for a second (FUN_007ECBBE).
#define REG_HKEY_BASE 0x3000u
// The game's own key, where its installer writes Install Dir and friends (ProStreet: the demo build's key).
#ifdef NFS_GAME_PS
#define GAME_REG_KEY "HKLM\\Software\\Electronic Arts\\Need for Speed ProStreet Demo"
#else
#define GAME_REG_KEY "HKLM\\Software\\EA Games\\Need for Speed Most Wanted"
#endif
// BEGIN offline registry: audit4fix_test.py compiles reg_save in a scratch-only C harness.
typedef struct { const char *key; char name[64]; uint32_t type, dw; char sz[260]; } RegValue;
static const char *reg_keys[] = {NULL, GAME_REG_KEY,
                                  "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"};
static RegValue reg_vals[64] = {
#ifdef NFS_GAME_PS
    {GAME_REG_KEY, "Install Dir", 1, 0, "C:\\NFSMW\\"},   // ProStreet appends file names to it directly: the trailing \ matters
#else
    {GAME_REG_KEY, "Install Dir", 1, 0, "C:\\NFSMW"},
#endif
    {GAME_REG_KEY, "CD Drive", 1, 0, "C:\\NFSMW\\"},
    {GAME_REG_KEY, "Language", 1, 0, "English US"},
    {GAME_REG_KEY, "CacheSize", 1, 0, "1468006400"},
    {GAME_REG_KEY, "SwapSize", 1, 0, "0"},
    {GAME_REG_KEY, "StreamingInstall", 1, 0, "off"},
    {"HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "~MHz", 4, 3000, ""},
};
static void reg_path(char *out, size_t n) {
    snprintf(out, n, "%s/registry.txt", userdata_dir());
}
static void reg_save(void) {

    char path[1024], tmp[1100];
    reg_path(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (unsigned i = 0; i < 64 && reg_vals[i].key; ++i) {
        if (strcmp(reg_vals[i].key, reg_keys[1])) continue;                 // only the game's key is saved
        if (reg_vals[i].type == 4) fprintf(f, "dword %s=%u\n", reg_vals[i].name, reg_vals[i].dw);
        else fprintf(f, "sz %s=%s\n", reg_vals[i].name, reg_vals[i].sz);
    }
    // A write error (disk full) keeps the previous registry.txt: durable_commit renames only a complete, synced file.
    if (!durable_commit(f, tmp, path)) fprintf(stderr, "boot: registry.txt not saved: %s\n", strerror(errno));
}
// END offline registry
static RegValue *reg_put(const char *name) {
    for (unsigned i = 0; i < 64 && reg_vals[i].key; ++i) if (!strcmp(reg_vals[i].key, reg_keys[1]) && !strcasecmp(reg_vals[i].name, name)) return &reg_vals[i];
    for (unsigned i = 0; i < 64; ++i) if (!reg_vals[i].key) { reg_vals[i].key = reg_keys[1]; snprintf(reg_vals[i].name, sizeof reg_vals[i].name, "%s", name); return &reg_vals[i]; }
    return NULL;
}
static int reg_first_run = 1;                   // no FirstTime when the settings were loaded (the game writes it during that run)
void registry_load(void) {
    char path[1024], line[512];
    reg_path(path, sizeof path);
    FILE *f = fopen(path, "r");
    while (f && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *sp = strchr(line, ' '), *eq = sp ? strchr(sp, '=') : NULL;
        if (!eq) continue;
        *sp = *eq = 0;
        RegValue *v = reg_put(sp + 1);
        if (!v) continue;
        if (!strcmp(line, "dword")) { v->type = 4; v->dw = (uint32_t)strtoul(eq + 1, NULL, 10); }
        else { v->type = 1; snprintf(v->sz, sizeof v->sz, "%s", eq + 1); }
    }
    if (f) fclose(f);
    // The text language comes from the player's LANGUAGES folder, the Mac's languages and F10 (settings_port.c); with an
    // English install (or Auto on an English Mac) it is "English US", the value this table always held.
    const char *settings_game_language(void), *lang = settings_game_language();
    RegValue *lv = reg_put("Language");
    if (lv && lang) { lv->type = 1; snprintf(lv->sz, sizeof lv->sz, "%s", lang); }
    for (unsigned i = 0; i < 64 && reg_vals[i].key; ++i) if (!strcasecmp(reg_vals[i].name, "FirstTime")) reg_first_run = 0;
    const char *o = getenv("BOOT_REG");
    while (o && *o) {
        char name[64];
        size_t n = strcspn(o, "=,");
        snprintf(name, sizeof name, "%.*s", (int)(n < 63 ? n : 63), o);
        o += n;
        if (*o == '=') {
            RegValue *v = reg_put(name);
            if (v) { v->type = 4; v->dw = (uint32_t)strtoul(o + 1, (char **)&o, 10); fprintf(stderr, "boot: registry %s=%u (BOOT_REG)\n", name, v->dw); }
        }
        while (*o && *o != ',') ++o;
        if (*o == ',') ++o;
    }
}
// d3d9.m (F10 Anti-aliasing): the game's own registry value, as its RegSetValueEx would store it; BOOT_REG runs keep the file.
void boot_reg_set_dword(const char *name, uint32_t v) {
    RegValue *r = reg_put(name);
    if (!r) return;
    r->type = 4; r->dw = v;
    if (!getenv("BOOT_REG")) reg_save();
}
// d3d9.m: is this the first run (the saved settings have no FirstTime yet), and did BOOT_REG set a value?
int boot_reg_first_run(void) { return reg_first_run; }
int boot_reg_override(const char *name) {
    const char *o = getenv("BOOT_REG");
    size_t n = strlen(name);
    for (; o && *o; o += strcspn(o, ",") + (o[strcspn(o, ",")] == ',')) if (!strncasecmp(o, name, n) && o[n] == '=') return 1;
    return 0;
}
// d3d9.m, after a first run's hardware detection: the game's own settings loader (FUN_006c1c00, which a first run
// skips) reads the registry again with only the BOOT_REG values answering, so they win over what detection picked.
static int reg_boot_only;
void boot_reg_reapply(Cpu *c) {
#ifdef NFS_GAME_PS
    (void)c; return;                      // MW's settings loader (FUN_006c1c00)
#endif
    if (!getenv("BOOT_REG")) return;
    Cpu s = *c;
    reg_boot_only = 1;
    call_guest(c, 0x006C1C00u, 0, NULL);
    reg_boot_only = 0;
    *c = s;
}
static const char *reg_key(uint32_t h) {
    uint32_t k = (h - REG_HKEY_BASE) / 4;
    return h >= REG_HKEY_BASE && k > 0 && k < sizeof reg_keys / sizeof *reg_keys ? reg_keys[k] : NULL;
}
// The path of a predefined root (HKLM, HKCU) or of one of our key handles, or NULL.
static const char *reg_base(uint32_t root) { return root == 0x80000002 ? "HKLM" : root == 0x80000001 ? "HKCU" : reg_key(root); }
// Opens root\sub among the known keys (index > 0) or fails (0). root may also be a key handle (a relative open); an
// empty sub under a key handle is that key again.
static int reg_open(uint32_t root, const char *sub, int create) {
    char path[512];
    const char *base = reg_base(root);
    if (reg_key(root) && (!sub || !*sub)) return (int)((root - REG_HKEY_BASE) / 4);
    snprintf(path, sizeof path, "%s\\%s", base ? base : "HK?", sub ? sub : "");
    for (unsigned k = 1; k < sizeof reg_keys / sizeof *reg_keys; ++k) if (!strcasecmp(reg_keys[k], path)) return (int)k;
    (void)create;                                             // other keys stay absent (writes to them are dropped)
    return 0;
}
static RegValue *reg_find(uint32_t h, const char *name) {
    const char *key = reg_key(h);
    if (!key) return NULL;
    for (unsigned i = 0; i < 64 && reg_vals[i].key; ++i)
        if (!strcasecmp(reg_vals[i].key, key) && !strcasecmp(reg_vals[i].name, name ? name : "")) return &reg_vals[i];
    return NULL;
}
static void reg_set(uint32_t h, const char *name, uint32_t type, uint32_t data, uint32_t size) {
    const char *key = reg_key(h);
    if (!key) return;
    RegValue *v = reg_find(h, name);
    if (!v) for (unsigned i = 0; i < 64; ++i) if (!reg_vals[i].key) { v = &reg_vals[i]; v->key = key; snprintf(v->name, sizeof v->name, "%s", name ? name : ""); break; }
    if (!v) return;
    v->type = type;
    if (type == 4) v->dw = M32(data);
    else { uint32_t n = size < sizeof v->sz ? size : sizeof v->sz - 1; memcpy(v->sz, G + data, n); v->sz[n] = 0; }
    if (!getenv("BOOT_REG")) reg_save();          // BOOT_REG runs don't overwrite the saved settings
}

// ---- additions for ProStreet: enumeration, deletion, key information, default values (no MW import uses them) ----
// Values are only ever under the known keys above; deleting a key deletes its values (the key itself stays known).
static RegValue *reg_value_at(const char *key, uint32_t index) {
    for (unsigned i = 0, n = 0; i < 64 && reg_vals[i].key; ++i)
        if (!strcasecmp(reg_vals[i].key, key) && n++ == index) return &reg_vals[i];
    return NULL;
}
static void reg_remove(RegValue *v) {                 // keeps the table dense: every loop stops at the first empty slot
    unsigned i = (unsigned)(v - reg_vals);
    memmove(&reg_vals[i], &reg_vals[i + 1], (63 - i) * sizeof *reg_vals);
    memset(&reg_vals[63], 0, sizeof reg_vals[63]);
}
static void reg_persist(const char *key) { if (!strcmp(key, reg_keys[1]) && !getenv("BOOT_REG")) reg_save(); }
// The distinct next path components under `base` among the known keys: subkey `index` into out, or 0 past the end.
static int reg_subkey(const char *base, uint32_t index, char *out, size_t n, uint32_t *count, uint32_t *maxlen) {
    char seen[16][128];
    unsigned ns = 0;
    size_t bl = strlen(base);
    int found = 0;
    for (unsigned k = 1; k < sizeof reg_keys / sizeof *reg_keys; ++k) {
        if (strncasecmp(reg_keys[k], base, bl) || reg_keys[k][bl] != '\\') continue;
        const char *rest = reg_keys[k] + bl + 1;
        size_t len = strcspn(rest, "\\");
        unsigned j = 0;
        while (j < ns && !(strlen(seen[j]) == len && !strncasecmp(seen[j], rest, len))) ++j;
        if (j < ns || ns == 16 || len >= sizeof seen[0]) continue;
        snprintf(seen[ns], sizeof seen[ns], "%.*s", (int)len, rest);
        if (ns == index && out) { snprintf(out, n, "%s", seen[ns]); found = 1; }
        if (maxlen && len > *maxlen) *maxlen = (uint32_t)len;
        ++ns;
    }
    if (count) *count = ns;
    return found;
}
static uint32_t value_size(const RegValue *v) { return v->type == 4 ? 4 : (uint32_t)strlen(v->sz) + 1; }
static void value_copy(const RegValue *v, uint32_t data) {
    if (v->type == 4) M32(data) = v->dw;
    else memcpy(G + data, v->sz, strlen(v->sz) + 1);
}

int win32_registry(Cpu *c, const char *fn) {
    if (!strcmp(fn, "RegOpenKeyExA") || !strcmp(fn, "RegOpenKeyA") || !strcmp(fn, "RegCreateKeyA")) {
        // (root, subkey, [opts, sam,] hkey*)
        int n = strstr(fn, "KeyEx") ? 5 : 3;
        uint32_t out = arg(c, n - 1);
        int k = reg_open(arg(c, 0), gptr(arg(c, 1)), fn[3] == 'C');
        if (boot_trace) fprintf(stderr, "      %s(%08X, %s) -> %s\n", fn, arg(c, 0), gptr(arg(c, 1)) ? gptr(arg(c, 1)) : "", k ? "ok" : "not found");
        if (!k) RET(2, n);                                    // ERROR_FILE_NOT_FOUND
        M32(out) = REG_HKEY_BASE + 4 * (uint32_t)k;
        RET(0, n);
    }
    if (!strcmp(fn, "RegQueryValueExA")) {        // (hkey, name, reserved, type*, data*, size*)
        const RegValue *v = reg_find(arg(c, 0), gptr(arg(c, 1)));
        if (reg_boot_only && !(gptr(arg(c, 1)) && boot_reg_override(gptr(arg(c, 1))))) v = NULL;
        if (boot_trace) fprintf(stderr, "      RegQueryValueExA(%08X, %s) -> %s\n", arg(c, 0), gptr(arg(c, 1)) ? gptr(arg(c, 1)) : "(default)", v ? "found" : "not found");
        if (!v) RET(2, 6);
        uint32_t size = v->type == 4 ? 4 : (uint32_t)strlen(v->sz) + 1, sp = arg(c, 5);
        if (arg(c, 3)) M32(arg(c, 3)) = v->type;
        if (arg(c, 4)) {
            if (sp && M32(sp) < size) { M32(sp) = size; RET(234, 6); }   // ERROR_MORE_DATA
            if (v->type == 4) M32(arg(c, 4)) = v->dw; else memcpy(G + arg(c, 4), v->sz, size);
        }
        if (sp) M32(sp) = size;
        RET(0, 6);
    }
    if (!strcmp(fn, "RegSetValueExA")) {          // (hkey, name, reserved, type, data, size)
        reg_set(arg(c, 0), gptr(arg(c, 1)), arg(c, 3), arg(c, 4), arg(c, 5));
        RET(0, 6);
    }
    if (!strcmp(fn, "RegCloseKey")) RET(0, 1);
    if (!strcmp(fn, "RegCreateKeyExA")) {          // (root, subkey, reserved, class, options, sam, sa, hkey*, disposition*)
        int k = reg_open(arg(c, 0), gptr(arg(c, 1)), 1);
        if (!k) RET(2, 9);                            // only the known keys exist (as RegCreateKeyA)
        M32(arg(c, 7)) = REG_HKEY_BASE + 4 * (uint32_t)k;
        if (arg(c, 8)) M32(arg(c, 8)) = 2;            // REG_OPENED_EXISTING_KEY
        RET(0, 9);
    }
    if (!strcmp(fn, "RegEnumKeyExA")) {            // (hkey, index, name, cchName*, reserved, class, cchClass*, lastWrite*)
        const char *base = reg_base(arg(c, 0));
        char name[128];
        if (!base) RET(6, 8);                         // ERROR_INVALID_HANDLE
        if (!reg_subkey(base, arg(c, 1), name, sizeof name, NULL, NULL)) RET(259, 8);   // ERROR_NO_MORE_ITEMS
        uint32_t len = (uint32_t)strlen(name), cch = arg(c, 3);
        if (M32(cch) < len + 1) RET(234, 8);          // ERROR_MORE_DATA
        memcpy(G + arg(c, 2), name, len + 1);
        M32(cch) = len;
        if (arg(c, 6)) M32(arg(c, 6)) = 0;
        if (arg(c, 7)) M64(arg(c, 7)) = 0;
        RET(0, 8);
    }
    if (!strcmp(fn, "RegEnumValueA")) {            // (hkey, index, name, cchName*, reserved, type*, data*, cbData*)
        const char *key = reg_key(arg(c, 0));
        if (!key) RET(6, 8);
        const RegValue *v = reg_value_at(key, arg(c, 1));
        if (!v) RET(259, 8);
        uint32_t len = (uint32_t)strlen(v->name), cch = arg(c, 3), size = value_size(v), cb = arg(c, 7);
        if (M32(cch) < len + 1) RET(234, 8);
        memcpy(G + arg(c, 2), v->name, len + 1);
        M32(cch) = len;
        if (arg(c, 5)) M32(arg(c, 5)) = v->type;
        if (arg(c, 6)) {
            if (cb && M32(cb) < size) { M32(cb) = size; RET(234, 8); }
            value_copy(v, arg(c, 6));
        }
        if (cb) M32(cb) = size;
        RET(0, 8);
    }
    if (!strcmp(fn, "RegQueryInfoKeyA")) {         // (hkey, class, cchClass*, reserved, subkeys*, maxSubkeyLen*, maxClassLen*,
        const char *base = reg_base(arg(c, 0));    //  values*, maxValueNameLen*, maxValueLen*, securityDescriptor*, lastWrite*)
        if (!base) RET(6, 12);
        uint32_t subkeys = 0, maxsub = 0, values = 0, maxname = 0, maxdata = 0;
        reg_subkey(base, 0xFFFFFFFFu, NULL, 0, &subkeys, &maxsub);
        for (unsigned i = 0; i < 64 && reg_vals[i].key; ++i) {
            if (strcasecmp(reg_vals[i].key, base)) continue;
            ++values;
            if (strlen(reg_vals[i].name) > maxname) maxname = (uint32_t)strlen(reg_vals[i].name);
            if (value_size(&reg_vals[i]) > maxdata) maxdata = value_size(&reg_vals[i]);
        }
        if (arg(c, 1) && arg(c, 2) && M32(arg(c, 2))) M8(arg(c, 1)) = 0;
        if (arg(c, 2)) M32(arg(c, 2)) = 0;
        const uint32_t out[] = {subkeys, maxsub, 0, values, maxname, maxdata, 0};
        for (int i = 0; i < 7; ++i) if (arg(c, 4 + i)) M32(arg(c, 4 + i)) = out[i];
        if (arg(c, 11)) M64(arg(c, 11)) = 0;
        RET(0, 12);
    }
    if (!strcmp(fn, "RegDeleteValueA")) {          // (hkey, name)
        RegValue *v = reg_find(arg(c, 0), gptr(arg(c, 1)));
        if (!v) RET(2, 2);
        const char *key = v->key;
        reg_remove(v);
        reg_persist(key);
        RET(0, 2);
    }
    if (!strcmp(fn, "RegDeleteKeyA")) {            // (hkey, subkey): its values go; the key stays known
        int k = reg_open(arg(c, 0), gptr(arg(c, 1)), 0);
        if (!k || !gptr(arg(c, 1)) || !*gptr(arg(c, 1))) RET(2, 2);
        for (RegValue *v; (v = reg_value_at(reg_keys[k], 0));) reg_remove(v);
        reg_persist(reg_keys[k]);
        RET(0, 2);
    }
    if (!strcmp(fn, "RegQueryValueA")) {           // (hkey, subkey, data*, cb*): the key's default (unnamed) string
        int k = reg_open(arg(c, 0), gptr(arg(c, 1)), 0);
        if (!k) RET(2, 4);
        const RegValue *v = reg_find(REG_HKEY_BASE + 4 * (uint32_t)k, "");
        const char *s = v && v->type != 4 ? v->sz : "";   // an unset default reads as the empty string
        uint32_t size = (uint32_t)strlen(s) + 1, cb = arg(c, 3);
        if (arg(c, 2)) {
            if (cb && M32(cb) < size) { M32(cb) = size; RET(234, 4); }
            memcpy(G + arg(c, 2), s, size);
        }
        if (cb) M32(cb) = size;
        RET(0, 4);
    }
    if (!strcmp(fn, "RegSetValueA")) {             // (hkey, subkey, type, data, cb): REG_SZ only; the length is the string's
        if (arg(c, 2) != 1) RET(87, 5);               // ERROR_INVALID_PARAMETER
        int k = reg_open(arg(c, 0), gptr(arg(c, 1)), 1);
        if (!k) RET(2, 5);
        reg_set(REG_HKEY_BASE + 4 * (uint32_t)k, "", 1, arg(c, 3), (uint32_t)strlen(gptr(arg(c, 3))) + 1);
        RET(0, 5);
    }
    return 0;
}
