// registry_test.c - standalone test of registry.c on a private guest address space; no game files.
// Built and run by runtime/registry_test.py (c_test_driver.py). Part 1 pins the behaviour MW had before the code moved out
// of boot.c (known keys, values, registry.txt persistence, BOOT_REG); part 2 covers the calls added for ProStreet.
// Every call goes through win32_registry() with a real guest stack, and the __stdcall rule is checked after each one.
// REGISTRY_TEST_SELFCHECK=1 adds one deliberately wrong expectation.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "host.h"

uint8_t *G;
__thread uint32_t last_error;
int boot_trace;
static Cpu cpu;
static Cpu *const c = &cpu;
static int fails, checks;
#define CHECK(x, ...) do { ++checks; if (!(x)) { if (fails++ < 40) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static char udir[512];
const char *userdata_dir(void) { return udir; }
const char *settings_game_language(void) { return "English US"; }
uint32_t call_guest(Cpu *cc, uint32_t fn, int n, const uint32_t *args) { (void)cc; (void)fn; (void)n; (void)args; return 0; }
int boot_reg_override(const char *name);

static uint32_t bump = 0x10000000u;
static uint32_t gal(uint32_t n) { uint32_t a = (bump + 15) & ~15u; bump = a + (n ? n : 1); memset(G + a, 0, n); return a; }
static uint32_t S(const char *s) { uint32_t a = gal((uint32_t)strlen(s) + 1); strcpy((char *)G + a, s); return a; }
static const char *gs(uint32_t a) { return (const char *)G + a; }

static int call(const char *fn, int n, const uint32_t *args) {
    uint32_t sp = 0x7F000000u;
    for (int i = n - 1; i >= 0; --i) { sp -= 4; M32(sp) = args[i]; }
    sp -= 4;
    M32(sp) = 0xDEADC0DEu;
    c->esp = sp;
    int ok = win32_registry(c, fn);
    if (ok) CHECK(c->esp == sp + 4 + 4 * (uint32_t)n, "%s: esp %08X, want %08X (__stdcall pops %d arguments)", fn, c->esp, sp + 4 + 4 * (uint32_t)n, n);
    return ok;
}
static uint32_t callv(const char *fn, int n, const uint32_t *args) {
    if (call(fn, n, args)) return c->eax;
    CHECK(0, "%s not handled", fn);
    return 0xBADu;
}
#define A(...) ((const uint32_t[]){__VA_ARGS__})
#define NA(...) (int)(sizeof((const uint32_t[]){__VA_ARGS__}) / 4)
#define CALL(fn, ...) callv(fn, NA(__VA_ARGS__), A(__VA_ARGS__))

#define HKLM 0x80000002u
#define GAME_KEY "Software\\EA Games\\Need for Speed Most Wanted"
static char filebuf[4096];
static const char *regfile(void) {
    char p[600];
    snprintf(p, sizeof p, "%s/registry.txt", udir);
    FILE *f = fopen(p, "r");
    size_t n = f ? fread(filebuf, 1, sizeof filebuf - 1, f) : 0;
    if (f) fclose(f);
    filebuf[n] = 0;
    return filebuf;
}
static uint32_t open_key(const char *sub) {
    uint32_t hk = gal(4);
    return CALL("RegOpenKeyExA", HKLM, S(sub), 0, 0x20019, hk) == 0 ? M32(hk) : 0;
}

static void test_mw_behaviour(void) {
    uint32_t game = open_key(GAME_KEY), cpu_key = open_key("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
    CHECK(game == 0x3004 && cpu_key == 0x3008, "the known keys open (%X, %X)", game, cpu_key);
    uint32_t hk = gal(4);
    CHECK(CALL("RegOpenKeyExA", HKLM, S("Software\\Other"), 0, 0x20019, hk) == 2, "an unknown key is absent");
    CHECK(CALL("RegCreateKeyA", HKLM, S("Software\\Other"), hk) == 2, "RegCreateKeyA only opens known keys");
    CHECK(CALL("RegOpenKeyA", HKLM, S(GAME_KEY), hk) == 0 && M32(hk) == game, "RegOpenKeyA");
    uint32_t type = gal(4), data = gal(64), size = gal(4);
    M32(size) = 64;
    CHECK(CALL("RegQueryValueExA", game, S("Install Dir"), 0, type, data, size) == 0 && M32(type) == 1 &&
          !strcmp(gs(data), "C:\\NFSMW") && M32(size) == 9, "RegQueryValueExA string");
    M32(size) = 3;
    CHECK(CALL("RegQueryValueExA", game, S("install dir"), 0, type, data, size) == 234 && M32(size) == 9, "small buffer: ERROR_MORE_DATA, names case-insensitive");
    CHECK(CALL("RegQueryValueExA", game, S("Install Dir"), 0, type, 0, size) == 0 && M32(size) == 9, "size query");
    CHECK(CALL("RegQueryValueExA", game, S("Nope"), 0, type, data, size) == 2, "missing value");
    M32(size) = 4;
    CHECK(CALL("RegQueryValueExA", cpu_key, S("~MHz"), 0, type, data, size) == 0 && M32(type) == 4 && M32(data) == 3000, "~MHz");
    M32(size) = 64;
    CHECK(CALL("RegQueryValueExA", game, S("Language"), 0, type, data, size) == 0 && !strcmp(gs(data), "English US"), "Language from settings_game_language");
    uint32_t dw = gal(4);
    M32(dw) = 7;
    CHECK(CALL("RegSetValueExA", game, S("g_Test"), 0, 4, dw, 4) == 0 && strstr(regfile(), "dword g_Test=7\n"), "a DWORD is saved:\n%s", filebuf);
    CHECK(CALL("RegSetValueExA", game, S("Name"), 0, 1, S("Kazzy"), 6) == 0 && strstr(regfile(), "sz Name=Kazzy\n"), "a string is saved");
    CHECK(CALL("RegSetValueExA", cpu_key, S("Extra"), 0, 4, dw, 4) == 0 && !strstr(regfile(), "Extra"), "only the game's key is saved");
    CHECK(CALL("RegCloseKey", game) == 0, "RegCloseKey");
    // registry.txt is read back at start-up
    char p[600];
    snprintf(p, sizeof p, "%s/registry.txt", udir);
    FILE *f = fopen(p, "a");
    fputs("dword g_FromFile=42\n", f);
    fclose(f);
    registry_load();
    M32(size) = 4;
    CHECK(CALL("RegQueryValueExA", game, S("g_FromFile"), 0, type, data, size) == 0 && M32(data) == 42, "registry_load reads registry.txt");
}

static void test_additions(void) {
    uint32_t game = open_key(GAME_KEY), hk = gal(4), disp = gal(4);
    // relative opens and RegCreateKeyExA
    CHECK(CALL("RegOpenKeyExA", game, S(""), 0, 0x20019, hk) == 0 && M32(hk) == game, "an empty subkey of a key handle is that key");
    CHECK(CALL("RegOpenKeyExA", game, 0, 0, 0x20019, hk) == 0 && M32(hk) == game, "a NULL subkey too");
    CHECK(CALL("RegOpenKeyExA", game, S("Sub"), 0, 0x20019, hk) == 2, "an unknown subkey of a key handle");
    M32(disp) = 0;
    CHECK(CALL("RegCreateKeyExA", HKLM, S(GAME_KEY), 0, 0, 0, 0xF003F, 0, hk, disp) == 0 && M32(hk) == game && M32(disp) == 2,
          "RegCreateKeyExA opens the existing key");
    CHECK(CALL("RegCreateKeyExA", HKLM, S("Software\\New"), 0, 0, 0, 0xF003F, 0, hk, 0) == 2, "RegCreateKeyExA of an unknown key");
    // RegEnumKeyExA: the subkeys under HKLM are the first components of the known keys
    uint32_t name = gal(64), cch = gal(4);
    int seen = 0;
    uint32_t i = 0;
    for (;; ++i) {
        M32(cch) = 64;
        uint32_t r = CALL("RegEnumKeyExA", HKLM, i, name, cch, 0, 0, 0, 0);
        if (r != 0) { CHECK(r == 259, "ends with ERROR_NO_MORE_ITEMS (%u)", r); break; }
        CHECK(M32(cch) == strlen(gs(name)), "cchName is the length");
        if (!strcmp(gs(name), "Software")) seen |= 1;
        if (!strcmp(gs(name), "HARDWARE")) seen |= 2;
    }
    CHECK(seen == 3 && i == 2, "HKLM has Software and HARDWARE (%u, mask %d)", i, seen);
    M32(cch) = 3;
    CHECK(CALL("RegEnumKeyExA", HKLM, 0, name, cch, 0, 0, 0, 0) == 234, "a small name buffer");
    M32(cch) = 64;
    CHECK(CALL("RegEnumKeyExA", game, 0, name, cch, 0, 0, 0, 0) == 259, "the game key has no subkeys");
    CHECK(CALL("RegEnumKeyExA", 0x3FFC, 0, name, cch, 0, 0, 0, 0) == 6, "a bad handle");
    // RegEnumValueA walks the game key's values in table order
    uint32_t type = gal(4), data = gal(300), cb = gal(4), n = 0, found = 0;
    for (;; ++n) {
        M32(cch) = 64; M32(cb) = 300;
        uint32_t r = CALL("RegEnumValueA", game, n, name, cch, 0, type, data, cb);
        if (r) { CHECK(r == 259, "ends with ERROR_NO_MORE_ITEMS"); break; }
        if (!strcmp(gs(name), "Install Dir")) found |= !strcmp(gs(data), "C:\\NFSMW") && M32(type) == 1 && M32(cb) == 9;
        if (!strcmp(gs(name), "g_Test")) found |= (M32(data) == 7 && M32(type) == 4 && M32(cb) == 4) << 1;
    }
    CHECK(found == 3 && n >= 8, "RegEnumValueA saw the values with their data (%u values, mask %u)", n, found);
    M32(cch) = 2; M32(cb) = 300;
    CHECK(CALL("RegEnumValueA", game, 0, name, cch, 0, type, data, cb) == 234, "a small value-name buffer");
    M32(cch) = 64; M32(cb) = 2;
    CHECK(CALL("RegEnumValueA", game, 0, name, cch, 0, type, data, cb) == 234 && M32(cb) == 9, "a small data buffer reports the size");
    // RegQueryInfoKeyA
    uint32_t sub = gal(4), maxsub = gal(4), vals = gal(4), maxname = gal(4), maxdata = gal(4);
    CHECK(CALL("RegQueryInfoKeyA", game, 0, 0, 0, sub, maxsub, 0, vals, maxname, maxdata, 0, 0) == 0 && M32(sub) == 0 && M32(vals) == n &&
          M32(maxname) == 16 && M32(maxdata) == 11, "RegQueryInfoKeyA on the game key: %u values, name %u, data %u", M32(vals), M32(maxname), M32(maxdata));
    CHECK(CALL("RegQueryInfoKeyA", HKLM, 0, 0, 0, sub, maxsub, 0, vals, 0, 0, 0, 0) == 0 && M32(sub) == 2 && M32(maxsub) == 8 && M32(vals) == 0,
          "RegQueryInfoKeyA on HKLM");
    // RegDeleteValueA keeps the table dense and the file in step
    CHECK(CALL("RegDeleteValueA", game, S("g_Test")) == 0 && !strstr(regfile(), "g_Test"), "RegDeleteValueA");
    M32(cb) = 4;
    CHECK(CALL("RegQueryValueExA", game, S("g_Test"), 0, type, data, cb) == 2 && CALL("RegDeleteValueA", game, S("g_Test")) == 2, "gone");
    M32(cb) = 4;
    CHECK(CALL("RegQueryValueExA", game, S("g_FromFile"), 0, type, data, cb) == 0 && M32(data) == 42, "values after it are still found");
    // default values: RegSetValueA / RegQueryValueA
    uint32_t cbs = gal(4);
    M32(cbs) = 300;
    CHECK(CALL("RegQueryValueA", game, 0, data, cbs) == 0 && !G[data] && M32(cbs) == 1, "an unset default reads as \"\"");
    CHECK(CALL("RegSetValueA", game, S(""), 1, S("default text"), 99) == 0 && strstr(regfile(), "sz =default text\n"), "RegSetValueA saves the default");
    M32(cbs) = 300;
    CHECK(CALL("RegQueryValueA", HKLM, S(GAME_KEY), data, cbs) == 0 && !strcmp(gs(data), "default text") && M32(cbs) == 13, "RegQueryValueA");
    M32(cbs) = 4;
    CHECK(CALL("RegQueryValueA", game, 0, data, cbs) == 234 && M32(cbs) == 13, "RegQueryValueA small buffer");
    M32(cb) = 300;
    CHECK(CALL("RegQueryValueExA", game, S(""), 0, type, data, cb) == 0 && !strcmp(gs(data), "default text"), "the default is the empty name");
    CHECK(CALL("RegSetValueA", game, 0, 4, S("x"), 2) == 87, "RegSetValueA takes REG_SZ only");
    CHECK(CALL("RegQueryValueA", HKLM, S("Software\\Other"), data, cbs) == 2, "RegQueryValueA of an unknown key");
    registry_load();                                  // the default survives a reload
    M32(cbs) = 300;
    CHECK(CALL("RegQueryValueA", game, 0, data, cbs) == 0 && !strcmp(gs(data), "default text"), "the default round-trips through registry.txt");
    // RegDeleteKeyA: the key's values go, the key stays known
    CHECK(CALL("RegDeleteKeyA", game, S("")) == 2, "RegDeleteKeyA needs a subkey");
    CHECK(CALL("RegDeleteKeyA", HKLM, S(GAME_KEY)) == 0, "RegDeleteKeyA");
    M32(cch) = 64; M32(cb) = 300;
    CHECK(CALL("RegEnumValueA", game, 0, name, cch, 0, type, data, cb) == 259 && !strstr(regfile(), "="), "no values left, none saved");
    CHECK(open_key(GAME_KEY) == game, "the key itself is still there");
    CHECK(CALL("RegDeleteKeyA", HKLM, S("Software\\Other")) == 2, "RegDeleteKeyA of an unknown key");
}

static void test_boot_reg(void) {
    setenv("BOOT_REG", "g_Override=5,g_Other=9", 1);
    registry_load();
    uint32_t game = open_key(GAME_KEY), type = gal(4), data = gal(8), cb = gal(4);
    M32(cb) = 4;
    CHECK(CALL("RegQueryValueExA", game, S("g_Override"), 0, type, data, cb) == 0 && M32(data) == 5, "BOOT_REG sets a DWORD for the run");
    CHECK(boot_reg_override("g_Other") && !boot_reg_override("g_None"), "boot_reg_override");
    const char *before = strdup(regfile());
    uint32_t dw = gal(4);
    M32(dw) = 1;
    CALL("RegSetValueExA", game, S("g_Run"), 0, 4, dw, 4);
    CHECK(!strcmp(before, regfile()), "BOOT_REG runs don't write registry.txt");
    free((void *)before);
    unsetenv("BOOT_REG");
}

int main(void) {
    G = mmap(0, 1ull << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (G == MAP_FAILED) { printf("cannot reserve guest memory\n"); return 2; }
    const char *tmp = getenv("C_TEST_TMP") ? getenv("C_TEST_TMP") : getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(udir, sizeof udir, "%s/registry_test.XXXXXX", tmp);
    if (!mkdtemp(udir)) { printf("cannot create a scratch directory\n"); return 2; }
    registry_load();
    test_mw_behaviour();
    test_additions();
    test_boot_reg();
    CHECK(!win32_registry(c, "NoSuchFunction"), "unknown functions are not handled");
    if (getenv("REGISTRY_TEST_SELFCHECK")) CHECK(open_key(GAME_KEY) == 0x3008, "deliberately wrong");
    char p[600];
    snprintf(p, sizeof p, "%s/registry.txt", udir);
    unlink(p);
    rmdir(udir);
    printf("%s: %d checks, %d failing\n", fails ? "FAIL" : "ok", checks, fails);
    return fails ? 1 : 0;
}
