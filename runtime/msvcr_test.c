// msvcr_test.c - standalone test of msvcr.c (the MSVCR80 shim) on a private guest address space; no game files.
// Built and run by runtime/msvcr_test.py (ASan + UBSan). Every call goes through win32_msvcr() with a real guest stack:
// arguments pushed right to left, a return address, and the __cdecl rule checked after each call (the handler pops
// only the return address). Host hooks (CRT heap, critical sections, exit, call_guest, clocks) are stubs below.
// MSVCR_TEST_SELFCHECK=1 adds one deliberately wrong expectation; the run must then fail (the checks can fail).
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "host.h"
#include "test_hostfs.h"

uint8_t *G;
static Cpu cpu;
static Cpu *const c = &cpu;
static int fails, checks;
#define CHECK(x, ...) do { ++checks; if (!(x)) { if (fails++ < 40) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

// ---- host stubs ----
static uint32_t bump = 0x10000000u;
uint32_t galloc(uint32_t n) { uint32_t a = (bump + 15) & ~15u; bump = a + (n ? n : 1); memset(G + a, 0, n); return a; }
uint32_t gstr(const char *s) { uint32_t a = galloc((uint32_t)strlen(s) + 1); strcpy((char *)G + a, s); return a; }

// CRT heap: size header + bump, so frees and reallocs are observable.
static uint32_t heap_next = 0x20000000u, live_blocks, freed_blocks;
uint32_t crt_heap_alloc(uint32_t n) {
    uint32_t a = ((heap_next + 8 + 15) & ~15u);
    M32(a - 4) = n;
    M32(a - 8) = 0xB10CB10Cu;
    heap_next = a + n;
    memset(G + a, 0, n);
    ++live_blocks;
    return a;
}
void crt_heap_free(uint32_t a) { if (M32(a - 8) == 0xB10CB10Cu) { M32(a - 8) = 0xF2EEF2EEu; --live_blocks; ++freed_blocks; } else ++fails, printf("FAIL bad free %08X\n", a); }
uint32_t crt_heap_size(uint32_t a) { return M32(a - 4); }
uint32_t crt_heap_realloc(uint32_t a, uint32_t n) {
    uint32_t b = crt_heap_alloc(n), old = M32(a - 4);
    memcpy(G + b, G + a, old < n ? old : n);
    crt_heap_free(a);
    return b;
}
static uint32_t cs_last, cs_enters, cs_leaves;
void crt_cs_enter(Cpu *cc, uint32_t cs) { (void)cc; cs_last = cs; ++cs_enters; }
void crt_cs_leave(uint32_t cs) { CHECK(cs == cs_last, "leave of another lock"); ++cs_leaves; }
static jmp_buf jb;
static int exit_code = -1;
static const char *fatal_fn;
void crt_exit_process(Cpu *cc, uint32_t code) { (void)cc; exit_code = (int)code; longjmp(jb, 1); }
void crt_fatal(const char *fn, const char *why) { (void)why; fatal_fn = fn; longjmp(jb, 2); }
uint64_t host_ticks(void) { static uint64_t t; return t += 5000000; }   // 5 ms per call
static uint64_t fake_filetime = 116444736000000000ull + 1234567890ull * 10000000ull + 4560000ull;
uint64_t host_filetime(void) { return fake_filetime; }

// threads.c stub: records CreateThread / ExitThread as the shim forwards them
static char thread_fn[32];
static uint32_t thread_args[6];
int win32_threads(Cpu *cc, const char *fn) {
    Cpu *c = cc;
    snprintf(thread_fn, sizeof thread_fn, "%s", fn);
    if (!strcmp(fn, "CreateThread")) { for (int i = 0; i < 6; ++i) thread_args[i] = arg(c, i); RET(0x2004, 6); }
    if (!strcmp(fn, "ExitThread")) { thread_args[0] = arg(c, 0); RET(0, 1); }
    return 0;
}

// call_guest: guest "functions" 0x5000+k are the test callbacks below. Arguments are read like a guest callee would.
static uint32_t init_log[8], init_n;
uint32_t call_guest(Cpu *cc, uint32_t fn, int n, const uint32_t *args) {
    (void)cc;
    switch (fn) {
    case 0x5000: { int32_t a = (int32_t)M32(args[0]), b = (int32_t)M32(args[1]); CHECK(n == 2, "cmp arity"); return (uint32_t)(a < b ? -1 : a > b); }
    case 0x5001: case 0x5002: case 0x5003: init_log[init_n++] = fn; return fn == 0x5003 ? 7 : 0;   // 0x5003 "fails" with 7
    case 0x5010: case 0x5011: init_log[init_n++] = fn; return 0;   // onexit functions
    }
    printf("FAIL call_guest to unknown %08X\n", fn);
    ++fails;
    return 0;
}

// ---- calling a CRT import ----
static uint32_t sp_args;
static int call(const char *fn, int n, const uint32_t *args) {
    uint32_t sp = 0x7F000000u;
    for (int i = n - 1; i >= 0; --i) { sp -= 4; M32(sp) = args[i]; }
    sp -= 4;
    M32(sp) = 0xDEADC0DEu;
    c->esp = sp;
    sp_args = sp + 4;
    int ok = win32_msvcr(c, fn);
    if (ok) CHECK(c->esp == sp_args, "%s: esp %08X after the call, want %08X (__cdecl pops only the return address)", fn, c->esp, sp_args);
    return ok;
}
#define A(...) ((const uint32_t[]){__VA_ARGS__})
#define NA(...) (int)(sizeof((const uint32_t[]){__VA_ARGS__}) / 4)
static uint32_t callv(const char *fn, int n, const uint32_t *args) {
    if (call(fn, n, args)) return c->eax;
    CHECK(0, "%s not handled", fn);
    return 0;
}
#define CALL(fn, ...) callv(fn, NA(__VA_ARGS__), A(__VA_ARGS__))
#define CALL0(fn) callv(fn, 0, NULL)
static uint32_t lo(double d) { uint64_t u; memcpy(&u, &d, 8); return (uint32_t)u; }
static uint32_t hi(double d) { uint64_t u; memcpy(&u, &d, 8); return (uint32_t)(u >> 32); }
#define D(d) lo(d), hi(d)
static uint32_t S(const char *s) { return gstr(s); }
static const char *gs(uint32_t a) { return (const char *)G + a; }
static double pop_st0(void) { double d = ST(0); x87_pop(c); return d; }
static uint32_t fatal_call(const char *fn, int n, const uint32_t *args) {
    fatal_fn = NULL;
    if (!setjmp(jb)) call(fn, n, args);
    return fatal_fn != NULL;
}

static void test_memory(void) {
    uint32_t a = CALL("malloc", 10), b = CALL("malloc", 0), z = CALL("calloc", 4, 8);
    CHECK(a && b && a != b, "malloc(10)=%08X malloc(0)=%08X", a, b);
    CHECK(z && crt_heap_size(z) == 32, "calloc size %u", crt_heap_size(z));
    CHECK(CALL("calloc", 0x10000, 0x10000) == 0, "calloc overflow must fail");
    memcpy(G + a, "abcdefghi", 10);
    uint32_t r = CALL("realloc", a, 100);
    CHECK(r && !memcmp(G + r, "abcdefghi", 10), "realloc keeps contents");
    CHECK(CALL("realloc", 0, 16) != 0, "realloc(NULL) allocates");
    uint32_t before = freed_blocks;
    CHECK(CALL("realloc", r, 0) == 0 && freed_blocks == before + 1, "realloc(p, 0) frees and returns NULL");
    uint32_t al = CALL("_aligned_malloc", 100, 64);
    CHECK(al && al % 64 == 0, "_aligned_malloc %08X not 64-aligned", al);
    before = freed_blocks;
    CALL("_aligned_free", al);
    CHECK(freed_blocks == before + 1, "_aligned_free frees the raw block");
    CHECK(fatal_call("_aligned_malloc", 2, A(8, 3)), "_aligned_malloc with a bad alignment is fatal");
    CALL("free", 0);
    CALL("free", b);
}

static void test_strings(void) {
    uint32_t buf = galloc(64);
    CHECK(CALL("strlen", S("hello")) == 5, "strlen");
    CALL("strcpy", buf, S("foo"));
    CALL("strcat", buf, S("bar"));
    CHECK(!strcmp(gs(buf), "foobar"), "strcpy/strcat: %s", gs(buf));
    memset(G + buf, 'x', 10);
    CALL("strncpy", buf, S("ab"), 5);
    CHECK(!memcmp(G + buf, "ab\0\0\0xxxxx", 10), "strncpy pads with zeros");
    CALL("strcpy", buf, S("12"));
    CALL("strncat", buf, S("3456"), 2);
    CHECK(!strcmp(gs(buf), "1234"), "strncat: %s", gs(buf));
    CHECK((int32_t)CALL("strcmp", S("abc"), S("abd")) == -1 && CALL("strcmp", S("b"), S("a")) == 1 && CALL("strcmp", S("x"), S("x")) == 0, "strcmp gives -1/0/1");
    CHECK((int32_t)CALL("strncmp", S("abcX"), S("abcY"), 3) == 0, "strncmp");
    CHECK((int32_t)CALL("_stricmp", S("HeLLo"), S("hello")) == 0 && (int32_t)CALL("_stricmp", S("ABC"), S("abd")) < 0, "_stricmp");
    CHECK((int32_t)CALL("_stricmp", S("_"), S("a")) < 0, "_stricmp compares lower-cased bytes ('_' < 'a')");
    CHECK((int32_t)CALL("_strnicmp", S("ABCx"), S("abcy"), 3) == 0, "_strnicmp");
    uint32_t s = S("a/b/c");
    CHECK(CALL("strchr", s, '/') == s + 1 && CALL("strrchr", s, '/') == s + 3 && CALL("strchr", s, 'z') == 0, "strchr/strrchr");
    CHECK(CALL("strchr", s, 0) == s + 5, "strchr finds the terminator");
    CHECK(CALL("strstr", s, S("b/")) == s + 2 && CALL("strstr", s, S("")) == s, "strstr");
    CHECK(CALL("strpbrk", s, S("cb")) == s + 2 && CALL("strcspn", s, S("c")) == 4, "strpbrk/strcspn");
    uint32_t t = S("  one,two,,three ");
    const char *want[] = {"one", "two", "three"};
    uint32_t delim = S(", ");
    for (int i = 0; i < 3; ++i) {
        uint32_t tok = CALL("strtok", i ? 0 : t, delim);
        CHECK(tok && !strcmp(gs(tok), want[i]), "strtok token %d: %s", i, tok ? gs(tok) : "(null)");
    }
    CHECK(CALL("strtok", 0, delim) == 0, "strtok ends with NULL");
    CHECK((int32_t)CALL("memcmp", S("ab\x01"), S("ab\x02"), 3) == -1, "memcmp");
    memcpy(G + buf, "0123456789", 10);
    CALL("memmove", buf + 2, buf, 5);
    CHECK(!memcmp(G + buf, "0101234789", 10), "memmove overlap");
    CHECK(CALL("memmove_s", buf, 10, buf + 1, 4) == 0, "memmove_s ok");
    CHECK(fatal_call("memmove_s", 4, A(buf, 2, buf + 4, 3)), "memmove_s count > size is fatal");
    CALL("memset", buf, 'z', 3);
    CHECK(!memcmp(G + buf, "zzz", 3), "memset");
}

static void test_conversion(void) {
    CHECK((int32_t)CALL("atoi", S("  -42xyz")) == -42, "atoi");
    CHECK(CALL("atoi", S("99999999999")) == 0x7FFFFFFFu, "atoi clamps");
    uint32_t end = galloc(4), s = S("0x1Fg");
    CHECK(CALL("strtol", s, end, 0) == 31 && M32(end) == s + 4, "strtol base 0 hex");
    s = S("  -1");
    CHECK(CALL("strtoul", s, end, 10) == 0xFFFFFFFFu && M32(end) == s + 4, "strtoul negates in 32 bits");
    CHECK(CALL("strtol", S("zz"), 0, 36) == 1295, "strtol base 36");
    CHECK(CALL("strtol", S("-3000000000"), 0, 10) == 0x80000000u, "strtol clamps to LONG_MIN");
    s = S("abc");
    CHECK(CALL("strtol", s, end, 10) == 0 && M32(end) == s, "strtol no digits");
    CHECK(CALL("strtol", S("017"), 0, 0) == 15, "strtol base 0 octal");
    uint32_t buf = galloc(40);
    CALL("_ltoa", (uint32_t)-255, buf, 10);
    CHECK(!strcmp(gs(buf), "-255"), "_ltoa -255: %s", gs(buf));
    CALL("_ltoa", (uint32_t)-1, buf, 16);
    CHECK(!strcmp(gs(buf), "ffffffff"), "_ltoa radix 16 unsigned: %s", gs(buf));
    CHECK(CALL("abs", (uint32_t)-7) == 7, "abs");
    CHECK(CALL("tolower", 'Q') == 'q' && CALL("toupper", 'q') == 'Q' && CALL("tolower", 0xC4) == 0xC4, "tolower/toupper");
    CHECK(CALL("isspace", '\t') && !CALL("isspace", 'a') && CALL("isdigit", '7') && !CALL("isdigit", 'x'), "isspace/isdigit");
    CHECK(CALL("isprint", ' ') && !CALL("isprint", 0x7F) && !CALL("isprint", (uint32_t)-1), "isprint");
    unsigned top = c->top;
    CALL("atof", S("  1.5d2rest"));
    CHECK(c->top == ((top - 1) & 7) && pop_st0() == 150.0, "atof with a 'd' exponent pushes 150");
    CALL("atof", S("inf"));
    CHECK(pop_st0() == 0.0, "atof does not parse inf (VC8)");
    CALL("atof", S("-.25e-1"));
    CHECK(pop_st0() == -0.025, "atof -.25e-1");
}

static void test_math(void) {
    c->cw = 0x027F;
    x87_push(c, 2.0);
    x87_push(c, 10.0);
    unsigned top = c->top;
    CALL0("_CIpow");
    CHECK(c->top == ((top + 1) & 7), "_CIpow pops one");
    CHECK(pop_st0() == 1024.0, "_CIpow(2, 10)");
    x87_push(c, 7.0); x87_push(c, 4.0); CALL0("_CIfmod");
    CHECK(pop_st0() == 3.0, "_CIfmod(7, 4)");
    x87_push(c, 1.0); x87_push(c, 1.0); CALL0("_CIatan2");
    CHECK(fabs(pop_st0() - 0.7853981633974483) < 1e-15, "_CIatan2(1, 1)");
    x87_push(c, -1.0); CALL0("_CIsqrt");
    double n = pop_st0();
    CHECK(isnan(n) && signbit(n), "_CIsqrt(-1) is the negative x87 indefinite NaN");
    const char *one[] = {"_CIsin", "_CIcos", "_CItan", "_CIasin", "_CIacos", "_CIatan", "_CIexp", "_CIlog", "_CIlog10", "_CIsinh", "_CIcosh", "_CItanh"};
    double (*ref[])(double) = {sin, cos, tan, asin, acos, atan, exp, log, log10, sinh, cosh, tanh};
    for (int i = 0; i < 12; ++i) {
        x87_push(c, 0.5);
        unsigned t0 = c->top;
        CALL0(one[i]);
        CHECK(c->top == t0, "%s keeps the stack depth", one[i]);
        CHECK(pop_st0() == ref[i](0.5), "%s(0.5)", one[i]);
    }
    CALL("ceil", D(2.1)); CHECK(pop_st0() == 3.0, "ceil");
    CALL("floor", D(-2.1)); CHECK(pop_st0() == -3.0, "floor");
    CALL("sqrt", D(81.0)); CHECK(pop_st0() == 9.0, "sqrt");
    CALL("cos", D(0.0)); CHECK(pop_st0() == 1.0, "cos");
    CALL("ldexp", D(1.5), 4); CHECK(pop_st0() == 24.0, "ldexp");
    CHECK(CALL("_isnan", D(NAN)) == 1 && CALL("_isnan", D(1.0)) == 0, "_isnan");
    // _control87: 24-bit precision makes results float-rounded, like the original under that control word
    uint32_t cur = CALL("_control87", 0, 0);
    CHECK((cur & 0x30000) == 0x10000 && (cur & 0x8001F) == 0x8001F, "initial: 53-bit, all exceptions masked (%08X)", cur);
    CALL("_control87", 0x20000, 0x30000);
    CHECK(((c->cw >> 8) & 3) == 0, "_PC_24 sets PC=00 (cw %04X)", c->cw);
    x87_push(c, 1.0); x87_push(c, 3.0); CALL0("_CIfmod");   // fmod(1,3) = 1, exact either way
    pop_st0();
    CALL("sqrt", D(2.0));
    CHECK(pop_st0() == (double)(float)sqrt(2.0), "24-bit precision rounds to float");
    CALL("_control87", 0x300, 0x300);
    CHECK(((c->cw >> 10) & 3) == 3, "_RC_CHOP");
    uint32_t out = galloc(4);
    CHECK(CALL("_controlfp_s", out, 0x10000, 0x30000) == 0 && (M32(out) & 0x30000) == 0x10000, "_controlfp_s back to 53-bit");
    c->cw = 0x027F;
    // rand: the documented MSVC LCG; default seed 1 gives 41, 18467, 6334
    uint32_t r1 = CALL0("rand"), r2 = CALL0("rand"), r3 = CALL0("rand");
    CHECK(r1 == 41 && r2 == 18467 && r3 == 6334, "rand sequence %u %u %u", r1, r2, r3);
    CALL("srand", 1);
    CHECK(CALL0("rand") == 41, "srand(1) restarts the sequence");
}

static void sprintf_is(const char *want, const char *fmt, int n, const uint32_t *args) {
    uint32_t buf = galloc(256), a[16];
    a[0] = buf;
    a[1] = S(fmt);
    for (int i = 0; i < n; ++i) a[2 + i] = args[i];
    uint32_t r = call("sprintf", 2 + n, a) ? c->eax : 0;
    CHECK(!strcmp(gs(buf), want) && r == strlen(want), "sprintf(\"%s\") = \"%s\" (%u), want \"%s\"", fmt, gs(buf), r, want);
}
#define SP(want, fmt, ...) sprintf_is(want, fmt, NA(__VA_ARGS__), A(__VA_ARGS__))

static void test_printf(void) {
    SP("42|   42|42   |00042|+42", "%d|%5d|%-5d|%05d|%+d", 42, 42, 42, 42, 42);
    SP("-7|4294967289|fffffff9", "%i|%u|%x", (uint32_t)-7, (uint32_t)-7, (uint32_t)-7);
    SP("ff FF 0xff 377 0X00FF", "%x %X %#x %o %#06X", 255, 255, 255, 255, 255);
    SP("-5000000000|18446744073709551615", "%I64d|%llu", (uint32_t)-705032704, (uint32_t)-2, 0xFFFFFFFFu, 0xFFFFFFFFu);
    SP("-0012", "%05d", (uint32_t)-12);
    SP("  007", "%5.3d", 7);
    SP("1.234500e+003|1.5E-010", "%e|%.1E", D(1234.5), D(1.5e-10));
    SP("0.0001|1e-005|3.14|  2.50|2.5000000000", "%g|%g|%.2f|%6.2f|%.10f", D(0.0001), D(1e-5), D(3.14159), D(2.5), D(2.5));
    SP("-0001.50", "%08.2f", D(-1.5));
    SP("1.#INF00|-1.#INF00|-1.#IND00|1.#QNAN0", "%f|%f|%f|%f", D(INFINITY), D(-INFINITY), lo(0), 0xFFF80000u, D(NAN));
    SP("hello|hel|   ab|(null)", "%s|%.3s|%5s|%s", S("hello"), S("hello"), S("ab"), 0);
    SP("A|  B|C ", "%c|%3c|%-2c", 'A', 'B', 'C');
    SP("0012FF7C", "%p", 0x12FF7C);
    SP("100%", "%d%%", 100);
    SP("  42|42  ", "%*d|%-*d", 4, 42, 4, 42);
    SP("  42", "%*d", 4, 42);
    SP("-42  ", "%*d", (uint32_t)-5, (uint32_t)-42);
    SP("1.5", "%.*f", 1, D(1.5));
    SP("12", "%hd", 0x1000C);
    uint32_t w = galloc(8);
    M16(w) = 'H'; M16(w + 2) = 'i'; M16(w + 4) = 0;
    SP("Hi|Hi", "%ls|%S", w, w);
    // _snprintf: -1 and no terminator when truncated; exact fit: length, no terminator
    uint32_t buf = galloc(16);
    memset(G + buf, '#', 16);
    CHECK(CALL("_snprintf", buf, 5, S("%s"), S("hello world")) == 0xFFFFFFFFu && !memcmp(G + buf, "hello#", 6), "_snprintf truncates: %.6s", gs(buf));
    memset(G + buf, '#', 16);
    CHECK(CALL("_snprintf", buf, 5, S("%s"), S("hello")) == 5 && G[buf + 5] == '#', "_snprintf exact fit: no terminator");
    CHECK(CALL("_snprintf", buf, 5, S("%d"), 12) == 2 && !strcmp(gs(buf), "12"), "_snprintf fits");
    uint32_t va = galloc(8);
    M32(va) = 3; M32(va + 4) = S("x");
    CHECK(CALL("vsprintf", buf, S("%d%s"), va) == 2 && !strcmp(gs(buf), "3x"), "vsprintf with a guest va_list");
    CHECK(CALL("_vsnprintf", buf, 1, S("%d%s"), va) == 0xFFFFFFFFu, "_vsnprintf truncates");
    CHECK(CALL("printf", S("guest says %d\n"), 5) == 13, "printf returns the length");
    CHECK(fatal_call("sprintf", 3, A(buf, S("%n"), galloc(4))), "%%n is fatal");
}

static void test_scanf(void) {
    uint32_t i = galloc(4), s = galloc(32), f = galloc(8), x = galloc(4), n = galloc(4);
    CHECK(CALL("sscanf", S("  12 abc 3.5 0x1f"), S("%d %s %f %x"), i, s, f, x) == 4, "sscanf 4 fields");
    CHECK(M32(i) == 12 && !strcmp(gs(s), "abc") && MF32(f) == 3.5f && M32(x) == 31, "sscanf values %d %s %f %x", M32(i), gs(s), MF32(f), M32(x));
    CHECK(CALL("sscanf", S("2.25"), S("%lf"), f) == 1 && MF64(f) == 2.25, "%%lf stores a double");
    CHECK(CALL("sscanf", S("12345"), S("%3d"), i) == 1 && M32(i) == 123, "width");
    CHECK(CALL("sscanf", S("1 2"), S("%*d %d"), i) == 1 && M32(i) == 2, "suppression");
    CHECK(CALL("sscanf", S("abc123"), S("%[a-z]%n"), s, n) == 1 && !strcmp(gs(s), "abc") && M32(n) == 3, "%%[ and %%n");
    CHECK(CALL("sscanf", S("   "), S("%d"), i) == 0xFFFFFFFFu, "EOF before the first conversion");
    CHECK(CALL("sscanf", S("x"), S("%d"), i) == 0, "matching failure");
    CHECK(CALL("sscanf", S("key=val"), S("key=%s"), s) == 1 && !strcmp(gs(s), "val"), "literals");
    CHECK(CALL("sscanf", S("ab"), S("%c%c"), s, s + 1) == 2 && G[s] == 'a' && G[s + 1] == 'b', "%%c");
}

static void test_sort(void) {
    uint32_t arr = galloc(4 * 50);
    uint32_t rng = 12345;
    for (int k = 0; k < 50; ++k) { rng = rng * 1103515245u + 12345u; M32(arr + 4 * k) = (rng >> 16) % 40; }
    CALL("qsort", arr, 50, 4, 0x5000);
    int sorted = 1;
    for (int k = 1; k < 50; ++k) sorted &= (int32_t)M32(arr + 4 * k - 4) <= (int32_t)M32(arr + 4 * k);
    CHECK(sorted, "qsort sorts");
    uint32_t key = galloc(4);
    M32(key) = M32(arr + 4 * 17);
    uint32_t hit = CALL("bsearch", key, arr, 50, 4, 0x5000);
    CHECK(hit && M32(hit) == M32(key), "bsearch finds");
    M32(key) = 1000;
    CHECK(CALL("bsearch", key, arr, 50, 4, 0x5000) == 0, "bsearch misses");
    CALL("qsort", arr, 0, 4, 0x5000);
    CALL("qsort", arr, 1, 4, 0x5000);
}

static void test_startup(void) {
    uint32_t tab = galloc(16);
    M32(tab) = 0x5001; M32(tab + 4) = 0; M32(tab + 8) = 0x5002; M32(tab + 12) = 0x5003;
    init_n = 0;
    CHECK(CALL("_initterm", tab, tab + 12) == 0 && init_n == 2 && init_log[0] == 0x5001 && init_log[1] == 0x5002, "_initterm calls in order, skips NULL");
    init_n = 0;
    CHECK(CALL("_initterm_e", tab, tab + 16) == 7 && init_n == 3, "_initterm_e stops at the first non-zero result");
    uint32_t argc = galloc(4), argv = galloc(4), envp = galloc(4);
    CHECK(CALL("__getmainargs", argc, argv, envp, 0, 0) == 0 && M32(argc) == 1 && !strcmp(gs(M32(M32(argv))), "nfs.exe") && M32(M32(argv) + 4) == 0, "__getmainargs");
    CHECK(M32(M32(envp)) == 0, "empty environment");
    uint32_t fm = CALL0("__p__fmode");
    CHECK(fm && CALL0("__p__fmode") == fm, "__p__fmode is stable");
    CHECK(CALL("_encode_pointer", 0x1234) == 0x1234 && CALL("_decode_pointer", 0x1234) == 0x1234, "pointer encoding round-trips");
    CHECK(CALL("_configthreadlocale", 1) == 2 && CALL("_configthreadlocale", 0) == 1, "_configthreadlocale");
    CALL("_lock", 8);
    uint32_t l8 = cs_last;
    CALL("_unlock", 8);
    CALL("_lock", 8);
    CHECK(cs_last == l8 && cs_enters == 2 && cs_leaves == 1, "_lock(8) reuses its critical section");
    CALL("_unlock", 8);
    CHECK(fatal_call("_lock", 1, A(64)), "_lock out of range is fatal");
    CALL("__set_app_type", 2);
    CHECK(CALL("_XcptFilter", 0, 0) == 0, "_XcptFilter continues the search");
    CHECK(CALL("getenv", S("PATH")) == 0, "getenv: empty environment");
    CHECK(fatal_call("_invalid_parameter_noinfo", 0, NULL) && !strcmp(fatal_fn, "_invalid_parameter_noinfo"), "invalid parameter is fatal");
    CHECK(fatal_call("_purecall", 0, NULL), "_purecall is fatal");
    CHECK(fatal_call("_amsg_exit", 1, A(9)), "_amsg_exit is fatal");
    // _onexit then exit(3): the functions run in reverse order, then the process ends with the code
    CALL("_onexit", 0x5010);
    CALL("__dllonexit", 0x5011, 0, 0);
    init_n = 0;
    exit_code = -1;
    if (!setjmp(jb)) call("exit", 1, A(3));
    CHECK(exit_code == 3 && init_n == 2 && init_log[0] == 0x5011 && init_log[1] == 0x5010, "exit runs onexit in reverse (code %d, n %u)", exit_code, init_n);
    exit_code = -1;
    if (!setjmp(jb)) call("_exit", 1, A(4));
    CHECK(exit_code == 4, "_exit");
}

static void test_time(void) {
    uint32_t t = galloc(8);
    CHECK(call("_time64", 1, A(t)) && c->eax == 1234567890u && c->edx == 0 && M64(t) == 1234567890u, "_time64");
    uint32_t tb = galloc(16);
    CALL("_ftime64", tb);
    CHECK(M64(tb) == 1234567890u && M16(tb + 8) == 456, "_ftime64 %llu.%u", (unsigned long long)M64(tb), M16(tb + 8));
    uint32_t c0 = CALL0("clock"), c1 = CALL0("clock");
    CHECK(c1 == c0 + 5, "clock in milliseconds (%u -> %u)", c0, c1);
}


static size_t host_file(const char *rel, char *buf, size_t cap) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", root, rel);
    FILE *f = fopen(p, "rb");
    if (!f) return (size_t)-1;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}
static void put_host_file(const char *rel, const char *data, size_t n) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", root, rel);
    FILE *f = fopen(p, "wb");
    fwrite(data, 1, n, f);
    fclose(f);
}

static void test_files(void) {
    char hb[256];
    CHECK(CALL("_mkdir", S("C:\\NFSMW\\save")) == 0 && (int32_t)CALL("_mkdir", S("save")) == -1, "_mkdir, then it exists");
    // text-mode stream: LF becomes CRLF in the file
    uint32_t f = CALL("fopen", S("save\\a.txt"), S("w"));
    CHECK(f != 0, "fopen w");
    CHECK(CALL("fprintf", f, S("x=%d\n"), 5) == 4, "fprintf returns the length");
    CHECK(CALL("fwrite", S("ab\n"), 1, 3, f) == 3, "fwrite items");
    CHECK(CALL("fwrite", S("abcd"), 2, 2, f) == 2, "fwrite counts items of size 2");
    CHECK(CALL("fflush", f) == 0 && CALL("fflush", 0) == 0, "fflush");
    CHECK(CALL("fclose", f) == 0, "fclose");
    size_t n = host_file("save/a.txt", hb, sizeof hb);
    CHECK(n == 13 && !memcmp(hb, "x=5\r\nab\r\nabcd", 13), "text mode wrote CRLF (%zu bytes)", n);
    // low-level reads: text strips CR, binary keeps it
    uint32_t buf = galloc(256);
    int32_t fd = (int32_t)CALL("_open", S("save\\a.txt"), 0x4000);                 // _O_RDONLY | _O_TEXT
    CHECK(fd >= 3, "_open %d", fd);
    CHECK(CALL("_read", (uint32_t)fd, buf, 100) == 11 && !memcmp(G + buf, "x=5\nab\nabcd", 11), "text _read");
    CHECK(CALL("_read", (uint32_t)fd, buf, 100) == 0, "_read at end");
    CHECK(CALL("_lseek", (uint32_t)fd, 2, 0) == 2 && CALL("_filelength", (uint32_t)fd) == 13, "_lseek/_filelength");
    CHECK(CALL("_close", (uint32_t)fd) == 0 && (int32_t)CALL("_close", (uint32_t)fd) == -1, "_close twice");
    fd = (int32_t)CALL("?_open@@YAHPBDHH@Z", S("save\\a.txt"), 0x8000, 0);          // the C++ overload, _O_BINARY
    CHECK(CALL("_read", (uint32_t)fd, buf, 100) == 13 && !memcmp(G + buf, "x=5\r\n", 5), "binary _read keeps CR");
    CALL("_close", (uint32_t)fd);
    // Ctrl-Z ends a text file; CR at the end of a read chunk peeks at the next byte
    put_host_file("save/z.txt", "ab\x1A" "cd", 5);
    fd = (int32_t)CALL("_open", S("save\\z.txt"), 0);
    CHECK(CALL("_read", (uint32_t)fd, buf, 10) == 2 && CALL("_read", (uint32_t)fd, buf, 10) == 0, "Ctrl-Z is end of file");
    CALL("_close", (uint32_t)fd);
    put_host_file("save/cr.txt", "a\r\nb", 4);
    fd = (int32_t)CALL("_open", S("save\\cr.txt"), 0);
    CHECK(CALL("_read", (uint32_t)fd, buf, 2) == 2 && !memcmp(G + buf, "a\n", 2), "CRLF across a chunk boundary");
    CHECK(CALL("_read", (uint32_t)fd, buf, 2) == 1 && G[buf] == 'b', "then the rest");
    CALL("_close", (uint32_t)fd);
    CHECK((int32_t)CALL("_open", S("save\\missing.txt"), 0) == -1, "_open of a missing file");
    CHECK((int32_t)CALL("_open", S("save\\a.txt"), 0x100 | 0x400 | 1) == -1, "_O_CREAT|_O_EXCL on an existing file");
    // _write in binary and append modes
    fd = (int32_t)CALL("_open", S("save\\w.bin"), 0x8000 | 0x100 | 0x200 | 1);
    CHECK(CALL("_write", (uint32_t)fd, S("1\n2"), 3) == 3, "_write binary");
    CALL("_close", (uint32_t)fd);
    f = CALL("fopen", S("save\\w.bin"), S("ab"));
    CALL("fwrite", S("Z"), 1, 1, f);
    CALL("fclose", f);
    n = host_file("save/w.bin", hb, sizeof hb);
    CHECK(n == 4 && !memcmp(hb, "1\n2Z", 4), "binary write + append");
    f = CALL("fopen", S("save\\w.bin"), S("r+b"));
    CHECK(f && CALL("fseek", f, 1, 0) == 0 && CALL("fwrite", S("X"), 1, 1, f) == 1, "fseek then write in r+");
    CALL("fclose", f);
    n = host_file("save/w.bin", hb, sizeof hb);
    CHECK(n == 4 && !memcmp(hb, "1X2Z", 4), "r+ overwrote byte 1");
    CHECK(CALL("fopen", S("save\\nope.txt"), S("r")) == 0, "fopen r of a missing file");
    CHECK(CALL("fclose", 0x12345) == 0xFFFFFFFFu, "fclose of a non-stream");
    // standard streams go to the log
    uint32_t iob = CALL0("__iob_func");
    CHECK(iob && M32(iob + 32 + 16) == 1 && M32(iob + 64 + 16) == 2, "_iob[1], _iob[2] are fds 1 and 2");
    CHECK(CALL("fprintf", iob + 64, S("to stderr %s\n"), S("ok")) == 13, "fprintf(stderr)");
    CHECK(CALL("fwrite", S("hi\n"), 1, 3, iob + 32) == 3, "fwrite(stdout)");
    CHECK(CALL("_write", 1, S("log\n"), 4) == 4, "_write(1)");
    // finding files
    uint32_t info = galloc(296);
    uint32_t h = CALL("_findfirst64i32", S("save\\*.txt"), info);
    int seen = 0, count = 0;
    if (h != 0xFFFFFFFFu) {
        do {
            const char *name = (const char *)G + info + 36;
            ++count;
            if (!strcmp(name, "a.txt")) { seen |= 1; CHECK(M32(info + 32) == 13 && M32(info) == 0x20 && M64(info + 24) > 1600000000ull, "a.txt info"); }
            if (!strcmp(name, "z.txt")) seen |= 2;
            if (!strcmp(name, "cr.txt")) seen |= 4;
        } while (CALL("_findnext64i32", h, info) == 0);
    }
    CHECK(seen == 7 && count == 3, "_findfirst/_findnext saw %d files (mask %d)", count, seen);
    CHECK(CALL("_findclose", h) == 0, "_findclose");
    CHECK(CALL("_findfirst64i32", S("save\\*.none"), info) == 0xFFFFFFFFu, "_findfirst with no match");
    // rename, remove, chmod, rmdir
    CHECK(CALL("rename", S("save\\a.txt"), S("save\\c.txt")) == 0 && host_file("save/c.txt", hb, sizeof hb) == 13, "rename");
    CHECK(CALL("_chmod", S("save\\c.txt"), 0x80) == 0 && (int32_t)CALL("_chmod", S("save\\a.txt"), 0x80) == -1, "_chmod");
    const char *files[] = {"save\\c.txt", "save\\z.txt", "save\\cr.txt", "save\\w.bin"};
    for (int k = 0; k < 4; ++k) CHECK(CALL("remove", S(files[k])) == 0, "remove %s", files[k]);
    CHECK((int32_t)CALL("remove", S("save\\c.txt")) == -1, "remove twice");
    CHECK(CALL("_rmdir", S("save")) == 0 && (int32_t)CALL("_rmdir", S("save")) == -1, "_rmdir");
    // paths
    CHECK(CALL("_getcwd", buf, 64) == buf && !strcmp(gs(buf), "C:\\NFSMW"), "_getcwd");
    CHECK(CALL("_getcwd", buf, 4) == 0, "_getcwd too small");
    uint32_t a = CALL("_getcwd", 0, 0);
    CHECK(a && !strcmp(gs(a), "C:\\NFSMW"), "_getcwd allocates");
    CHECK(CALL("_fullpath", buf, S("data\\..\\x/./y.txt"), 260) == buf && !strcmp(gs(buf), "C:\\NFSMW\\x\\y.txt"), "_fullpath relative: %s", gs(buf));
    a = CALL("_fullpath", 0, S("\\abs\\p"), 0);
    CHECK(a && !strcmp(gs(a), "C:\\abs\\p"), "_fullpath rooted: %s", a ? gs(a) : "(null)");
    CALL("_fullpath", buf, S("D:\\q\\.\\r\\..\\s"), 260);
    CHECK(!strcmp(gs(buf), "D:\\q\\s"), "_fullpath with a drive: %s", gs(buf));
    CALL("_fullpath", buf, S("C:\\.."), 260);
    CHECK(!strcmp(gs(buf), "C:\\"), "_fullpath stops at the root: %s", gs(buf));
    CHECK(CALL0("_getdrive") == 3, "_getdrive");
    uint32_t df = galloc(16);
    CHECK(CALL("_getdiskfree", 3, df) == 0 && M32(df + 12) == 512, "_getdiskfree");
}

static void test_wide(void) {
    // _vsnwprintf: UTF-16 format and output; %s wide, %S narrow, %c wide, %hs narrow in a wide format
    uint32_t fmt = galloc(64), w = galloc(16), out = galloc(64), va = galloc(32);
    const uint16_t f16[] = {'%', 's', '=', '%', 'd', ' ', '%', 'S', ' ', '%', 'c', '%', 'h', 's', '|', '%', '5', 's', 0};
    memcpy(G + fmt, f16, sizeof f16);
    const uint16_t name[] = {'n', 0xE9, 0x416, 0};                    // "né" + Cyrillic Zhe
    memcpy(G + w, name, sizeof name);
    M32(va) = w; M32(va + 4) = 42; M32(va + 8) = S("ok"); M32(va + 12) = 0x416; M32(va + 16) = S("x"); M32(va + 20) = w;
    uint32_t n = CALL("_vsnwprintf", out, 32, fmt, va);
    const uint16_t want[] = {'n', 0xE9, 0x416, '=', '4', '2', ' ', 'o', 'k', ' ', 0x416, 'x', '|', ' ', ' ', 'n', 0xE9, 0x416, 0};
    CHECK(n == 18 && !memcmp(G + out, want, sizeof want), "_vsnwprintf output (%u units)", n);
    CHECK(CALL("_vsnwprintf", out, 3, fmt, va) == 0xFFFFFFFFu, "_vsnwprintf truncates with -1");
    // narrow output of a wide argument: Latin-1 kept, wider characters become '?'
    uint32_t nb = galloc(16);
    CALL("sprintf", nb, S("%ls"), w);
    CHECK(!strcmp(gs(nb), "n\xE9?"), "%%ls narrows to Latin-1");
}

static void test_time2(void) {
    uint32_t t = galloc(8), tm;
    M64(t) = 1234567890;                                              // 2009-02-13 23:31:30 UTC, a Friday
    tm = CALL("_gmtime64", t);
    CHECK(tm && M32(tm) == 30 && M32(tm + 4) == 31 && M32(tm + 8) == 23 && M32(tm + 12) == 13 && M32(tm + 16) == 1 &&
          M32(tm + 20) == 109 && M32(tm + 24) == 5 && M32(tm + 28) == 43 && M32(tm + 32) == 0, "_gmtime64 fields");
    CHECK(CALL("_localtime64", t) == tm && M32(tm + 8) == 23, "_localtime64 (TZ=UTC) shares the per-thread buffer");
    uint32_t t32 = galloc(4);
    M32(t32) = 86400;
    CHECK(CALL("_localtime32", t32) && M32(tm + 12) == 2 && M32(tm + 20) == 70, "_localtime32");
    M64(t) = (uint64_t)-1;
    CHECK(CALL("_localtime64", t) == 0, "negative time gives NULL");
    M64(t) = 32535216000ull;
    CHECK(CALL("_gmtime64", t) == 0, "past 3000-12-31 gives NULL");
    uint32_t mt = galloc(36);
    const int32_t in[9] = {0, 0, 0, 32, 0, 109, 0, 0, 0};             // 32 January 2009
    for (int k = 0; k < 9; ++k) M32(mt + 4 * (uint32_t)k) = (uint32_t)in[k];
    CHECK(call("_mktime64", 1, A(mt)) && c->eax == 1233446400u && c->edx == 0, "_mktime64 = %u", c->eax);
    CHECK(M32(mt + 12) == 1 && M32(mt + 16) == 1 && M32(mt + 24) == 0, "_mktime64 normalizes to 1 February (Sunday)");
    M32(mt + 12) = 32; M32(mt + 16) = 0;
    CHECK(call("_mkgmtime64", 1, A(mt)) && c->eax == 1233446400u, "_mkgmtime64");
    CALL("_difftime64", 100, 0, 40, 0);
    CHECK(pop_st0() == 60.0, "_difftime64");
    M64(t) = 1234567890;
    tm = CALL("_gmtime64", t);
    uint32_t s = CALL("asctime", tm);
    CHECK(s && !strcmp(gs(s), "Fri Feb 13 23:31:30 2009\n"), "asctime: %s", s ? gs(s) : "(null)");
    M32(tm + 12) = 2;
    CHECK(!strcmp(gs(CALL("asctime", tm)), "Fri Feb 02 23:31:30 2009\n"), "asctime pads the day with a zero (VC8)");
    uint32_t tb = galloc(16);
    CALL("_ftime64", tb);
    CHECK(M16(tb + 10) == 0 && M16(tb + 12) == 0, "_ftime64 time zone under TZ=UTC");
}

static void test_threads(void) {
    uint32_t tid = galloc(4);
    CHECK(CALL("_beginthreadex", 0, 0x10000, 0x401000, 0x55, 4, tid) == 0x2004, "_beginthreadex returns CreateThread's handle");
    CHECK(!strcmp(thread_fn, "CreateThread") && thread_args[1] == 0x10000 && thread_args[2] == 0x401000 && thread_args[3] == 0x55 &&
          thread_args[4] == 4 && thread_args[5] == tid, "CreateThread got the same arguments");
    CALL("_endthreadex", 7);
    CHECK(!strcmp(thread_fn, "ExitThread") && thread_args[0] == 7, "_endthreadex -> ExitThread(7)");
}

uint32_t crt_data_import(const char *name);
static void test_data_imports(void) {
    uint32_t fd = crt_data_import("MSVCR80.dll!_adjust_fdiv"), env = crt_data_import("MSVCR80.dll!__initenv");
    CHECK(fd && M32(fd) == 0, "_adjust_fdiv is a zero variable");
    uint32_t argc = galloc(4), argv = galloc(4), envp = galloc(4);
    CALL("__getmainargs", argc, argv, envp, 0, 0);
    CHECK(env && M32(env) == M32(envp) && M32(M32(env)) == 0, "__initenv points at the (empty) environment __getmainargs returns");
    CHECK(crt_data_import("MSVCR80.dll!malloc") == 0 && crt_data_import("KERNEL32.dll!__initenv") == 0, "functions and other DLLs are not data");
    CHECK(crt_data_import("MSVCR80.dll!_adjust_fdiv") == fd, "stable address");
}

int main(void) {
    G = mmap(0, 1ull << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (G == MAP_FAILED) { printf("cannot reserve guest memory\n"); return 2; }
    c->cw = 0x027F;
    setenv("TZ", "UTC", 1);
    tzset();
    const char *tmp = getenv("C_TEST_TMP") ? getenv("C_TEST_TMP") : getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(root, sizeof root, "%s/msvcr_test.XXXXXX", tmp);
    if (!mkdtemp(root)) { printf("cannot create a scratch directory\n"); return 2; }
    test_memory();
    test_strings();
    test_conversion();
    test_math();
    test_printf();
    test_scanf();
    test_sort();
    test_startup();
    test_time();
    test_files();
    test_wide();
    test_time2();
    test_threads();
    test_data_imports();
    CHECK(!win32_msvcr(c, "NoSuchCrtFunction"), "unknown functions are not handled");
    rmdir(root);
    if (getenv("MSVCR_TEST_SELFCHECK")) SP("43", "%d", 42);   // deliberately wrong: must be reported
    printf("%s: %d checks, %d failing\n", fails ? "FAIL" : "ok", checks, fails);
    return fails ? 1 : 0;
}
