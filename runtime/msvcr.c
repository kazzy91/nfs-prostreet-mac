// msvcr.c - MSVCR80/MSVCP80 (Visual C++ 2005 runtime) for the guest, implemented natively. See docs/crt-shim.md.
// CRT functions are __cdecl: a handler sets eax (edx:eax for 64-bit results, ST(0) for double) and pops only the
// return address (CRET). Anything not handled here returns 0, and host_import stops with the import's name.
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "host.h"

// heap.c: the guest process heap, the same one HeapAlloc serves (crt_heap_alloc zeroes, returns 0 when full).
uint32_t crt_heap_alloc(uint32_t n);
void crt_heap_free(uint32_t a);
uint32_t crt_heap_realloc(uint32_t a, uint32_t n);
uint32_t crt_heap_size(uint32_t a);
// threads.c: guest CRITICAL_SECTION enter/leave (recursive, GIL-aware), for _lock/_unlock.
void crt_cs_enter(Cpu *c, uint32_t cs);
void crt_cs_leave(uint32_t cs);
// boot.c's file layer: the same handles, paths and save protection as CreateFileA & co (failures: 0xFFFFFFFF / -1 / 0).
int host_resolve(const char *win, char *out, size_t n);
uint32_t host_file_open(const char *win, uint32_t access, uint32_t share, uint32_t disp);
int64_t host_file_read(uint32_t h, uint32_t buf, uint32_t n);
int64_t host_file_write(uint32_t h, uint32_t buf, uint32_t n);
int64_t host_file_seek(uint32_t h, int64_t distance, int method);
int64_t host_file_size(uint32_t h);
int host_file_close(uint32_t h);
int host_file_remove(const char *win, int dir);
int host_file_rename(const char *from, const char *to);
int host_mkdir(const char *win);
int host_file_exists(const char *win);
uint32_t host_find_first(const char *win, uint32_t data);
int host_find_next(uint32_t h, uint32_t data);
void host_find_close(uint32_t h);
// Ends the run like ExitProcess (boot.c / app.m); tests provide their own.
void crt_exit_process(Cpu *c, uint32_t code);
void crt_fatal(const char *fn, const char *why) __attribute__((noreturn));

#define CRET(v) do { c->eax = (uint32_t)(v); c->esp += 4; return 1; } while (0)
#define CRET64(v) do { uint64_t r_ = (uint64_t)(v); c->eax = (uint32_t)r_; c->edx = (uint32_t)(r_ >> 32); c->esp += 4; return 1; } while (0)
#define CRETF(d) do { x87_push(c, x87_round(c, (d))); c->esp += 4; return 1; } while (0)
#define CRETV() do { c->esp += 4; return 1; } while (0)

static double argd(Cpu *c, int i) { uint64_t u = (uint64_t)arg(c, i) | (uint64_t)arg(c, i + 1) << 32; double d; memcpy(&d, &u, 8); return d; }
static char *gs(uint32_t a) { return (char *)G + a; }

// ---------------- ctype: the "C" locale ----------------
static int c_isspace(int ch) { return ch == ' ' || (ch >= 9 && ch <= 13); }
static int c_isdigit(int ch) { return ch >= '0' && ch <= '9'; }
static int c_isprint(int ch) { return ch >= 0x20 && ch <= 0x7E; }
static int c_tolower(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }
static int c_toupper(int ch) { return ch >= 'a' && ch <= 'z' ? ch - 32 : ch; }

// ---------------- conversion ----------------
// strtol/strtoul with 32-bit results: overflow clamps (LONG_MAX/LONG_MIN, ULONG_MAX); strtoul negates in 32 bits.
static uint32_t c_strtox(uint32_t s, uint32_t *end, int base, int is_signed) {
    uint32_t p = s, start;
    while (c_isspace(M8(p))) ++p;
    int neg = 0;
    if (M8(p) == '+' || M8(p) == '-') neg = M8(p++) == '-';
    if ((base == 0 || base == 16) && M8(p) == '0' && (M8(p + 1) | 0x20) == 'x' && isxdigit(M8(p + 2))) { p += 2; base = 16; }
    else if (base == 0) base = M8(p) == '0' ? 8 : 10;
    if (base < 2 || base > 36) { if (end) *end = s; return 0; }
    start = p;
    uint64_t v = 0;
    int over = 0;
    for (;; ++p) {
        int ch = M8(p), d = c_isdigit(ch) ? ch - '0' : (ch | 0x20) >= 'a' && (ch | 0x20) <= 'z' ? (ch | 0x20) - 'a' + 10 : 99;
        if (d >= base) break;
        v = v * (uint64_t)base + (uint64_t)d;
        if (v > 0xFFFFFFFFull) over = 1, v = 0xFFFFFFFFull + 1;
    }
    if (p == start) { if (end) *end = s; return 0; }
    if (end) *end = p;
    if (is_signed) {
        if (over || (!neg && v > 0x7FFFFFFFull)) return neg ? 0x80000000u : 0x7FFFFFFFu;
        if (neg && v > 0x80000000ull) return 0x80000000u;
        return neg ? (uint32_t)-(int64_t)v : (uint32_t)v;
    }
    if (over) return 0xFFFFFFFFu;
    return neg ? (uint32_t)-(uint32_t)v : (uint32_t)v;
}

// MSVC's decimal float syntax (no hex, inf or nan; 'd'/'D' accepted as the exponent letter). Copies at most `max`
// chars of the longest valid prefix into buf (NUL-terminated, 'd' turned into 'e') and returns how many it took.
static uint32_t float_extent(uint32_t p, uint32_t max, char *buf, size_t cap) {
    uint32_t q = p, n = 0;
#define TAKE(ch) do { if (n + 1 < cap) buf[n] = (char)(ch); ++n; ++q; } while (0)
    if (n < max && (M8(q) == '+' || M8(q) == '-')) TAKE(M8(q));
    uint32_t digits = 0;
    while (n < max && c_isdigit(M8(q))) { TAKE(M8(q)); ++digits; }
    if (n < max && M8(q) == '.') { TAKE('.'); while (n < max && c_isdigit(M8(q))) { TAKE(M8(q)); ++digits; } }
    if (!digits) { buf[0] = 0; return 0; }
    uint32_t save_n = n, save_q = q;
    if (n < max && ((M8(q) | 0x20) == 'e' || (M8(q) | 0x20) == 'd')) {
        TAKE('e');
        if (n < max && (M8(q) == '+' || M8(q) == '-')) TAKE(M8(q));
        uint32_t ed = 0;
        while (n < max && c_isdigit(M8(q))) { TAKE(M8(q)); ++ed; }
        if (!ed) { n = save_n; q = save_q; }
    }
#undef TAKE
    buf[n < cap ? n : cap - 1] = 0;
    return q - p;
}
static double c_atof(uint32_t s, uint32_t *end) {
    uint32_t p = s;
    while (c_isspace(M8(p))) ++p;
    char buf[512];
    uint32_t n = float_extent(p, 0xFFFFFFFFu, buf, sizeof buf);
    if (end) *end = n ? p + n : s;
    return n ? strtod(buf, NULL) : 0.0;
}

// ---------------- printf engine ----------------
typedef struct {
    uint32_t dst, cap;   // guest output (cap units at most); dst 0 = host log
    uint32_t n;          // units produced (all, also beyond cap)
    int wide;            // guest output is UTF-16 (wprintf family)
    char line[512];
    int ln;
} Out;
static void out_flush(Out *o) {
    if (o->ln) { fprintf(stderr, "guest: %.*s\n", o->ln, o->line); o->ln = 0; }
}
// One output unit. Narrow output keeps Latin-1 and turns anything wider into '?', like MW's code-page identity mapping.
static void out_u(Out *o, uint16_t u) {
    char ch = u > 0xFF ? '?' : (char)u;
    if (o->dst) {
        if (o->n < o->cap) { if (o->wide) M16(o->dst + 2 * o->n) = u; else M8(o->dst + o->n) = (uint8_t)ch; }
    } else if (ch == '\n' || o->ln == (int)sizeof o->line) { out_flush(o); if (ch != '\n') o->line[o->ln++] = ch; }
    else o->line[o->ln++] = ch;
    ++o->n;
}
static void out_c(Out *o, char ch) { out_u(o, (uint8_t)ch); }
static void out_s(Out *o, const char *s, size_t n) { while (n--) out_c(o, *s++); }
static void out_pad(Out *o, char ch, int n) { while (n-- > 0) out_c(o, ch); }

typedef struct { uint32_t p; } VA;   // a guest va_list: the address of the next argument
static uint32_t va32(VA *v) { uint32_t x = M32(v->p); v->p += 4; return x; }
static uint64_t va64(VA *v) { uint64_t x = M64(v->p); v->p += 8; return x; }

// MSVC 2005 prints exponents with (at least) three digits: 1.000000e+000.
static size_t exp3(char *b, size_t n, size_t cap) {
    char *e = NULL;
    for (size_t i = 0; i < n; ++i) if (b[i] == 'e' || b[i] == 'E') { e = b + i; break; }
    if (!e || (e[1] != '+' && e[1] != '-')) return n;
    size_t digits = n - (size_t)(e + 2 - b);
    if (digits >= 3 || n + (3 - digits) >= cap) return n;
    size_t add = 3 - digits;
    memmove(e + 2 + add, e + 2, digits + 1);
    memset(e + 2, '0', add);
    return n + add;
}
// 1.#INF, 1.#QNAN, 1.#SNAN, -1.#IND: VC8's text for non-finite values, padded or cut to the precision after "1."
static size_t nonfinite(double d, char t, int prec, int plus, int space, char *b, size_t cap) {
    uint64_t u;
    memcpy(&u, &d, 8);
    int neg = (int)(u >> 63);
    uint64_t mant = u & 0xFFFFFFFFFFFFFull;
    const char *tail = isinf(d) ? "#INF" : (neg && mant == 0x8000000000000ull) ? "#IND" : (mant & 0x8000000000000ull) ? "#QNAN" : "#SNAN";
    size_t n = 0;
    if (neg) b[n++] = '-';
    else if (plus) b[n++] = '+';
    else if (space) b[n++] = ' ';
    b[n++] = '1';
    b[n++] = '.';
    int p = prec < 0 ? 6 : prec;
    if (t == 'g' || t == 'G') p = (int)strlen(tail);
    for (int i = 0; i < p && n + 6 < cap; ++i) b[n++] = i < (int)strlen(tail) ? tail[i] : '0';
    if (t == 'e' || t == 'E') { memcpy(b + n, t == 'e' ? "e+000" : "E+000", 5); n += 5; }
    b[n] = 0;
    return n;
}

// fw: the format string is UTF-16 (wprintf family). In wide formats %s/%c take wide arguments and %S/%C narrow ones;
// h forces narrow, l/w force wide (MSVC rules).
static void format(Out *o, uint32_t f, int fw, VA *v) {
    const uint32_t step = fw ? 2 : 1;
#define FC(i) (fw ? M16(f + 2 * (i)) : M8(f + (i)))
    for (;;) {
        uint16_t u = FC(0);
        f += step;
        if (!u) break;
        if (u != '%') { out_u(o, u); continue; }
        char ch;
        int left = 0, plus = 0, space = 0, alt = 0, zero = 0;
        for (;; f += step) {
            ch = (char)FC(0);
            if (ch == '-') left = 1;
            else if (ch == '+') plus = 1;
            else if (ch == ' ') space = 1;
            else if (ch == '#') alt = 1;
            else if (ch == '0') zero = 1;
            else break;
        }
        int width = 0, prec = -1;
        if (FC(0) == '*') { f += step; int32_t w = (int32_t)va32(v); if (w < 0) { left = 1; w = -w; } width = w; }
        else while (c_isdigit(FC(0))) { width = width * 10 + (FC(0) - '0'); f += step; }
        if (FC(0) == '.') {
            f += step;
            prec = 0;
            if (FC(0) == '*') { f += step; int32_t p = (int32_t)va32(v); prec = p < 0 ? -1 : p; }
            else while (c_isdigit(FC(0))) { prec = prec * 10 + (FC(0) - '0'); f += step; }
        }
        if (width > 65536) width = 65536;
        if (prec > 4096) prec = 4096;
        int size = 0;   // 'h', 'l' (also w), 64 (ll, I64), 'L'
        ch = (char)FC(0);
        if (ch == 'h') { size = 'h'; f += step; }
        else if (ch == 'l') { f += step; if (FC(0) == 'l') { f += step; size = 64; } else size = 'l'; }
        else if (ch == 'L') { size = 'L'; f += step; }
        else if (ch == 'w') { size = 'l'; f += step; }
        else if (ch == 'I') {
            if (FC(1) == '6' && FC(2) == '4') { size = 64; f += 3 * step; }
            else if (FC(1) == '3' && FC(2) == '2') f += 3 * step;
            else f += step;
        }
        uint16_t tu = FC(0);
        f += step;
        if (!tu) break;
        char t = tu > 0x7F ? '?' : (char)tu;
        char hf[16], *body = NULL, small[64];
        uint16_t *units = NULL;   // %s/%c: UTF-16 units, emitted as they are (padding counts units)
        size_t blen = 0;
        int numeric = 0, zero_ok = 0, owned = 0;
        int wsrc = size == 'l' ? 1 : size == 'h' ? 0 : (t == 's' || t == 'c') ? fw : !fw;   // %s/%c argument width
        switch (t) {
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': {
            long long sv = 0;
            unsigned long long uv = 0;
            int sgn = t == 'd' || t == 'i';
            if (size == 64) { uint64_t r = va64(v); sv = (int64_t)r; uv = r; }
            else { uint32_t r = va32(v); if (size == 'h') r &= 0xFFFF; sv = size == 'h' ? (int16_t)r : (int32_t)r; uv = r; }
            snprintf(hf, sizeof hf, "%%%s%s%s%sll%c", plus ? "+" : "", space ? " " : "", alt ? "#" : "", prec >= 0 ? ".*" : "", sgn ? 'd' : t);
            int need = prec >= 0 ? (sgn ? snprintf(NULL, 0, hf, prec, sv) : snprintf(NULL, 0, hf, prec, uv))
                                 : (sgn ? snprintf(NULL, 0, hf, sv) : snprintf(NULL, 0, hf, uv));
            body = malloc((size_t)need + 1);
            owned = 1;
            if (prec >= 0) sgn ? snprintf(body, (size_t)need + 1, hf, prec, sv) : snprintf(body, (size_t)need + 1, hf, prec, uv);
            else sgn ? snprintf(body, (size_t)need + 1, hf, sv) : snprintf(body, (size_t)need + 1, hf, uv);
            blen = (size_t)need;
            numeric = 1;
            zero_ok = prec < 0;
            break;
        }
        case 'e': case 'E': case 'f': case 'g': case 'G': {
            uint64_t r = va64(v);
            double d;
            memcpy(&d, &r, 8);
            if (!isfinite(d)) {
                body = malloc((size_t)(prec < 0 ? 6 : prec) + 32);
                owned = 1;
                blen = nonfinite(d, t, prec, plus, space, body, (size_t)(prec < 0 ? 6 : prec) + 32);
                numeric = 1;
                break;
            }
            snprintf(hf, sizeof hf, "%%%s%s%s%s%c", plus ? "+" : "", space ? " " : "", alt ? "#" : "", prec >= 0 ? ".*" : "", t);
            int need = prec >= 0 ? snprintf(NULL, 0, hf, prec, d) : snprintf(NULL, 0, hf, d);
            body = malloc((size_t)need + 8);
            owned = 1;
            if (prec >= 0) snprintf(body, (size_t)need + 1, hf, prec, d);
            else snprintf(body, (size_t)need + 1, hf, d);
            blen = exp3(body, (size_t)need, (size_t)need + 8);
            numeric = zero_ok = 1;
            break;
        }
        case 'c': case 'C': {
            uint32_t r = va32(v);
            units = malloc(sizeof *units);
            units[0] = wsrc ? (uint16_t)r : (uint8_t)r;
            blen = 1;
            break;
        }
        case 's': case 'S': {
            uint32_t p = va32(v);
            if (!p) { body = (char *)"(null)"; blen = 6; if (prec >= 0 && (size_t)prec < blen) blen = (size_t)prec; break; }
            size_t n = 0;
            if (wsrc) while ((prec < 0 || n < (size_t)prec) && M16(p + 2 * n)) ++n;
            else while ((prec < 0 || n < (size_t)prec) && M8(p + n)) ++n;
            units = malloc((n ? n : 1) * sizeof *units);
            for (size_t k = 0; k < n; ++k) units[k] = wsrc ? M16(p + 2 * k) : M8(p + k);
            blen = n;
            break;
        }
        case 'p':
            blen = (size_t)snprintf(small, sizeof small, "%08X", va32(v));
            body = small;
            break;
        case 'n':
            crt_fatal("printf", "%n is disabled in the VC8 runtime (invalid parameter)");
            return;
        default:   // '%' and anything unknown: the character itself
            small[0] = t;
            body = small;
            blen = 1;
            break;
        }
        int pad = width > (int)blen ? width - (int)blen : 0;
        if (units) {
            if (!left) out_pad(o, ' ', pad);
            for (size_t k = 0; k < blen; ++k) out_u(o, units[k]);
            if (left) out_pad(o, ' ', pad);
            free(units);
            continue;
        }
        if (left) { out_s(o, body, blen); out_pad(o, ' ', pad); }
        else if (zero && zero_ok && numeric) {
            size_t pre = 0;
            if (blen && (body[0] == '-' || body[0] == '+' || body[0] == ' ')) pre = 1;
            if (blen >= pre + 2 && body[pre] == '0' && (body[pre + 1] == 'x' || body[pre + 1] == 'X')) pre += 2;
            out_s(o, body, pre);
            out_pad(o, '0', pad);
            out_s(o, body + pre, blen - pre);
        } else { out_pad(o, ' ', pad); out_s(o, body, blen); }
        if (owned) free(body);
    }
#undef FC
}

// vsnprintf-style front end: writes at most cap chars to dst; returns the full length.
static uint32_t format_to(uint32_t dst, uint32_t cap, uint32_t fmt, uint32_t va) {
    Out o = {.dst = dst, .cap = cap};
    VA v = {va};
    format(&o, fmt, 0, &v);
    return o.n;
}
// The same for UTF-16 output and format (_vsnwprintf): cap and the result count wchar_t units.
static uint32_t wformat_to(uint32_t dst, uint32_t cap, uint32_t fmt, uint32_t va) {
    Out o = {.dst = dst, .cap = cap, .wide = 1};
    VA v = {va};
    format(&o, fmt, 1, &v);
    return o.n;
}

// ---------------- scanf engine ----------------
static int scan(uint32_t s, uint32_t f, VA *v) {
    uint32_t p = s;
    int assigned = 0, any = 0;
    for (;;) {
        char ch = (char)M8(f++);
        if (!ch) break;
        if (c_isspace(ch)) { while (c_isspace(M8(p))) ++p; continue; }
        if (ch != '%' || M8(f) == '%') {
            if (ch == '%') { ++f; while (c_isspace(M8(p))) ++p; }
            if (M8(p) != (uint8_t)ch) break;
            ++p;
            continue;
        }
        int suppress = 0, size = 0;
        uint32_t width = 0;
        if (M8(f) == '*') { suppress = 1; ++f; }
        while (c_isdigit(M8(f))) width = width * 10 + (uint32_t)(M8(f++) - '0');
        ch = (char)M8(f);
        if (ch == 'h') { size = 'h'; ++f; }
        else if (ch == 'l') { ++f; if (M8(f) == 'l') { ++f; size = 64; } else size = 'l'; }
        else if (ch == 'L') { size = 'l'; ++f; }
        else if (ch == 'I' && M8(f + 1) == '6' && M8(f + 2) == '4') { size = 64; f += 3; }
        char t = (char)M8(f++);
        if (!t) break;
        if (t == 'n') { if (!suppress) M32(va32(v)) = p - s; continue; }
        if (t != 'c' && t != '[') while (c_isspace(M8(p))) ++p;
        if (!M8(p)) return any ? assigned : -1;   // input failure: EOF before the first conversion
        uint32_t max = width ? width : 0xFFFFFFFFu;
        if (t == 'd' || t == 'i' || t == 'u' || t == 'x' || t == 'X' || t == 'o') {
            char buf[128];
            uint32_t n = 0;
            while (n < max && n + 1 < sizeof buf && M8(p + n) && !c_isspace(M8(p + n))) { buf[n] = (char)M8(p + n); ++n; }
            buf[n] = 0;
            char *end;
            int base = t == 'o' ? 8 : t == 'x' || t == 'X' ? 16 : t == 'i' ? 0 : 10;
            long long sv = 0;
            unsigned long long uv = 0;
            if (t == 'd' || t == 'i') sv = strtoll(buf, &end, base); else { uv = strtoull(buf, &end, base); sv = (long long)uv; }
            if (end == buf) break;
            p += (uint32_t)(end - buf);
            any = 1;
            if (!suppress) {
                uint32_t dst = va32(v);
                if (size == 'h') M16(dst) = (uint16_t)sv;
                else if (size == 64) M64(dst) = (uint64_t)sv;
                else M32(dst) = (uint32_t)sv;
                ++assigned;
            }
        } else if (t == 'e' || t == 'E' || t == 'f' || t == 'g' || t == 'G') {
            char buf[512];
            uint32_t n = float_extent(p, max, buf, sizeof buf);
            if (!n) break;
            p += n;
            any = 1;
            if (!suppress) {
                uint32_t dst = va32(v);
                double d = strtod(buf, NULL);
                if (size == 'l') MF64(dst) = d; else MF32(dst) = (float)d;
                ++assigned;
            }
        } else if (t == 's') {
            uint32_t dst = suppress ? 0 : va32(v), n = 0;
            while (n < max && M8(p) && !c_isspace(M8(p))) { if (dst) M8(dst + n) = M8(p); ++n; ++p; }
            if (dst) M8(dst + n) = 0;
            any = 1;
            if (!suppress) ++assigned;
        } else if (t == 'c') {
            uint32_t n = width ? width : 1, dst = suppress ? 0 : va32(v), k = 0;
            for (; k < n && M8(p); ++k, ++p) if (dst) M8(dst + k) = M8(p);
            if (k < n) return any ? assigned : -1;
            any = 1;
            if (!suppress) ++assigned;
        } else if (t == '[') {
            uint8_t set[256] = {0};
            int neg = 0;
            if (M8(f) == '^') { neg = 1; ++f; }
            if (M8(f) == ']') { set[']'] = 1; ++f; }
            while (M8(f) && M8(f) != ']') {
                uint8_t a = M8(f);
                if (M8(f + 1) == '-' && M8(f + 2) && M8(f + 2) != ']') { for (unsigned k = a; k <= M8(f + 2); ++k) set[k] = 1; f += 3; }
                else { set[a] = 1; ++f; }
            }
            if (M8(f) == ']') ++f;
            uint32_t dst = suppress ? 0 : va32(v), n = 0;
            while (n < max && M8(p) && (set[M8(p)] ^ neg)) { if (dst) M8(dst + n) = M8(p); ++n; ++p; }
            if (!n) break;
            if (dst) M8(dst + n) = 0;
            any = 1;
            if (!suppress) ++assigned;
        } else break;
    }
    return assigned;
}

// ---------------- qsort / bsearch with a guest comparator ----------------
static void swap_bytes(uint32_t a, uint32_t b, uint32_t w) {
    if (a == b) return;
    uint8_t tmp[256];
    while (w) {
        uint32_t k = w < sizeof tmp ? w : (uint32_t)sizeof tmp;
        memcpy(tmp, G + a, k); memcpy(G + a, G + b, k); memcpy(G + b, tmp, k);
        a += k; b += k; w -= k;
    }
}
static int32_t cmp_guest(Cpu *c, uint32_t fn, uint32_t a, uint32_t b) { uint32_t args[2] = {a, b}; return (int32_t)call_guest(c, fn, 2, args); }
static void qsort_guest(Cpu *c, uint32_t base, uint32_t n, uint32_t w, uint32_t fn) {
    while (n > 1) {
        if (n < 8) {   // insertion sort
            for (uint32_t i = 1; i < n; ++i)
                for (uint32_t j = i; j > 0 && cmp_guest(c, fn, base + (j - 1) * w, base + j * w) > 0; --j)
                    swap_bytes(base + (j - 1) * w, base + j * w, w);
            return;
        }
        uint32_t lo = base, mid = base + (n / 2) * w, hi = base + (n - 1) * w;   // median of three into lo
        if (cmp_guest(c, fn, mid, lo) < 0) swap_bytes(mid, lo, w);
        if (cmp_guest(c, fn, hi, lo) < 0) swap_bytes(hi, lo, w);
        if (cmp_guest(c, fn, hi, mid) < 0) swap_bytes(hi, mid, w);
        swap_bytes(lo, mid, w);                                                   // pivot at lo
        uint32_t i = 1, j = n - 1;
        for (;;) {
            while (i <= j && cmp_guest(c, fn, base + i * w, lo) < 0) ++i;
            while (j >= i && cmp_guest(c, fn, base + j * w, lo) > 0) --j;
            if (i >= j) break;
            swap_bytes(base + i * w, base + j * w, w);
            ++i; --j;
        }
        swap_bytes(lo, base + j * w, w);
        uint32_t nl = j, nr = n - j - 1;                                          // recurse on the smaller side
        if (nl < nr) { qsort_guest(c, base, nl, w, fn); base += (j + 1) * w; n = nr; }
        else { qsort_guest(c, base + (j + 1) * w, nr, w, fn); n = nl; }
    }
}

// ---------------- x87 control word <-> the CRT's abstract format (float.h) ----------------
static uint32_t cw_to_abstract(uint16_t cw) {
    uint32_t a = 0;
    if (cw & 0x01) a |= 0x10;      // _EM_INVALID
    if (cw & 0x02) a |= 0x80000;   // _EM_DENORMAL
    if (cw & 0x04) a |= 0x08;      // _EM_ZERODIVIDE
    if (cw & 0x08) a |= 0x04;      // _EM_OVERFLOW
    if (cw & 0x10) a |= 0x02;      // _EM_UNDERFLOW
    if (cw & 0x20) a |= 0x01;      // _EM_INEXACT
    static const uint32_t rc[4] = {0, 0x100, 0x200, 0x300};   // near, down, up, chop
    a |= rc[(cw >> 10) & 3];
    static const uint32_t pc[4] = {0x20000, 0x20000, 0x10000, 0};   // 24, (reserved), 53, 64
    a |= pc[(cw >> 8) & 3];
    if (cw & 0x1000) a |= 0x40000; // _IC_AFFINE
    return a;
}
static uint16_t abstract_to_cw(uint32_t a, uint16_t cw) {
    cw &= (uint16_t)~0x1F3F;
    if (a & 0x10) cw |= 0x01;
    if (a & 0x80000) cw |= 0x02;
    if (a & 0x08) cw |= 0x04;
    if (a & 0x04) cw |= 0x08;
    if (a & 0x02) cw |= 0x10;
    if (a & 0x01) cw |= 0x20;
    cw |= (uint16_t)(((a >> 8) & 3) << 10);
    uint32_t pc = a & 0x30000;
    cw |= (uint16_t)((pc == 0x20000 ? 0 : pc == 0x10000 ? 2 : 3) << 8);
    if (a & 0x40000) cw |= 0x1000;
    return cw;
}
static uint32_t control87(Cpu *c, uint32_t value, uint32_t mask) {
    uint32_t cur = cw_to_abstract(c->cw);
    uint32_t next = (cur & ~mask) | (value & mask);
    c->cw = abstract_to_cw(next, c->cw);
    return cw_to_abstract(c->cw);
}

// ---------------- per-thread and process state ----------------
static __thread uint32_t rand_seed = 1, rand_seeded;
static __thread uint32_t strtok_next;
static uint32_t fmode_var, commode_var, envp_var, onexit_tab[256];
static unsigned onexit_n;
static int locale_mode = 2;                    // _DISABLE_PER_THREAD_LOCALE
static uint32_t crt_locks[64];                 // guest CRITICAL_SECTIONs for _lock(n)
static uint64_t clock_t0;

static uint32_t crt_envp(void) { if (!envp_var) envp_var = galloc(4); return envp_var; }   // an empty environment

// Data imports: the IAT slot holds the variable's address (boot.c's IAT fill asks here first). 0 = a function import.
uint32_t crt_data_import(const char *name) {
    if (strncmp(name, "MSVCR80", 7) || !strchr(name, '!')) return 0;
    const char *fn = strchr(name, '!') + 1;
    if (!strcmp(fn, "_adjust_fdiv")) { static uint32_t v; if (!v) v = galloc(4); return v; }   // 0: no Pentium FDIV workaround
    if (!strcmp(fn, "__initenv")) { static uint32_t v; if (!v) { v = galloc(4); M32(v) = crt_envp(); } return v; }
    return 0;
}

static void run_onexit(Cpu *c) {
    while (onexit_n) {
        uint32_t fn = onexit_tab[--onexit_n];
        if (fn) call_guest(c, fn, 0, NULL);
    }
}

static int crt_mem_str(Cpu *c, const char *fn) {
    // ---- memory ----
    if (!strcmp(fn, "malloc")) CRET(crt_heap_alloc(arg(c, 0) ? arg(c, 0) : 1));
    if (!strcmp(fn, "calloc")) {
        uint64_t n = (uint64_t)arg(c, 0) * arg(c, 1);
        CRET(n > 0xFFFFFFE0ull ? 0 : crt_heap_alloc(n ? (uint32_t)n : 1));
    }
    if (!strcmp(fn, "free")) { if (arg(c, 0)) crt_heap_free(arg(c, 0)); CRETV(); }
    if (!strcmp(fn, "realloc")) {
        uint32_t p = arg(c, 0), n = arg(c, 1);
        if (!p) CRET(crt_heap_alloc(n ? n : 1));
        if (!n) { crt_heap_free(p); CRET(0); }
        CRET(crt_heap_realloc(p, n));
    }
    if (!strcmp(fn, "_aligned_malloc")) {
        uint32_t n = arg(c, 0), al = arg(c, 1);
        if (!al || (al & (al - 1))) crt_fatal(fn, "alignment is not a power of 2");
        if (al < 4) al = 4;
        uint32_t raw = crt_heap_alloc(n + al + 4);
        if (!raw) CRET(0);
        uint32_t p = (raw + 4 + al - 1) & ~(al - 1);
        M32(p - 4) = raw;
        CRET(p);
    }
    if (!strcmp(fn, "_aligned_free")) { if (arg(c, 0)) crt_heap_free(M32(arg(c, 0) - 4)); CRETV(); }
    // ---- memory blocks ----
    if (!strcmp(fn, "memset")) { memset(G + arg(c, 0), (int)arg(c, 1), arg(c, 2)); CRET(arg(c, 0)); }
    if (!strcmp(fn, "memcpy") || !strcmp(fn, "memmove")) { memmove(G + arg(c, 0), G + arg(c, 1), arg(c, 2)); CRET(arg(c, 0)); }
    if (!strcmp(fn, "memmove_s")) {                 // (dst, dstsize, src, count) -> errno_t
        uint32_t d = arg(c, 0), ds = arg(c, 1), s = arg(c, 2), n = arg(c, 3);
        if (!n) CRET(0);
        if (!d || !s || n > ds) crt_fatal(fn, "invalid parameter (null pointer or count > destination size)");
        memmove(G + d, G + s, n);
        CRET(0);
    }
    if (!strcmp(fn, "memcmp")) { int r = memcmp(G + arg(c, 0), G + arg(c, 1), arg(c, 2)); CRET(r < 0 ? -1 : r > 0); }
    // ---- strings ----
    if (!strcmp(fn, "strlen")) CRET(strlen(gs(arg(c, 0))));
    if (!strcmp(fn, "strcpy")) { memmove(gs(arg(c, 0)), gs(arg(c, 1)), strlen(gs(arg(c, 1))) + 1); CRET(arg(c, 0)); }
    if (!strcmp(fn, "strcat")) { char *d = gs(arg(c, 0)); memmove(d + strlen(d), gs(arg(c, 1)), strlen(gs(arg(c, 1))) + 1); CRET(arg(c, 0)); }
    if (!strcmp(fn, "strncpy")) {
        uint32_t d = arg(c, 0), s = arg(c, 1), n = arg(c, 2), k = 0;
        for (; k < n && M8(s + k); ++k) M8(d + k) = M8(s + k);
        for (; k < n; ++k) M8(d + k) = 0;
        CRET(d);
    }
    if (!strcmp(fn, "strncat")) {
        uint32_t d = arg(c, 0), s = arg(c, 1), n = arg(c, 2), e = d + (uint32_t)strlen(gs(d)), k = 0;
        for (; k < n && M8(s + k); ++k) M8(e + k) = M8(s + k);
        M8(e + k) = 0;
        CRET(d);
    }
    if (!strcmp(fn, "strcmp") || !strcmp(fn, "strcoll")) { int r = strcmp(gs(arg(c, 0)), gs(arg(c, 1))); CRET(r < 0 ? -1 : r > 0); }
    if (!strcmp(fn, "strncmp")) { int r = strncmp(gs(arg(c, 0)), gs(arg(c, 1)), arg(c, 2)); CRET(r < 0 ? -1 : r > 0); }
    if (!strcmp(fn, "_stricmp") || !strcmp(fn, "_strnicmp")) {
        uint32_t a = arg(c, 0), b = arg(c, 1), n = fn[4] == 'n' ? arg(c, 2) : 0xFFFFFFFFu;
        int r = 0;
        for (uint32_t k = 0; k < n; ++k) {
            int x = c_tolower(M8(a + k)), y = c_tolower(M8(b + k));
            if (x != y || !x) { r = x - y; break; }
        }
        CRET(r);
    }
    if (!strcmp(fn, "strchr")) { char *r = strchr(gs(arg(c, 0)), (char)arg(c, 1)); CRET(r ? (uint32_t)(r - (char *)G) : 0); }
    if (!strcmp(fn, "strrchr")) { char *r = strrchr(gs(arg(c, 0)), (char)arg(c, 1)); CRET(r ? (uint32_t)(r - (char *)G) : 0); }
    if (!strcmp(fn, "strstr")) { char *r = strstr(gs(arg(c, 0)), gs(arg(c, 1))); CRET(r ? (uint32_t)(r - (char *)G) : 0); }
    if (!strcmp(fn, "strpbrk")) { char *r = strpbrk(gs(arg(c, 0)), gs(arg(c, 1))); CRET(r ? (uint32_t)(r - (char *)G) : 0); }
    if (!strcmp(fn, "strcspn")) CRET(strcspn(gs(arg(c, 0)), gs(arg(c, 1))));
    if (!strcmp(fn, "strtok")) {                     // per-thread position, as in the multithreaded CRT
        uint32_t s = arg(c, 0) ? arg(c, 0) : strtok_next;
        const char *delim = gs(arg(c, 1));
        if (!s) CRET(0);
        while (M8(s) && strchr(delim, M8(s))) ++s;
        if (!M8(s)) { strtok_next = 0; CRET(0); }
        uint32_t tok = s;
        while (M8(s) && !strchr(delim, M8(s))) ++s;
        if (M8(s)) { M8(s) = 0; strtok_next = s + 1; } else strtok_next = 0;
        CRET(tok);
    }
    // ---- ctype ----
    if (!strcmp(fn, "tolower")) CRET(c_tolower((int32_t)arg(c, 0)));
    if (!strcmp(fn, "toupper")) CRET(c_toupper((int32_t)arg(c, 0)));
    if (!strcmp(fn, "isspace")) CRET(c_isspace((int32_t)arg(c, 0)) ? 8 : 0);    // _SPACE
    if (!strcmp(fn, "isdigit")) CRET(c_isdigit((int32_t)arg(c, 0)) ? 4 : 0);    // _DIGIT
    if (!strcmp(fn, "isprint")) CRET(c_isprint((int32_t)arg(c, 0)) ? 0x157 : 0);
    // ---- conversion ----
    if (!strcmp(fn, "atoi")) CRET(c_strtox(arg(c, 0), NULL, 10, 1));
    if (!strcmp(fn, "strtol") || !strcmp(fn, "strtoul")) {
        uint32_t end, r = c_strtox(arg(c, 0), &end, (int)arg(c, 2), !strcmp(fn, "strtol"));
        if (arg(c, 1)) M32(arg(c, 1)) = end;
        CRET(r);
    }
    if (!strcmp(fn, "atof")) CRETF(c_atof(arg(c, 0), NULL));
    if (!strcmp(fn, "_ltoa")) {                       // (value, buf, radix): negative only in radix 10
        int32_t v = (int32_t)arg(c, 0);
        uint32_t buf = arg(c, 1), radix = arg(c, 2), u = (uint32_t)v, k = 0;
        char tmp[40];
        int neg = radix == 10 && v < 0;
        if (neg) u = (uint32_t)-(int64_t)v;
        if (radix < 2 || radix > 36) radix = 10;
        do { uint32_t d = u % radix; tmp[k++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); u /= radix; } while (u);
        uint32_t o = 0;
        if (neg) M8(buf + o++) = '-';
        while (k) M8(buf + o++) = (uint8_t)tmp[--k];
        M8(buf + o) = 0;
        CRET(buf);
    }
    if (!strcmp(fn, "abs")) { int32_t v = (int32_t)arg(c, 0); CRET(v < 0 ? (uint32_t)-(int64_t)v : (uint32_t)v); }
    return 0;
}

static int crt_math(Cpu *c, const char *fn) {
    // _CI* intrinsics: arguments on the x87 stack (exact names, so recomp/import_coverage.py counts them)
    if (!strcmp(fn, "_CIpow") || !strcmp(fn, "_CIfmod") || !strcmp(fn, "_CIatan2")) {
        double x = ST(1), y = ST(0);
        double r = fn[3] == 'p' ? pow(x, y) : fn[3] == 'f' ? fmod(x, y) : atan2(x, y);
        x87_pop(c);
        ST(0) = x87_round(c, x87_nan(r, x, y));
        CRETV();
    }
    double (*f1)(double) = !strcmp(fn, "_CIsqrt") ? sqrt : !strcmp(fn, "_CIsin") ? sin : !strcmp(fn, "_CIcos") ? cos
                         : !strcmp(fn, "_CItan") ? tan : !strcmp(fn, "_CIasin") ? asin : !strcmp(fn, "_CIacos") ? acos
                         : !strcmp(fn, "_CIatan") ? atan : !strcmp(fn, "_CIexp") ? exp : !strcmp(fn, "_CIlog") ? log
                         : !strcmp(fn, "_CIlog10") ? log10 : !strcmp(fn, "_CIsinh") ? sinh : !strcmp(fn, "_CIcosh") ? cosh
                         : !strcmp(fn, "_CItanh") ? tanh : NULL;
    if (f1) {
        double y = ST(0);
        ST(0) = x87_round(c, x87_nan(f1(y), y, y));
        CRETV();
    }
    if (!strcmp(fn, "ceil")) CRETF(ceil(argd(c, 0)));
    if (!strcmp(fn, "floor")) CRETF(floor(argd(c, 0)));
    if (!strcmp(fn, "cos")) CRETF(x87_nan(cos(argd(c, 0)), argd(c, 0), argd(c, 0)));
    if (!strcmp(fn, "sqrt")) CRETF(x87_nan(sqrt(argd(c, 0)), argd(c, 0), argd(c, 0)));
    if (!strcmp(fn, "ldexp")) CRETF(ldexp(argd(c, 0), (int32_t)arg(c, 2)));
    if (!strcmp(fn, "_isnan")) CRET(isnan(argd(c, 0)) ? 1 : 0);
    if (!strcmp(fn, "_control87")) CRET(control87(c, arg(c, 0), arg(c, 1)));
    if (!strcmp(fn, "_controlfp_s")) {               // (unsigned *current, new, mask) -> errno_t; denormal control excluded
        uint32_t cur = arg(c, 0), mask = arg(c, 2) & ~0x80000u;
        uint32_t r = mask ? control87(c, arg(c, 1), mask) : cw_to_abstract(c->cw);
        if (cur) M32(cur) = r;
        CRET(0);
    }
    if (!strcmp(fn, "rand")) {
        rand_seed = rand_seed * 214013u + 2531011u;
        CRET((rand_seed >> 16) & 0x7FFF);
    }
    if (!strcmp(fn, "srand")) { rand_seed = arg(c, 0); rand_seeded = 1; CRETV(); }
    return 0;
}

static int crt_misc(Cpu *c, const char *fn) {
    // ---- printf / scanf ----
    if (!strcmp(fn, "sprintf")) { uint32_t n = format_to(arg(c, 0), 0xFFFFFFFFu, arg(c, 1), c->esp + 12); M8(arg(c, 0) + n) = 0; CRET(n); }
    if (!strcmp(fn, "vsprintf")) { uint32_t n = format_to(arg(c, 0), 0xFFFFFFFFu, arg(c, 1), arg(c, 2)); M8(arg(c, 0) + n) = 0; CRET(n); }
    if (!strcmp(fn, "_snprintf") || !strcmp(fn, "_vsnprintf")) {   // (dst, count, fmt, ... | va)
        uint32_t d = arg(c, 0), cap = arg(c, 1);
        uint32_t n = format_to(d, cap, arg(c, 2), fn[1] == 'v' ? arg(c, 3) : c->esp + 16);
        if (n < cap) M8(d + n) = 0;
        CRET(n <= cap ? n : 0xFFFFFFFFu);
    }
    if (!strcmp(fn, "printf")) {
        Out o = {0};
        VA v = {c->esp + 8};
        format(&o, arg(c, 0), 0, &v);
        out_flush(&o);
        CRET(o.n);
    }
    if (!strcmp(fn, "sscanf")) { VA v = {c->esp + 12}; CRET((uint32_t)scan(arg(c, 0), arg(c, 1), &v)); }
    // ---- searching and sorting ----
    if (!strcmp(fn, "qsort")) { qsort_guest(c, arg(c, 0), arg(c, 1), arg(c, 2), arg(c, 3)); CRETV(); }
    if (!strcmp(fn, "bsearch")) {                    // (key, base, num, width, cmp)
        uint32_t key = arg(c, 0), base = arg(c, 1), lo = 0, hi = arg(c, 2), w = arg(c, 3), cmp = arg(c, 4);
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            int32_t r = cmp_guest(c, cmp, key, base + mid * w);
            if (!r) CRET(base + mid * w);
            if (r < 0) hi = mid; else lo = mid + 1;
        }
        CRET(0);
    }
    // ---- time ----
    if (!strcmp(fn, "clock")) { if (!clock_t0) clock_t0 = host_ticks(); CRET((host_ticks() - clock_t0) / 1000000u); }
    if (!strcmp(fn, "_time64")) {
        uint64_t t = (host_filetime() - 116444736000000000ull) / 10000000u;
        if (arg(c, 0)) M64(arg(c, 0)) = t;
        CRET64(t);
    }
    if (!strcmp(fn, "_ftime64")) {                   // struct __timeb64 { __time64_t time; u16 millitm; i16 timezone; i16 dstflag; }
        uint64_t ft = host_filetime() - 116444736000000000ull;
        uint32_t p = arg(c, 0);
        M64(p) = ft / 10000000u;
        M16(p + 8) = (uint16_t)(ft / 10000u % 1000u);
        time_t now = (time_t)(ft / 10000000u);
        struct tm lt;
        localtime_r(&now, &lt);
        M16(p + 10) = (uint16_t)(int16_t)(-lt.tm_gmtoff / 60);   // minutes west of UTC, the Mac's time zone
        M16(p + 12) = (uint16_t)(lt.tm_isdst > 0);
        CRETV();
    }
    if (!strcmp(fn, "getenv")) CRET(0);              // the guest's environment is empty
    // ---- start-up and exit ----
    if (!strcmp(fn, "__set_app_type") || !strcmp(fn, "__setusermatherr") || !strcmp(fn, "_crt_debugger_hook")) CRETV();
    if (!strcmp(fn, "__p__fmode")) { if (!fmode_var) fmode_var = galloc(4); CRET(fmode_var); }
    if (!strcmp(fn, "__p__commode")) { if (!commode_var) commode_var = galloc(4); CRET(commode_var); }
    if (!strcmp(fn, "_encode_pointer") || !strcmp(fn, "_decode_pointer")) CRET(arg(c, 0));
    if (!strcmp(fn, "_configthreadlocale")) {
        int prev = locale_mode, req = (int)arg(c, 0);
        if (req == 1 || req == 2) locale_mode = req;
        CRET(prev);
    }
    if (!strcmp(fn, "__getmainargs")) {              // (int *argc, char ***argv, char ***envp, int wildcard, _startupinfo *)
        static uint32_t argv;
        if (!argv) {
            argv = galloc(8);
            M32(argv) = gstr("nfs.exe");
        }
        M32(arg(c, 0)) = 1;
        M32(arg(c, 1)) = argv;
        M32(arg(c, 2)) = crt_envp();
        CRET(0);
    }
    if (!strcmp(fn, "_initterm") || !strcmp(fn, "_initterm_e")) {   // [begin, end) of function pointers
        // call_guest pushes below esp and restores it, so our return address at [esp] stays intact
        int with_result = fn[9] == '_';
        uint32_t end = arg(c, 1);
        for (uint32_t p = arg(c, 0); p < end; p += 4) {
            uint32_t f = M32(p);
            if (!f) continue;
            uint32_t r = call_guest(c, f, 0, NULL);
            if (with_result && r) CRET(r);
        }
        CRET(0);
    }
    if (!strcmp(fn, "_onexit") || !strcmp(fn, "__dllonexit")) {
        if (onexit_n == sizeof onexit_tab / sizeof *onexit_tab) CRET(0);
        onexit_tab[onexit_n++] = arg(c, 0);
        CRET(arg(c, 0));
    }
    if (!strcmp(fn, "_cexit")) { run_onexit(c); CRETV(); }
    if (!strcmp(fn, "exit")) { run_onexit(c); crt_exit_process(c, arg(c, 0)); CRETV(); }
    if (!strcmp(fn, "_exit")) { crt_exit_process(c, arg(c, 0)); CRETV(); }
    if (!strcmp(fn, "_lock") || !strcmp(fn, "_unlock")) {
        uint32_t n = arg(c, 0);
        if (n >= sizeof crt_locks / sizeof *crt_locks) crt_fatal(fn, "lock number out of range");
        if (!crt_locks[n]) crt_locks[n] = galloc(24);
        if (fn[1] == 'l') crt_cs_enter(c, crt_locks[n]); else crt_cs_leave(crt_locks[n]);
        CRETV();
    }
    if (!strcmp(fn, "_XcptFilter")) CRET(0);         // EXCEPTION_CONTINUE_SEARCH: no CRT signal handlers installed
    if (!strcmp(fn, "_invalid_parameter_noinfo")) crt_fatal(fn, "invalid parameter");
    if (!strcmp(fn, "_invoke_watson")) crt_fatal(fn, "invalid parameter (Watson)");
    if (!strcmp(fn, "_amsg_exit")) { char why[32]; snprintf(why, sizeof why, "runtime error R60%02u", arg(c, 0)); crt_fatal(fn, why); }
    if (!strcmp(fn, "_purecall")) crt_fatal(fn, "pure virtual function call");
    return 0;
}


// ---------------- low-level I/O: CRT file descriptors over Win32 handles ----------------
// fd 0-2 are the standard streams: writes go to the log, reads see end of file. Text mode (the default unless
// _O_BINARY or _fmode says binary) turns CRLF into LF and stops at Ctrl-Z on reads, and LF into CRLF on writes.
#define O_WRONLY_ 0x1
#define O_RDWR_ 0x2
#define O_APPEND_ 0x8
#define O_CREAT_ 0x100
#define O_TRUNC_ 0x200
#define O_EXCL_ 0x400
#define O_TEXT_ 0x4000
#define O_BINARY_ 0x8000
#define CRT_NFD 64
static struct { uint32_t h; uint8_t open, text, append, eof; } fdtab[CRT_NFD] = {{0, 1, 1, 0, 1}, {0, 1, 1, 0, 0}, {0, 1, 1, 0, 0}};

static int crt_open(const char *path, uint32_t oflag) {
    int fd = 3;
    while (fd < CRT_NFD && fdtab[fd].open) ++fd;
    if (fd == CRT_NFD) return -1;                                       // EMFILE
    uint32_t mode = oflag & 3, access = mode == 0 ? 0x80000000u : mode == O_WRONLY_ ? 0x40000000u : 0xC0000000u;
    uint32_t cr = oflag & (O_CREAT_ | O_TRUNC_ | O_EXCL_), disp;
    if ((cr & O_CREAT_) && (cr & O_EXCL_)) disp = 1;                    // CREATE_NEW
    else if ((cr & O_CREAT_) && (cr & O_TRUNC_)) disp = 2;              // CREATE_ALWAYS
    else if (cr & O_CREAT_) disp = 4;                                   // OPEN_ALWAYS
    else if (cr & O_TRUNC_) disp = 5;                                   // TRUNCATE_EXISTING
    else disp = 3;                                                      // OPEN_EXISTING
    uint32_t h = host_file_open(path, access, 3, disp);
    if (h == 0xFFFFFFFFu) return -1;
    int text = (oflag & O_BINARY_) ? 0 : (oflag & O_TEXT_) ? 1 : !(fmode_var && (M32(fmode_var) & O_BINARY_));
    fdtab[fd].h = h; fdtab[fd].open = 1; fdtab[fd].text = (uint8_t)text; fdtab[fd].append = !!(oflag & O_APPEND_); fdtab[fd].eof = 0;
    return fd;
}
static int fd_ok(int32_t fd) { return fd >= 0 && fd < CRT_NFD && fdtab[fd].open; }
static int32_t crt_read(int32_t fd, uint32_t buf, uint32_t n) {
    if (!fd_ok(fd)) return -1;
    if (fd < 3 || fdtab[fd].eof || !n) return 0;
    int64_t r = host_file_read(fdtab[fd].h, buf, n);
    if (r < 0) return -1;
    if (!fdtab[fd].text) return (int32_t)r;
    uint32_t in = 0, out = 0;
    for (; in < (uint32_t)r; ++in) {
        uint8_t ch = M8(buf + in);
        if (ch == 0x1A) { fdtab[fd].eof = 1; host_file_seek(fdtab[fd].h, (int64_t)in - r, 1); break; }   // Ctrl-Z ends a text file
        if (ch == '\r') {
            if (in + 1 < (uint32_t)r) { if (M8(buf + in + 1) == '\n') continue; }
            else {                                                       // CR at the end of the chunk: peek one byte
                uint32_t peek = crt_heap_alloc(1);
                int64_t k = host_file_read(fdtab[fd].h, peek, 1);
                if (k == 1 && M8(peek) == '\n') ch = '\n';
                else if (k == 1) host_file_seek(fdtab[fd].h, -1, 1);
                crt_heap_free(peek);
            }
        }
        M8(buf + out++) = ch;
    }
    return (int32_t)out;
}
static void log_bytes(int32_t fd, uint32_t buf, uint32_t n) {
    Out o = {0};
    for (uint32_t k = 0; k < n; ++k) out_c(&o, (char)M8(buf + k));
    out_flush(&o);
    (void)fd;
}
static int32_t crt_write(int32_t fd, uint32_t buf, uint32_t n) {
    if (!fd_ok(fd)) return -1;
    if (fd < 3) { log_bytes(fd, buf, n); return (int32_t)n; }
    if (!n) return 0;
    if (fdtab[fd].append) host_file_seek(fdtab[fd].h, 0, 2);
    if (!fdtab[fd].text) { int64_t r = host_file_write(fdtab[fd].h, buf, n); return r < 0 ? -1 : (int32_t)r; }
    uint32_t lf = 0;
    for (uint32_t k = 0; k < n; ++k) lf += M8(buf + k) == '\n';
    uint32_t tmp = crt_heap_alloc(n + lf), o = 0;
    if (!tmp) return -1;
    for (uint32_t k = 0; k < n; ++k) { if (M8(buf + k) == '\n') M8(tmp + o++) = '\r'; M8(tmp + o++) = M8(buf + k); }
    int64_t r = host_file_write(fdtab[fd].h, tmp, o);
    crt_heap_free(tmp);
    return r < 0 || (uint32_t)r != o ? -1 : (int32_t)n;
}
static int32_t crt_lseek(int32_t fd, int32_t off, int32_t origin) {
    if (!fd_ok(fd) || fd < 3 || origin < 0 || origin > 2) return -1;
    int64_t r = host_file_seek(fdtab[fd].h, off, origin);
    if (r < 0 || r > 0x7FFFFFFF) return -1;
    fdtab[fd].eof = 0;
    return (int32_t)r;
}
static int32_t crt_close(int32_t fd) {
    if (!fd_ok(fd)) return -1;
    if (fd < 3) return 0;
    int ok = host_file_close(fdtab[fd].h);
    memset(&fdtab[fd], 0, sizeof fdtab[fd]);
    return ok ? 0 : -1;
}

// ---------------- stdio: unbuffered FILE streams ----------------
// struct _iobuf (32 bytes): +0 _ptr, +4 _cnt, +8 _base, +12 _flag, +16 _file, +20 _charbuf, +24 _bufsiz, +28 _tmpfname.
// Nothing is buffered, so _ptr/_cnt stay 0; the game imports no getc/putc that would read them directly.
#define IOREAD 0x1
#define IOWRT 0x2
#define IOEOF 0x10
#define IOERR 0x20
#define IORW 0x80
#define CRT_NFILE 20
static uint32_t iob;
static uint32_t iob_init(void) {
    if (!iob) {
        iob = galloc(32 * CRT_NFILE);
        for (int k = 0; k < 3; ++k) { M32(iob + 32 * k + 12) = k ? IOWRT : IOREAD; M32(iob + 32 * k + 16) = (uint32_t)k; }
    }
    return iob;
}
static int file_ok(uint32_t f) { iob_init(); return f >= iob && f < iob + 32 * CRT_NFILE && (f - iob) % 32 == 0 && M32(f + 12); }
static uint32_t crt_fopen(const char *path, const char *mode) {
    iob_init();
    uint32_t f = 0;
    for (int k = 3; k < CRT_NFILE && !f; ++k) if (!M32(iob + 32 * k + 12)) f = iob + 32 * (uint32_t)k;
    if (!f) return 0;
    uint32_t oflag, flag;
    if (mode[0] == 'r') { oflag = 0; flag = IOREAD; }
    else if (mode[0] == 'w') { oflag = O_WRONLY_ | O_CREAT_ | O_TRUNC_; flag = IOWRT; }
    else if (mode[0] == 'a') { oflag = O_WRONLY_ | O_CREAT_ | O_APPEND_; flag = IOWRT; }
    else return 0;
    for (const char *m = mode + 1; *m; ++m) {
        if (*m == '+') { oflag = (oflag & ~3u) | O_RDWR_; flag = IORW; }
        else if (*m == 'b') oflag |= O_BINARY_;
        else if (*m == 't') oflag |= O_TEXT_;
    }
    int fd = crt_open(path, oflag);
    if (fd < 0) return 0;
    memset(G + f, 0, 32);
    M32(f + 12) = flag;
    M32(f + 16) = (uint32_t)fd;
    return f;
}

// ---- setjmp / longjmp (Lua's protected calls; MW's CRT was translated code, ProStreet imports them) ----
// _setjmp3(buf, n, ...) keeps MSVC's layout: ebp, ebx, edi, esi, esp (at the return address), the return address,
// the SEH registration (fs:[0]), the try level and the 'VC20' cookie. longjmp(buf, v) restores them and hands the
// guest's continuation to the host: only a known protected frame can be resumed (boot.c host_lua_resume unwinds the
// native frames of the abandoned calls and runs the translated continuation); any other target stops by name.
void host_lua_resume(Cpu *c, uint32_t target);
static int crt_setjmp(Cpu *c, const char *fn) {
    if (!strcmp(fn, "_setjmp3")) {
        uint32_t b = arg(c, 0);
        M32(b) = c->ebp; M32(b + 4) = c->ebx; M32(b + 8) = c->edi; M32(b + 12) = c->esi;
        M32(b + 16) = c->esp; M32(b + 20) = M32(c->esp); M32(b + 24) = M32(c->fs_base);
        M32(b + 28) = 0xFFFFFFFFu; M32(b + 32) = 0x56433230u;            // try level -1, 'VC20'
        CRET(0);
    }
    if (!strcmp(fn, "longjmp")) {
        uint32_t b = arg(c, 0), v = arg(c, 1), target = M32(b + 20);
        c->ebp = M32(b); c->ebx = M32(b + 4); c->edi = M32(b + 8); c->esi = M32(b + 12);
        c->esp = M32(b + 16) + 4;                                            // as if _setjmp3 had just returned
        M32(c->fs_base) = M32(b + 24);
        c->eax = v ? v : 1;
        c->edx = b;
        host_lua_resume(c, target);                                         // doesn't return for a known frame
        fprintf(stderr, "boot: longjmp to %08X, which isn't a known protected frame\n", target);
        return 0;                                                           // host_import stops with the name
    }
    return 0;
}

static int crt_files(Cpu *c, const char *fn) {
    // ---- low-level I/O ----
    if (!strcmp(fn, "_open") || !strcmp(fn, "?_open@@YAHPBDHH@Z")) CRET((uint32_t)crt_open(gs(arg(c, 0)), arg(c, 1)));
    if (!strcmp(fn, "_read")) CRET((uint32_t)crt_read((int32_t)arg(c, 0), arg(c, 1), arg(c, 2)));
    if (!strcmp(fn, "_write")) CRET((uint32_t)crt_write((int32_t)arg(c, 0), arg(c, 1), arg(c, 2)));
    if (!strcmp(fn, "_lseek")) CRET((uint32_t)crt_lseek((int32_t)arg(c, 0), (int32_t)arg(c, 1), (int32_t)arg(c, 2)));
    if (!strcmp(fn, "_close")) CRET((uint32_t)crt_close((int32_t)arg(c, 0)));
    if (!strcmp(fn, "_filelength")) {
        int32_t fd = (int32_t)arg(c, 0);
        int64_t n = fd_ok(fd) && fd >= 3 ? host_file_size(fdtab[fd].h) : -1;
        CRET(n < 0 || n > 0x7FFFFFFF ? 0xFFFFFFFFu : (uint32_t)n);
    }
    // ---- stdio ----
    if (!strcmp(fn, "__iob_func")) CRET(iob_init());
    if (!strcmp(fn, "fopen")) CRET(crt_fopen(gs(arg(c, 0)), gs(arg(c, 1))));
    if (!strcmp(fn, "fclose")) {
        uint32_t f = arg(c, 0);
        if (!file_ok(f)) CRET(0xFFFFFFFFu);
        int32_t r = (f - iob) / 32 < 3 ? 0 : crt_close((int32_t)M32(f + 16));
        if ((f - iob) / 32 >= 3) memset(G + f, 0, 32);
        CRET(r ? 0xFFFFFFFFu : 0);
    }
    if (!strcmp(fn, "fwrite")) {                     // (buf, size, count, stream) -> items written
        uint32_t buf = arg(c, 0), size = arg(c, 1), count = arg(c, 2), f = arg(c, 3);
        uint64_t total = (uint64_t)size * count;
        if (!total) CRET(0);
        if (!file_ok(f) || total > 0x7FFFFFFF) CRET(0);
        int32_t r = crt_write((int32_t)M32(f + 16), buf, (uint32_t)total);
        if (r < 0) { M32(f + 12) |= IOERR; CRET(0); }
        CRET((uint32_t)r / size);
    }
    if (!strcmp(fn, "fseek")) {                      // (stream, offset, origin) -> 0 / -1
        uint32_t f = arg(c, 0);
        if (!file_ok(f)) CRET(0xFFFFFFFFu);
        M32(f + 12) &= ~(uint32_t)IOEOF;
        CRET(crt_lseek((int32_t)M32(f + 16), (int32_t)arg(c, 1), (int32_t)arg(c, 2)) < 0 ? 0xFFFFFFFFu : 0);
    }
    if (!strcmp(fn, "fflush")) CRET(!arg(c, 0) || file_ok(arg(c, 0)) ? 0 : 0xFFFFFFFFu);   // nothing is buffered
    if (!strcmp(fn, "fprintf")) {                    // (stream, fmt, ...)
        uint32_t f = arg(c, 0);
        if (!file_ok(f)) CRET(0xFFFFFFFFu);
        int32_t fd = (int32_t)M32(f + 16);
        if (fd < 3) {
            Out o = {0};
            VA v = {c->esp + 12};
            format(&o, arg(c, 1), 0, &v);
            out_flush(&o);
            CRET(o.n);
        }
        uint32_t n = format_to(0x10, 0, arg(c, 1), c->esp + 12);      // length only: cap 0 writes nothing (dst just non-zero)
        uint32_t tmp = crt_heap_alloc(n + 1);
        if (!tmp) CRET(0xFFFFFFFFu);
        format_to(tmp, n, arg(c, 1), c->esp + 12);
        int32_t r = crt_write(fd, tmp, n);
        crt_heap_free(tmp);
        if (r < 0) { M32(f + 12) |= IOERR; CRET(0xFFFFFFFFu); }
        CRET(n);
    }
    if (!strcmp(fn, "_vsnwprintf")) {                // (wchar_t *dst, count, fmt, va): count in wchar_t units
        uint32_t d = arg(c, 0), cap = arg(c, 1);
        uint32_t n = wformat_to(d, cap, arg(c, 2), arg(c, 3));
        if (n < cap) M16(d + 2 * n) = 0;
        CRET(n <= cap ? n : 0xFFFFFFFFu);
    }
    // ---- files and directories ----
    if (!strcmp(fn, "_findfirst64i32") || !strcmp(fn, "_findnext64i32")) {
        static uint32_t wfd;                         // WIN32_FIND_DATAA scratch
        if (!wfd) wfd = galloc(320);
        int first = fn[5] == 'f';
        uint32_t info = arg(c, 1), h = first ? host_find_first(gs(arg(c, 0)), wfd) : arg(c, 0);
        if (first ? h == 0xFFFFFFFFu : !host_find_next(h, wfd)) CRET(0xFFFFFFFFu);
        // struct _finddata64i32_t: attrib +0, time_create +8, time_access +16, time_write +24, size +32, name[260] +36
        memset(G + info, 0, 296);
        M32(info) = M32(wfd);
        for (int k = 0; k < 3; ++k) {
            uint64_t ft = M64(wfd + 4 + 8 * (uint32_t)k);
            M64(info + 8 + 8 * (uint32_t)k) = ft ? (uint64_t)(ft / 10000000u - 11644473600ull) : 0;
        }
        M32(info + 32) = M32(wfd + 32);
        memcpy(G + info + 36, G + wfd + 44, 260);
        CRET(first ? h : 0);
    }
    if (!strcmp(fn, "_findclose")) { host_find_close(arg(c, 0)); CRET(0); }
    if (!strcmp(fn, "_mkdir")) CRET(host_mkdir(gs(arg(c, 0))) ? 0 : 0xFFFFFFFFu);
    if (!strcmp(fn, "_rmdir")) CRET(host_file_remove(gs(arg(c, 0)), 1) ? 0 : 0xFFFFFFFFu);
    if (!strcmp(fn, "remove")) CRET(host_file_remove(gs(arg(c, 0)), 0) ? 0 : 0xFFFFFFFFu);
    if (!strcmp(fn, "rename")) CRET(host_file_rename(gs(arg(c, 0)), gs(arg(c, 1))) ? 0 : 0xFFFFFFFFu);
    if (!strcmp(fn, "_chmod")) CRET(host_file_exists(gs(arg(c, 0))) ? 0 : 0xFFFFFFFFu);   // permissions are not modelled
    if (!strcmp(fn, "_getcwd") || !strcmp(fn, "_fullpath")) {
        // The guest's current directory is the fake module folder boot.c reports (GetCurrentDirectoryA: C:\NFSMW).
        static const char cwd[] = "C:\\NFSMW";
        char path[1024];
        uint32_t buf = arg(c, 0), max;
        if (fn[1] == 'g') { snprintf(path, sizeof path, "%s", cwd); max = arg(c, 1); }
        else {                                       // _fullpath(abs, rel, max): absolute, '\', "." and ".." resolved
            const char *rel = arg(c, 1) ? gs(arg(c, 1)) : "";
            char raw[1024];
            if (!*rel) snprintf(raw, sizeof raw, "%s", cwd);
            else if (rel[0] && rel[1] == ':') snprintf(raw, sizeof raw, "%s", rel);
            else if (rel[0] == '\\' || rel[0] == '/') snprintf(raw, sizeof raw, "C:%s", rel);
            else snprintf(raw, sizeof raw, "%s\\%s", cwd, rel);
            for (char *p = raw; *p; ++p) if (*p == '/') *p = '\\';
            size_t n = 0;
            path[n++] = raw[0]; path[n++] = ':';
            char *save = NULL;
            for (char *tok = strtok_r(raw + 2, "\\", &save); tok; tok = strtok_r(NULL, "\\", &save)) {
                if (!strcmp(tok, ".")) continue;
                if (!strcmp(tok, "..")) { while (n > 2 && path[n - 1] != '\\') --n; if (n > 2) --n; continue; }
                if (n + strlen(tok) + 2 >= sizeof path) break;
                path[n++] = '\\';
                memcpy(path + n, tok, strlen(tok));
                n += strlen(tok);
            }
            if (n == 2) path[n++] = '\\';
            path[n] = 0;
            max = arg(c, 2);
        }
        uint32_t len = (uint32_t)strlen(path);
        if (!buf) {                                  // _getcwd: max(maxlen, needed); _fullpath: _MAX_PATH (260) or needed
            uint32_t want = fn[1] == 'g' ? max : 260;
            if (want < len + 1) want = len + 1;
            if (!(buf = crt_heap_alloc(want))) CRET(0);
        }
        else if (len + 1 > max) CRET(0);             // ERANGE
        memcpy(G + buf, path, len + 1);
        CRET(buf);
    }
    if (!strcmp(fn, "_getdrive")) CRET(3);           // C:
    if (!strcmp(fn, "_getdiskfree")) {               // (drive, struct _diskfree_t *): the values GetDiskFreeSpaceA reports
        uint32_t p = arg(c, 1);
        M32(p) = 0x01FFFFFF; M32(p + 4) = 0x00FFFFFF; M32(p + 8) = 8; M32(p + 12) = 512;
        CRET(0);
    }
    return 0;
}

// ---------------- broken-down time ----------------
// struct tm: nine ints (sec, min, hour, mday, mon, year, wday, yday, isdst). Results live in a per-thread guest
// buffer, as in the multithreaded CRT. Local time is the Mac's time zone.
static __thread uint32_t tm_buf, asc_buf;
static void tm_put(uint32_t p, const struct tm *t) {
    const int v[9] = {t->tm_sec, t->tm_min, t->tm_hour, t->tm_mday, t->tm_mon, t->tm_year, t->tm_wday, t->tm_yday, t->tm_isdst > 0};
    for (int k = 0; k < 9; ++k) M32(p + 4 * (uint32_t)k) = (uint32_t)v[k];
}
static void tm_get(uint32_t p, struct tm *t) {
    memset(t, 0, sizeof *t);
    t->tm_sec = (int32_t)M32(p); t->tm_min = (int32_t)M32(p + 4); t->tm_hour = (int32_t)M32(p + 8);
    t->tm_mday = (int32_t)M32(p + 12); t->tm_mon = (int32_t)M32(p + 16); t->tm_year = (int32_t)M32(p + 20);
    t->tm_isdst = (int32_t)M32(p + 32);
}
#define TIME64_MAX 32535215999ll   // 3000-12-31 23:59:59, the VC8 limit
static int crt_time(Cpu *c, const char *fn) {
    if (!strcmp(fn, "_localtime64") || !strcmp(fn, "_gmtime64") || !strcmp(fn, "_localtime32")) {
        int64_t t = !strcmp(fn, "_localtime32") ? (int64_t)(int32_t)M32(arg(c, 0)) : (int64_t)M64(arg(c, 0));
        if (t < 0 || t > TIME64_MAX) CRET(0);
        time_t tt = (time_t)t;
        struct tm r;
        if (!(fn[1] == 'g' ? gmtime_r(&tt, &r) : localtime_r(&tt, &r))) CRET(0);
        if (!tm_buf) tm_buf = galloc(36);
        tm_put(tm_buf, &r);
        CRET(tm_buf);
    }
    if (!strcmp(fn, "_mktime64") || !strcmp(fn, "_mkgmtime64")) {   // normalizes the struct in place
        struct tm r;
        tm_get(arg(c, 0), &r);
        if (fn[3] == 'g') r.tm_isdst = 0;
        time_t t = fn[3] == 'g' ? timegm(&r) : mktime(&r);
        if (t == (time_t)-1 || t < 0 || t > TIME64_MAX) CRET64(-1);
        tm_put(arg(c, 0), &r);
        CRET64((int64_t)t);
    }
    if (!strcmp(fn, "_difftime64")) {                // (time1, time0), two __time64_t
        int64_t t1 = (int64_t)((uint64_t)arg(c, 0) | (uint64_t)arg(c, 1) << 32), t0 = (int64_t)((uint64_t)arg(c, 2) | (uint64_t)arg(c, 3) << 32);
        CRETF((double)(t1 - t0));
    }
    if (!strcmp(fn, "asctime")) {                    // "Wed Jan 02 02:03:55 1980\n": VC8 pads the day with a zero
        static const char days[] = "SunMonTueWedThuFriSat", mons[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
        uint32_t p = arg(c, 0);
        int32_t wday = (int32_t)M32(p + 24), mon = (int32_t)M32(p + 16);
        if (wday < 0 || wday > 6 || mon < 0 || mon > 11) CRET(0);
        if (!asc_buf) asc_buf = galloc(32);
        snprintf(gs(asc_buf), 32, "%.3s %.3s %02d %02d:%02d:%02d %d\n", days + 3 * wday, mons + 3 * mon, (int32_t)M32(p + 12),
                 (int32_t)M32(p + 8), (int32_t)M32(p + 4), (int32_t)M32(p), (int32_t)M32(p + 20) + 1900);
        CRET(asc_buf);
    }
    return 0;
}

// ---------------- threads ----------------
// Calls a __stdcall import handler from host code with a fresh guest frame; returns eax.
static uint32_t call_import(Cpu *c, int (*h)(Cpu *, const char *), const char *fn, int n, const uint32_t *args) {
    uint32_t sp = c->esp;
    for (int i = n - 1; i >= 0; --i) { c->esp -= 4; M32(c->esp) = args[i]; }
    c->esp -= 4;
    M32(c->esp) = 0xFEEDF00D;
    if (!h(c, fn)) crt_fatal(fn, "no host handler");
    c->esp = sp;
    return c->eax;
}
static int crt_threads(Cpu *c, const char *fn) {
    if (!strcmp(fn, "_beginthreadex")) {             // (security, stack, start, arg, initflag, thrdaddr*): CreateThread's
        uint32_t a[6] = {arg(c, 0), arg(c, 1), arg(c, 2), arg(c, 3), arg(c, 4), arg(c, 5)};   // arguments in the same order
        CRET(call_import(c, win32_threads, "CreateThread", 6, a));
    }
    if (!strcmp(fn, "_endthreadex")) {
        uint32_t a[1] = {arg(c, 0)};
        call_import(c, win32_threads, "ExitThread", 1, a);
        CRETV();
    }
    return 0;
}

int win32_msvcr(Cpu *c, const char *fn) {
    return crt_mem_str(c, fn) || crt_math(c, fn) || crt_misc(c, fn) || crt_setjmp(c, fn) || crt_files(c, fn) || crt_time(c, fn) || crt_threads(c, fn);
}
