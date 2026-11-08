// msvcr.c - MSVCR80/MSVCP80 (Visual C++ 2005 runtime) for the guest, implemented natively. See docs/crt-shim.md.
// CRT functions are __cdecl: a handler sets eax (edx:eax for 64-bit results, ST(0) for double) and pops only the
// return address (CRET). Anything not handled here returns 0, and host_import stops with the import's name.
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

// heap.c: the guest process heap, the same one HeapAlloc serves (crt_heap_alloc zeroes, returns 0 when full).
uint32_t crt_heap_alloc(uint32_t n);
void crt_heap_free(uint32_t a);
uint32_t crt_heap_realloc(uint32_t a, uint32_t n);
uint32_t crt_heap_size(uint32_t a);
// threads.c: guest CRITICAL_SECTION enter/leave (recursive, GIL-aware), for _lock/_unlock.
void crt_cs_enter(Cpu *c, uint32_t cs);
void crt_cs_leave(uint32_t cs);
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
    uint32_t dst, cap;   // guest output (cap bytes at most); dst 0 = host log
    uint32_t n;          // characters produced (all, also beyond cap)
    char line[512];
    int ln;
} Out;
static void out_flush(Out *o) {
    if (o->ln) { fprintf(stderr, "guest: %.*s\n", o->ln, o->line); o->ln = 0; }
}
static void out_c(Out *o, char ch) {
    if (o->dst) { if (o->n < o->cap) M8(o->dst + o->n) = (uint8_t)ch; }
    else if (ch == '\n' || o->ln == (int)sizeof o->line) { out_flush(o); if (ch != '\n') o->line[o->ln++] = ch; }
    else o->line[o->ln++] = ch;
    ++o->n;
}
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

static void format(Out *o, uint32_t f, VA *v) {
    for (;;) {
        char ch = (char)M8(f++);
        if (!ch) break;
        if (ch != '%') { out_c(o, ch); continue; }
        int left = 0, plus = 0, space = 0, alt = 0, zero = 0;
        for (;; ++f) {
            ch = (char)M8(f);
            if (ch == '-') left = 1;
            else if (ch == '+') plus = 1;
            else if (ch == ' ') space = 1;
            else if (ch == '#') alt = 1;
            else if (ch == '0') zero = 1;
            else break;
        }
        int width = 0, prec = -1;
        if (M8(f) == '*') { ++f; int32_t w = (int32_t)va32(v); if (w < 0) { left = 1; w = -w; } width = w; }
        else while (c_isdigit(M8(f))) width = width * 10 + (M8(f++) - '0');
        if (M8(f) == '.') {
            ++f;
            prec = 0;
            if (M8(f) == '*') { ++f; int32_t p = (int32_t)va32(v); prec = p < 0 ? -1 : p; }
            else while (c_isdigit(M8(f))) prec = prec * 10 + (M8(f++) - '0');
        }
        if (width > 65536) width = 65536;
        if (prec > 4096) prec = 4096;
        int size = 0;   // 'h', 'l' (also w), 64 (ll, I64), 'L'
        ch = (char)M8(f);
        if (ch == 'h') { size = 'h'; ++f; }
        else if (ch == 'l') { ++f; if (M8(f) == 'l') { ++f; size = 64; } else size = 'l'; }
        else if (ch == 'L') { size = 'L'; ++f; }
        else if (ch == 'w') { size = 'l'; ++f; }
        else if (ch == 'I') {
            if (M8(f + 1) == '6' && M8(f + 2) == '4') { size = 64; f += 3; }
            else if (M8(f + 1) == '3' && M8(f + 2) == '2') f += 3;
            else ++f;
        }
        char t = (char)M8(f++);
        if (!t) break;
        char hf[16], *body = NULL, small[64];
        size_t blen = 0;
        int numeric = 0, zero_ok = 0, owned = 0;
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
            small[0] = (t == 'C' || size == 'l') && (r & 0xFFFF) > 0xFF ? '?' : (char)r;
            body = small;
            blen = 1;
            break;
        }
        case 's': case 'S': {
            uint32_t p = va32(v);
            int wide = t == 'S' || size == 'l';
            if (!p) { body = (char *)"(null)"; blen = 6; if (prec >= 0 && (size_t)prec < blen) blen = (size_t)prec; break; }
            size_t n = 0;
            if (wide) while ((prec < 0 || n < (size_t)prec) && M16(p + 2 * n)) ++n;
            else while ((prec < 0 || n < (size_t)prec) && M8(p + n)) ++n;
            body = malloc(n + 1);
            owned = 1;
            for (size_t k = 0; k < n; ++k) { uint16_t w = wide ? M16(p + 2 * k) : M8(p + k); body[k] = w > 0xFF ? '?' : (char)w; }
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
}

// vsnprintf-style front end: writes at most cap chars to dst; returns the full length.
static uint32_t format_to(uint32_t dst, uint32_t cap, uint32_t fmt, uint32_t va) {
    Out o = {.dst = dst, .cap = cap};
    VA v = {va};
    format(&o, fmt, &v);
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
static uint32_t fmode_var, commode_var, onexit_tab[256];
static unsigned onexit_n;
static int locale_mode = 2;                    // _DISABLE_PER_THREAD_LOCALE
static uint32_t crt_locks[64];                 // guest CRITICAL_SECTIONs for _lock(n)
static uint64_t clock_t0;

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
        format(&o, arg(c, 0), &v);
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
        M16(p + 10) = 0;                             // minutes west of UTC: the guest sees UTC
        M16(p + 12) = 0;
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
        static uint32_t argv, envp;
        if (!argv) {
            argv = galloc(8);
            M32(argv) = gstr("nfs.exe");
            envp = galloc(4);
        }
        M32(arg(c, 0)) = 1;
        M32(arg(c, 1)) = argv;
        M32(arg(c, 2)) = envp;
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

int win32_msvcr(Cpu *c, const char *fn) {
    return crt_mem_str(c, fn) || crt_math(c, fn) || crt_misc(c, fn);
}
