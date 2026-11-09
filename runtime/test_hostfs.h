// test_hostfs.h - a stand-in for boot.c's file layer (host_file_*, host_find_*) for offline tests: real files under a
// temporary directory `root`, guest paths "C:\\NFSMW\\a\\b" -> <root>/a/b (the fake module folder dropped, like resolve()).
// Include after host.h; the including test creates `root` (mkdtemp) before the first call.
#pragma once
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static char root[512];
static void hostpath(const char *win, char *out, size_t n) {
    const char *p = win;
    if (p[0] && p[1] == ':') p += 2;
    while (*p == '\\' || *p == '/') ++p;
    if (!strncasecmp(p, "NFSMW", 5) && (p[5] == '\\' || p[5] == '/' || !p[5])) { p += 5; while (*p == '\\' || *p == '/') ++p; }   // like boot.c resolve()
    snprintf(out, n, "%s/%s", root, p);
    for (char *q = out + strlen(root); *q; ++q) if (*q == '\\') *q = '/';
}
int host_resolve(const char *win, char *out, size_t n) { hostpath(win, out, n); return 0; }
static int hfd[64];
static int hf(uint32_t h) { uint32_t k = (h - 0x1000) / 4; return h >= 0x1000 && k < 64 && hfd[k] ? hfd[k] - 1 : -1; }
uint32_t host_file_open(const char *win, uint32_t access, uint32_t share, uint32_t disp) {
    (void)share;
    char p[1024];
    hostpath(win, p, sizeof p);
    int fl = (access & 0xC0000000u) == 0xC0000000u ? O_RDWR : (access & 0x40000000u) ? O_WRONLY : O_RDONLY;
    fl |= disp == 1 ? O_CREAT | O_EXCL : disp == 2 ? O_CREAT | O_TRUNC : disp == 4 ? O_CREAT : disp == 5 ? O_TRUNC : 0;
    int fd = open(p, fl, 0644), k = 1;
    if (fd < 0) return 0xFFFFFFFFu;
    while (hfd[k]) ++k;
    hfd[k] = fd + 1;
    return 0x1000 + 4 * (uint32_t)k;
}
int64_t host_file_read(uint32_t h, uint32_t buf, uint32_t n) { return hf(h) < 0 ? -1 : read(hf(h), G + buf, n); }
int64_t host_file_write(uint32_t h, uint32_t buf, uint32_t n) { return hf(h) < 0 ? -1 : write(hf(h), G + buf, n); }
int64_t host_file_seek(uint32_t h, int64_t d, int m) { return hf(h) < 0 ? -1 : lseek(hf(h), d, m); }
int64_t host_file_size(uint32_t h) { struct stat st; return hf(h) < 0 || fstat(hf(h), &st) ? -1 : st.st_size; }
int host_file_close(uint32_t h) { int fd = hf(h); if (fd < 0) return 0; close(fd); hfd[(h - 0x1000) / 4] = 0; return 1; }
int host_file_remove(const char *win, int dir) { char p[1024]; hostpath(win, p, sizeof p); return (dir ? rmdir(p) : unlink(p)) == 0; }
int host_file_rename(const char *a, const char *b) { char p[1024], q[1024]; hostpath(a, p, sizeof p); hostpath(b, q, sizeof q); return rename(p, q) == 0; }
int host_mkdir(const char *win) { char p[1024]; hostpath(win, p, sizeof p); return mkdir(p, 0755) == 0; }
int host_file_exists(const char *win) { char p[1024]; struct stat st; hostpath(win, p, sizeof p); return !stat(p, &st); }
static struct { DIR *d; char dir[1024]; char pat[128]; } finds[8];
static int find_fill(int k, uint32_t data) {
    struct dirent *e;
    while ((e = readdir(finds[k].d))) {
        char p[2048];
        struct stat st;
        snprintf(p, sizeof p, "%s/%s", finds[k].dir, e->d_name);
        if (fnmatch(finds[k].pat, e->d_name, FNM_CASEFOLD) || stat(p, &st)) continue;
        memset(G + data, 0, 320);
        M32(data) = S_ISDIR(st.st_mode) ? 0x10 : 0x20;
        uint64_t ft = ((uint64_t)st.st_mtime + 11644473600ull) * 10000000ull;
        M64(data + 4) = ft; M64(data + 12) = ft; M64(data + 20) = ft;
        M32(data + 32) = (uint32_t)st.st_size;
        snprintf((char *)G + data + 44, 260, "%s", e->d_name);
        return 1;
    }
    return 0;
}
uint32_t host_find_first(const char *win, uint32_t data) {
    char spec[1024];
    snprintf(spec, sizeof spec, "%s", win);
    char *slash = strrchr(spec, '\\');
    int k = 0;
    while (finds[k].d) ++k;
    snprintf(finds[k].pat, sizeof finds[k].pat, "%s", slash ? slash + 1 : spec);
    if (slash) *slash = 0; else spec[0] = 0;
    hostpath(spec, finds[k].dir, sizeof finds[k].dir);
    if (!(finds[k].d = opendir(finds[k].dir))) return 0xFFFFFFFFu;
    if (find_fill(k, data)) return 0x2800 + 4 * (uint32_t)k;
    closedir(finds[k].d); finds[k].d = NULL;
    return 0xFFFFFFFFu;
}
int host_find_next(uint32_t h, uint32_t data) { int k = (int)(h - 0x2800) / 4; return k >= 0 && k < 8 && finds[k].d && find_fill(k, data); }
void host_find_close(uint32_t h) { int k = (int)(h - 0x2800) / 4; if (k >= 0 && k < 8 && finds[k].d) { closedir(finds[k].d); finds[k].d = NULL; } }
uint32_t host_file_attr(const char *win) {
    char p[1024];
    struct stat st;
    hostpath(win, p, sizeof p);
    return stat(p, &st) ? 0xFFFFFFFFu : S_ISDIR(st.st_mode) ? 0x10 : 0x20;
}
