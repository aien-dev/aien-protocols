/*
 * vc1-check.c: reference encoder, decoder and id computer for VerifiedCrumbV1
 * (specs/verified-crumb/SPEC.md).
 *
 * Self-contained C99, libc only. The SHA-256 below is copied from
 * specs/execution-transcript/tools/trn1_verify.c lines 53 to 117 (FIPS 180-4).
 *
 *   vc1-check FILE.hex            print "ACCEPT <vc id>" or "REFUSE <CODE> @<offset>"
 *   vc1-check --corpus DIR        check DIR/expected.txt against DIR/<name>.hex,
 *                                 print "VC1_CONFORMANCE impl=c pass=N fail=M"
 *
 * Exit: 0 accept/all pass, 1 refuse/any fail, 2 usage or I/O error.
 * Compile with -DVC1_MUTANT=N (1..5) to build a deliberately broken checker;
 * tools/check-golden.sh proves the corpus rejects every mutant.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VC1_MUTANT
#define VC1_MUTANT 0
#endif

/* ---- SHA-256 (copy of trn1_verify.c) ------------------------------------- */
typedef struct { uint32_t h[8]; uint64_t n; uint8_t b[64]; uint32_t used; } sha256;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

static void sha_block(sha256 *s, const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void sha_init(sha256 *s) {
    static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(s->h, iv, sizeof iv); s->n = 0; s->used = 0;
}
static void sha_update(sha256 *s, const void *data, size_t len) {
    const uint8_t *p = data;
    s->n += len;
    while (len) {
        uint32_t k = 64 - s->used;
        if (k > len) k = (uint32_t)len;
        memcpy(s->b + s->used, p, k);
        s->used += k; p += k; len -= k;
        if (s->used == 64) { sha_block(s, s->b); s->used = 0; }
    }
}
static void sha_final(sha256 *s, uint8_t out[32]) {
    uint64_t bits = s->n * 8;
    uint8_t pad = 0x80, z = 0, l[8];
    sha_update(s, &pad, 1);
    while (s->used != 56) sha_update(s, &z, 1);
    for (int i = 0; i < 8; i++) l[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(s, l, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i] = (uint8_t)(s->h[i] >> 24); out[4*i+1] = (uint8_t)(s->h[i] >> 16);
        out[4*i+2] = (uint8_t)(s->h[i] >> 8); out[4*i+3] = (uint8_t)s->h[i];
    }
}
static void sha2(const void *a, size_t na, uint8_t out[32]) {
    sha256 s; sha_init(&s); sha_update(&s, a, na); sha_final(&s, out);
}

/* ---- VC1 model ----------------------------------------------------------- */
#define TAG "AIEN_VERIFIED_CRUMB_V1"
#define TAG_LEN 22
#define VC_VERSION 1u
#define VC_MAX 256          /* max entries per list (SPEC section 3.6) */
#define VC_STR_MAX 256      /* max bytes per string */

enum code {
    OK = 0,
    /* resolve-level names, also produced at format level */
    MISSING_RECEIPT = 1, DEPENDENCY_CYCLE = 2,
    /* format-level */
    BAD_DOMAIN_TAG = 20, UNKNOWN_FORMAT_VERSION, TRUNCATED, TRAILING_BYTES,
    DUPLICATE_DEPENDENCY, UNSORTED_DEPENDENCIES, NONCANONICAL_SET, BAD_STRING,
    ZERO_ID, TOO_MANY_ENTRIES
};
static const char *code_name(int c) {
    switch (c) {
    case MISSING_RECEIPT: return "MISSING_RECEIPT";
    case DEPENDENCY_CYCLE: return "DEPENDENCY_CYCLE";
    case BAD_DOMAIN_TAG: return "BAD_DOMAIN_TAG";
    case UNKNOWN_FORMAT_VERSION: return "UNKNOWN_FORMAT_VERSION";
    case TRUNCATED: return "TRUNCATED";
    case TRAILING_BYTES: return "TRAILING_BYTES";
    case DUPLICATE_DEPENDENCY: return "DUPLICATE_DEPENDENCY";
    case UNSORTED_DEPENDENCIES: return "UNSORTED_DEPENDENCIES";
    case NONCANONICAL_SET: return "NONCANONICAL_SET";
    case BAD_STRING: return "BAD_STRING";
    case ZERO_ID: return "ZERO_ID";
    case TOO_MANY_ENTRIES: return "TOO_MANY_ENTRIES";
    }
    return "?";
}

typedef struct { uint8_t semantic_id[32], required_contract[32]; } dep_t;
typedef struct { char s[VC_STR_MAX + 1]; } str_t;
typedef struct {
    uint32_t format_version;
    uint8_t semantic_id[32], contract_id[32], source_or_ir_digest[32];
    uint32_t n_real; uint8_t realization_ids[VC_MAX][32];
    uint32_t n_dep; dep_t deps[VC_MAX];
    uint8_t receipt_id[32]; str_t verifier_profile, verifier_version; uint8_t evidence_root[32];
    uint32_t n_exp; str_t exports[VC_MAX];
    uint32_t n_cap; str_t capabilities[VC_MAX];
} vc_t;

static int is_zero(const uint8_t *p) {
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= p[i];
    return acc == 0;
}

/* ---- decoder ------------------------------------------------------------- */
typedef struct { const uint8_t *b; size_t n, pos; int err; size_t err_at; } cur_t;

static int fail(cur_t *c, int code) {
    if (!c->err) { c->err = code; c->err_at = c->pos; }
    return code;
}
static int need(cur_t *c, size_t k) {
    if (c->err) return 0;
    if (c->n - c->pos < k) { fail(c, TRUNCATED); return 0; }
    return 1;
}
static uint32_t rd32(cur_t *c) {
    if (!need(c, 4)) return 0;
    const uint8_t *p = c->b + c->pos; c->pos += 4;
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint64_t rd64(cur_t *c) {
    uint64_t hi = rd32(c), lo = rd32(c);
    return hi << 32 | lo;
}
static void rd_id(cur_t *c, uint8_t out[32]) {
    if (!need(c, 32)) { memset(out, 0, 32); return; }
    memcpy(out, c->b + c->pos, 32); c->pos += 32;
}
static void rd_str(cur_t *c, str_t *out) {
    uint64_t len = rd64(c);
    out->s[0] = 0;
    if (c->err) return;
    if (len == 0 || len > VC_STR_MAX) { fail(c, BAD_STRING); return; }
    if (!need(c, (size_t)len)) return;
    for (uint64_t i = 0; i < len; i++) {
        uint8_t ch = c->b[c->pos + i];
        if (ch < 0x21 || ch > 0x7e) { c->pos += (size_t)i; fail(c, BAD_STRING); return; }
    }
    memcpy(out->s, c->b + c->pos, (size_t)len); out->s[len] = 0; c->pos += (size_t)len;
}
static uint32_t rd_count(cur_t *c) {
    uint32_t n = rd32(c);
    if (!c->err && n > VC_MAX) { fail(c, TOO_MANY_ENTRIES); return 0; }
    return n;
}

/* Field order is the refusal order; the first failure wins. */
static int decode(const uint8_t *b, size_t n, vc_t *v, size_t *err_at) {
    cur_t c = { b, n, 0, 0, 0 };
    memset(v, 0, sizeof *v);
    if (!need(&c, TAG_LEN)) goto done;
    if (memcmp(b, TAG, TAG_LEN) != 0) { fail(&c, BAD_DOMAIN_TAG); goto done; }
    c.pos = TAG_LEN;
    v->format_version = rd32(&c);
    if (!c.err && v->format_version != VC_VERSION) { c.pos -= 4; fail(&c, UNKNOWN_FORMAT_VERSION); c.pos += 4; }
    rd_id(&c, v->semantic_id); rd_id(&c, v->contract_id); rd_id(&c, v->source_or_ir_digest);
    if (!c.err && (is_zero(v->semantic_id) || is_zero(v->contract_id) || is_zero(v->source_or_ir_digest)))
        fail(&c, ZERO_ID);
    v->n_real = rd_count(&c);
    for (uint32_t i = 0; i < v->n_real && !c.err; i++) {
        rd_id(&c, v->realization_ids[i]);
        if (!c.err && i > 0 && memcmp(v->realization_ids[i - 1], v->realization_ids[i], 32) >= 0)
            fail(&c, NONCANONICAL_SET);
    }
    v->n_dep = rd_count(&c);
    for (uint32_t i = 0; i < v->n_dep && !c.err; i++) {
        rd_id(&c, v->deps[i].semantic_id); rd_id(&c, v->deps[i].required_contract);
        if (c.err) break;
        if (memcmp(v->deps[i].semantic_id, v->semantic_id, 32) == 0) { fail(&c, DEPENDENCY_CYCLE); break; }
        if (is_zero(v->deps[i].semantic_id) || is_zero(v->deps[i].required_contract)) { fail(&c, ZERO_ID); break; }
        if (i > 0) {
            int cmp = memcmp(v->deps[i - 1].semantic_id, v->deps[i].semantic_id, 32);
#if VC1_MUTANT != 4
            if (cmp == 0) { fail(&c, DUPLICATE_DEPENDENCY); break; }
#endif
#if VC1_MUTANT != 1
            if (cmp > 0) { fail(&c, UNSORTED_DEPENDENCIES); break; }
#endif
        }
    }
    rd_id(&c, v->receipt_id);
#if VC1_MUTANT != 2
    if (!c.err && is_zero(v->receipt_id)) fail(&c, MISSING_RECEIPT);
#endif
    rd_str(&c, &v->verifier_profile); rd_str(&c, &v->verifier_version);
    rd_id(&c, v->evidence_root);
    if (!c.err && is_zero(v->evidence_root)) fail(&c, ZERO_ID);
    v->n_exp = rd_count(&c);
    for (uint32_t i = 0; i < v->n_exp && !c.err; i++) {
        rd_str(&c, &v->exports[i]);
        if (!c.err && i > 0 && strcmp(v->exports[i - 1].s, v->exports[i].s) >= 0) fail(&c, NONCANONICAL_SET);
    }
    v->n_cap = rd_count(&c);
    for (uint32_t i = 0; i < v->n_cap && !c.err; i++) {
        rd_str(&c, &v->capabilities[i]);
        if (!c.err && i > 0 && strcmp(v->capabilities[i - 1].s, v->capabilities[i].s) >= 0) fail(&c, NONCANONICAL_SET);
    }
#if VC1_MUTANT != 5
    if (!c.err && c.pos != c.n) fail(&c, TRAILING_BYTES);
#endif
done:
    *err_at = c.err_at;
    return c.err;
}

/* ---- encoder ------------------------------------------------------------- */
typedef struct { uint8_t *p; size_t n, cap; } buf_t;
static void put(buf_t *o, const void *d, size_t k) {
    if (o->n + k > o->cap) {
        o->cap = (o->n + k) * 2 + 64;
        o->p = realloc(o->p, o->cap);
        if (!o->p) { fputs("out of memory\n", stderr); exit(2); }
    }
    memcpy(o->p + o->n, d, k); o->n += k;
}
static void put32(buf_t *o, uint32_t x) {
    uint8_t t[4] = { (uint8_t)(x >> 24), (uint8_t)(x >> 16), (uint8_t)(x >> 8), (uint8_t)x };
    put(o, t, 4);
}
static void put_str(buf_t *o, const char *s) {
    uint64_t n = strlen(s);
    put32(o, (uint32_t)(n >> 32)); put32(o, (uint32_t)n); put(o, s, (size_t)n);
}
static int cmp_dep(const void *a, const void *b) { return memcmp(a, b, 32); }
static int cmp_id(const void *a, const void *b) { return memcmp(a, b, 32); }
static int cmp_str(const void *a, const void *b) { return strcmp(((const str_t *)a)->s, ((const str_t *)b)->s); }

/* Canonical bytes, with every list sorted (the encoder owns the sort; the
 * decoder refuses unsorted input). Duplicate dependencies are refused. */
static int encode(vc_t *v, buf_t *o) {
    qsort(v->realization_ids, v->n_real, 32, cmp_id);
    qsort(v->deps, v->n_dep, sizeof(dep_t), cmp_dep);
    qsort(v->exports, v->n_exp, sizeof(str_t), cmp_str);
    qsort(v->capabilities, v->n_cap, sizeof(str_t), cmp_str);
    for (uint32_t i = 1; i < v->n_dep; i++)
        if (memcmp(v->deps[i - 1].semantic_id, v->deps[i].semantic_id, 32) == 0) return DUPLICATE_DEPENDENCY;
    o->n = 0;
    put(o, TAG, TAG_LEN); put32(o, v->format_version);
    put(o, v->semantic_id, 32); put(o, v->contract_id, 32); put(o, v->source_or_ir_digest, 32);
    put32(o, v->n_real); for (uint32_t i = 0; i < v->n_real; i++) put(o, v->realization_ids[i], 32);
    put32(o, v->n_dep);
    for (uint32_t i = 0; i < v->n_dep; i++) { put(o, v->deps[i].semantic_id, 32); put(o, v->deps[i].required_contract, 32); }
    put(o, v->receipt_id, 32); put_str(o, v->verifier_profile.s); put_str(o, v->verifier_version.s);
    put(o, v->evidence_root, 32);
    put32(o, v->n_exp); for (uint32_t i = 0; i < v->n_exp; i++) put_str(o, v->exports[i].s);
    put32(o, v->n_cap); for (uint32_t i = 0; i < v->n_cap; i++) put_str(o, v->capabilities[i].s);
    return OK;
}

/* VC id = SHA-256 over the canonical bytes (which start with the domain tag). */
static void vc_id(const uint8_t *canon, size_t n, uint8_t out[32]) {
#if VC1_MUTANT == 3
    sha2(canon + TAG_LEN, n - TAG_LEN, out);   /* mutant: domain tag dropped from the hash */
#else
    sha2(canon, n, out);
#endif
}

/* ---- I/O ----------------------------------------------------------------- */
static int unhex(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}
/* Read a lowercase-hex file (whitespace ignored). Returns malloc'd bytes or NULL. */
static uint8_t *read_hex(const char *path, size_t *n_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0; char *t = malloc(cap); int ch;
    while ((ch = fgetc(f)) != EOF) {
        if (ch == '\n' || ch == '\r' || ch == ' ') continue;
        if (n + 1 > cap) { cap *= 2; t = realloc(t, cap); }
        t[n++] = (char)ch;
    }
    fclose(f);
    if (n % 2) { free(t); return NULL; }
    uint8_t *b = malloc(n / 2 + 1);
    for (size_t i = 0; i < n; i += 2) {
        int hi = unhex((unsigned char)t[i]), lo = unhex((unsigned char)t[i + 1]);
        if (hi < 0 || lo < 0) { free(t); free(b); return NULL; }
        b[i / 2] = (uint8_t)(hi << 4 | lo);
    }
    free(t); *n_out = n / 2; return b;
}
static void hex32(const uint8_t *p, char out[65]) {
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", p[i]);
}

static vc_t g_vc;   /* large, so static */

/* Check one buffer. On accept fills id_hex; on refuse fills code and offset. */
static int check(const uint8_t *b, size_t n, char id_hex[65], int *code, size_t *at) {
    size_t err_at = 0;
    int rc = decode(b, n, &g_vc, &err_at);
    if (rc) { *code = rc; *at = err_at; return 1; }
    /* canonical round trip: re-encoding must reproduce the input bytes */
    buf_t o = { 0, 0, 0 };
    vc_t *tmp = malloc(sizeof *tmp); memcpy(tmp, &g_vc, sizeof *tmp);
    int erc = encode(tmp, &o);
    int same = erc == OK && o.n == n && memcmp(o.p, b, n) == 0;
    /* the encoder sorts: a reversed copy must encode to the same bytes */
    if (same && g_vc.n_dep > 1) {
        for (uint32_t i = 0; i < g_vc.n_dep / 2; i++) {
            dep_t t = tmp->deps[i]; tmp->deps[i] = tmp->deps[g_vc.n_dep - 1 - i]; tmp->deps[g_vc.n_dep - 1 - i] = t;
        }
        buf_t o2 = { 0, 0, 0 };
        same = encode(tmp, &o2) == OK && o2.n == o.n && memcmp(o2.p, o.p, o.n) == 0;
        free(o2.p);
    }
    free(tmp); free(o.p);
    if (!same) { *code = TRAILING_BYTES; *at = n; fputs("vc1-check: internal: encode/decode round trip differs\n", stderr); return 2; }
    uint8_t id[32]; vc_id(b, n, id); hex32(id, id_hex);
    return 0;
}

static int run_file(const char *path) {
    size_t n; uint8_t *b = read_hex(path, &n);
    if (!b) { fprintf(stderr, "vc1-check: cannot read lowercase hex file %s\n", path); return 2; }
    char id[65]; int code = 0; size_t at = 0;
    int r = check(b, n, id, &code, &at);
    free(b);
    if (r == 0) { printf("ACCEPT %s\n", id); return 0; }
    if (r == 2) return 2;
    printf("REFUSE %s @%zu\n", code_name(code), at);
    return 1;
}

static int run_corpus(const char *dir) {
    char path[1024], line[512];
    snprintf(path, sizeof path, "%s/expected.txt", dir);
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "vc1-check: cannot open %s\n", path); return 2; }
    int pass = 0, failn = 0;
    while (fgets(line, sizeof line, f)) {
        char name[256], verb[16], arg[128];
        if (sscanf(line, "%255s %15s %127s", name, verb, arg) != 3) continue;
        snprintf(path, sizeof path, "%s/%s.hex", dir, name);
        size_t n; uint8_t *b = read_hex(path, &n);
        char id[65] = ""; int code = 0; size_t at = 0; int ok = 0;
        if (b) {
            int r = check(b, n, id, &code, &at);
            if (r == 0) ok = strcmp(verb, "ACCEPT") == 0 && strcmp(arg, id) == 0;
            else if (r == 1) ok = strcmp(verb, "REFUSE") == 0 && strcmp(arg, code_name(code)) == 0;
            free(b);
        }
        if (ok) pass++; else { failn++; printf("FAIL %s (expected %s %s)\n", name, verb, arg); }
    }
    fclose(f);
    printf("VC1_CONFORMANCE impl=c pass=%d fail=%d\n", pass, failn);
    return failn ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--corpus") == 0) return run_corpus(argv[2]);
    if (argc == 2 && argv[1][0] != '-') return run_file(argv[1]);
    fputs("usage: vc1-check FILE.hex | vc1-check --corpus DIR\n", stderr);
    return 2;
}
