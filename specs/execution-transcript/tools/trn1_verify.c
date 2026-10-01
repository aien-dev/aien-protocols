/* trn1_verify.c: reference verifier for the TRN1 execution transcript,
 * wire schema 1, contract 0.1.0. Spec: ../TRN1_TRANSCRIPT_SPEC.md.
 *
 * Self-contained C99: its own SHA-256 (FIPS 180-4), libc only, no imports
 * from any implementation repository. It exists to prove the corpus, not to
 * be linked into a runtime.
 *
 * Usage:
 *   trn1_verify FILE                 print one verdict line (spec section 7)
 *   trn1_verify --compare EXP ACT    print one compare line (spec section 8)
 *   trn1_verify --corpus DIR         check DIR/expected.txt and DIR/compare.txt,
 *                                    print TRN1_CONFORMANCE impl=c pass=N fail=M
 *
 * Exit status: 0 on accept / MATCH / all corpus lines agree, 1 otherwise,
 * 2 on usage or I/O error.
 *
 * Mutation hooks: building with -DTRN1_MUTANT=K disables check K (the
 * numbers are the CHK_* values below). tools/mutate-verifier.sh builds every
 * mutant and requires the corpus to fail each one, which shows every check
 * is exercised by at least one vector.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TRN1_MUTANT
#define TRN1_MUTANT 0
#endif
#define CHECK(k) (TRN1_MUTANT != (k))

enum {
    CHK_MAGIC = 1, CHK_VERSION, CHK_HDR_FLAGS, CHK_PRODUCER, CHK_HDR_RESERVED,
    CHK_TYPE, CHK_SUBSYS, CHK_REC_RESERVED, CHK_LIMIT, CHK_SEQ, CHK_PREV,
    CHK_IDENT_LEN, CHK_END_SUBSYS, CHK_BODY_RESERVED, CHK_CAP_OP,
    CHK_CRASH_SEQ, CHK_CRUMB_SHAPE, CHK_CRUMB_DIGEST, CHK_ARGUS_FLAG,
    CHK_ARGUS_LINK, CHK_ARGUS_CONT, CHK_INPUT_DIGEST, CHK_END_ANNOT,
    CHK_END_COUNT, CHK_TRAILING, CHK_TRUNCATED, CHK_LAST
};

/* ---- refusal codes (spec section 6) ------------------------------------ */
enum {
    R_OK = 0, R_MAGIC = -1, R_VERSION = -2, R_LENGTH = -3, R_NONCANONICAL = -4,
    R_UNKNOWN = -5, R_SHAPE = -6, R_GAP = -7, R_CHAIN = -8, R_DIGEST = -9,
    R_TRUNCATED = -10
};

/* ---- SHA-256 ------------------------------------------------------------ */
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
static void sha2(const void *a, size_t na, const void *b, size_t nb, uint8_t out[32]) {
    sha256 s; sha_init(&s); sha_update(&s, a, na); if (nb) sha_update(&s, b, nb); sha_final(&s, out);
}

/* ---- little-endian readers ---------------------------------------------- */
static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t g32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t g64(const uint8_t *p) { return (uint64_t)g32(p) | (uint64_t)g32(p + 4) << 32; }
static int all_zero(const uint8_t *p, size_t n) { while (n--) if (*p++) return 0; return 1; }

/* ---- registries (spec sections 4 and 5) --------------------------------- */
#define HDR_SIZE      48u
#define REC_HDR_SIZE  56u
#define MAX_IDENT     65536u
#define MAX_ANNOT     65536u
#define MAX_CONTENT   4096u
#define T_END         0xFFFFu

static const char *subsys_name(uint16_t s) {
    static const char *n[] = { "transcript", "omega-world", "omega-cortex", "omega-jspace",
        "aienos-kernel", "aienos-argus", "aienos-store", "sovcore-runtime",
        "sovcore-scheduler", "sovcore-kv", "external" };
    return s < sizeof n / sizeof n[0] ? n[s] : NULL;
}

/* Fixed identity length per record type; -1 = variable (rule in code), 0 = unknown type. */
static long ident_rule(uint16_t t) {
    switch (t) {
    case 1: return 32;   /* SCHED_DECISION */
    case 2: return 24;   /* BRANCH_CREATE */
    case 3: return 24;   /* BRANCH_DESTROY */
    case 4: return 40;   /* RNG_SEED */
    case 5: return 24;   /* RNG_DRAW */
    case 6: return 48;   /* ARTIFACT_DIGEST */
    case 7: return 32;   /* CAP_TRANSITION */
    case 8: return 56;   /* CORTEX_READ */
    case 9: return 56;   /* EFFECT_INTENT */
    case 10: return 48;  /* EFFECT_COMMIT */
    case 11: return -1;  /* EXTERNAL_INPUT: 48 + content (0..4096) */
    case 12: return 16;  /* CLOCK_READ */
    case 13: return 48;  /* CRASH_BOUNDARY */
    case 14: return 40;  /* CHECKPOINT */
    case 15: return -1;  /* RX_CRUMB: 32 + canonical crumb bytes */
    case 16: return 200; /* ARGUS_EVENT */
    case T_END: return 16;
    default: return 0;
    }
}

/* RX_CRUMB canonical bytes: the exact preimage omega hashes after the
 * "AIEN_RX_CAUSAL_V1" tag (omega src/runtime/rx_world.c crumb_hash).
 * Returns 1 if the bytes parse exactly, 0 otherwise. */
static int crumb_shape(const uint8_t *c, size_t n) {
    size_t o = 0;
    uint64_t id;
    uint32_t k;
#define NEED(x) do { if (n - o < (size_t)(x)) return 0; } while (0)
    NEED(8 + 4 + 4 + 4 + 8 + 8); id = g64(c); o += 36;
    NEED(4); k = g32(c + o); o += 4; if (k > 8) return 0; NEED((size_t)k * 24); o += (size_t)k * 24;
    NEED(4); k = g32(c + o); o += 4; if (k > 8) return 0; NEED((size_t)k * 16); o += (size_t)k * 16;
    NEED(4); k = g32(c + o); o += 4; if (k > 8) return 0; NEED((size_t)k * 24); o += (size_t)k * 24;
    NEED(4); o += 4;                                  /* reason */
    NEED(4); k = g32(c + o); o += 4; if (k > 65) return 0;
    for (uint32_t i = 0; i < k; i++) {
        uint64_t p;
        NEED(8); p = g64(c + o); o += 8;
        if (p >= 1 && p < id) { NEED(32); o += 32; }
    }
#undef NEED
    return o == n;
}

/* ---- transcript walk ---------------------------------------------------- */
#define MAX_RECS 4096u
typedef struct {
    int code;              /* R_* */
    uint64_t event;        /* failing record position, 0 = header */
    uint64_t records;      /* on accept: record count including END */
    uint8_t run_id[32];
    uint8_t final_digest[32];
    uint8_t (*cmp)[32];    /* compared digest per record (index 0 = record 1) */
    uint16_t *subsys;
} Verdict;

static int refuse(Verdict *v, int code, uint64_t ev) { v->code = code; v->event = ev; return code; }

static int verify(const uint8_t *b, size_t n, Verdict *v) {
    size_t o = 0;
    uint8_t prev[32], argus_after[32];
    int have_argus = 0;
    uint64_t seq = 0;

    memset(v, 0, sizeof *v);
    v->cmp = calloc(MAX_RECS, 32);
    v->subsys = calloc(MAX_RECS, sizeof *v->subsys);
    if (!v->cmp || !v->subsys) { fprintf(stderr, "out of memory\n"); exit(2); }

    /* Header, check order 1..5. */
    if (n < 4) return refuse(v, R_LENGTH, 0);
    if (CHECK(CHK_MAGIC) && memcmp(b, "TRN1", 4) != 0) return refuse(v, R_MAGIC, 0);
    if (n < 6) return refuse(v, R_LENGTH, 0);
    if (CHECK(CHK_VERSION) && g16(b + 4) != 1) return refuse(v, R_VERSION, 0);
    if (n < HDR_SIZE) return refuse(v, R_LENGTH, 0);
    if (CHECK(CHK_HDR_FLAGS) && g16(b + 6) != 0) return refuse(v, R_NONCANONICAL, 0);
    if (CHECK(CHK_PRODUCER) && (g16(b + 40) == 0 || !subsys_name(g16(b + 40)))) return refuse(v, R_UNKNOWN, 0);
    if (CHECK(CHK_HDR_RESERVED) && !all_zero(b + 42, 6)) return refuse(v, R_NONCANONICAL, 0);
    memcpy(v->run_id, b + 8, 32);
    sha2(b, HDR_SIZE, NULL, 0, prev);
    o = HDR_SIZE;

    for (;;) {
        const uint8_t *r, *id, *an;
        uint16_t type, sub;
        uint32_t ilen, alen;
        long rule;
        uint64_t pos = seq + 1;

        /* 1. record header present */
        if (o == n) return refuse(v, CHECK(CHK_TRUNCATED) ? R_TRUNCATED : R_OK, pos);
        if (n - o < REC_HDR_SIZE) return refuse(v, R_LENGTH, pos);
        if (pos > MAX_RECS) return refuse(v, R_LENGTH, pos);
        r = b + o;
        type = g16(r); sub = g16(r + 2); ilen = g32(r + 4); alen = g32(r + 8);
        /* 2. known type and subsystem */
        rule = ident_rule(type);
        if (CHECK(CHK_TYPE) && rule == 0) return refuse(v, R_UNKNOWN, pos);
        if (CHECK(CHK_SUBSYS) && !subsys_name(sub)) return refuse(v, R_UNKNOWN, pos);
        /* 3. reserved */
        if (CHECK(CHK_REC_RESERVED) && g32(r + 12) != 0) return refuse(v, R_NONCANONICAL, pos);
        /* 4. length limits */
        if (CHECK(CHK_LIMIT) && (ilen > MAX_IDENT || alen > MAX_ANNOT)) return refuse(v, R_LENGTH, pos);
        /* 5. sequence */
        if (CHECK(CHK_SEQ) && g64(r + 16) != pos) return refuse(v, R_GAP, pos);
        /* 6. chain */
        if (CHECK(CHK_PREV) && memcmp(r + 24, prev, 32) != 0) return refuse(v, R_CHAIN, pos);
        /* 7. body present */
        if ((uint64_t)(n - o - REC_HDR_SIZE) < (uint64_t)ilen + alen) return refuse(v, R_LENGTH, pos);
        id = r + REC_HDR_SIZE; an = id + ilen;

        /* 8. shape, then reserved fields, then embedded digests */
        if (CHECK(CHK_IDENT_LEN)) {
            if (rule > 0 && ilen != (uint32_t)rule) return refuse(v, R_SHAPE, pos);
            if (type == 11 && (ilen < 48 || ilen > 48 + MAX_CONTENT)) return refuse(v, R_SHAPE, pos);
            if (type == 15 && ilen < 32) return refuse(v, R_SHAPE, pos);
        }
        if (CHECK(CHK_END_SUBSYS) && ((type == T_END) != (sub == 0))) return refuse(v, R_SHAPE, pos);
        if (CHECK(CHK_CAP_OP) && type == 7 && (id[4] < 1 || id[4] > 6)) return refuse(v, R_SHAPE, pos);
        if (CHECK(CHK_CRASH_SEQ) && type == 13 && g64(id + 8) >= pos) return refuse(v, R_SHAPE, pos);
        if (CHECK(CHK_CRUMB_SHAPE) && type == 15 && ilen >= 32 && !crumb_shape(id + 32, ilen - 32)) return refuse(v, R_SHAPE, pos);
        if (CHECK(CHK_ARGUS_FLAG) && type == 16 && id[128] > 1) return refuse(v, R_SHAPE, pos);
        if (CHECK(CHK_END_ANNOT) && type == T_END && alen != 0) return refuse(v, R_SHAPE, pos);
        if (CHECK(CHK_BODY_RESERVED)) {
            int bad = 0;
            switch (type) {
            case 3: bad = g32(id + 20) != 0; break;
            case 6: bad = g32(id + 4) != 0; break;
            case 7: bad = !all_zero(id + 5, 3); break;
            case 10: bad = g32(id + 12) != 0; break;
            case 11: bad = g32(id + 4) != 0; break;
            case 12: bad = g32(id + 4) != 0; break;
            case 14: bad = g32(id + 4) != 0; break;
            case 16: bad = !all_zero(id + 129, 7); break;
            case T_END: bad = g64(id + 8) != 0; break;
            }
            if (bad) return refuse(v, R_NONCANONICAL, pos);
        }
        if (type == 15 && ilen >= 32) {
            uint8_t d[32];
            sha2("AIEN_RX_CAUSAL_V1", 17, id + 32, ilen - 32, d);
            if (CHECK(CHK_CRUMB_DIGEST) && memcmp(d, id, 32) != 0) return refuse(v, R_DIGEST, pos);
        }
        if (type == 11 && ilen > 48) {
            uint8_t d[32];
            sha2(id + 48, ilen - 48, NULL, 0, d);
            if (CHECK(CHK_INPUT_DIGEST) && memcmp(d, id + 16, 32) != 0) return refuse(v, R_DIGEST, pos);
        }
        if (type == 16) {
            const uint8_t *before = id + 136, *after = id + 168;
            if (CHECK(CHK_ARGUS_CONT) && have_argus && memcmp(before, argus_after, 32) != 0)
                return refuse(v, R_DIGEST, pos);
            if (CHECK(CHK_ARGUS_LINK)) {
                uint8_t d[32];
                if (id[128]) sha2(before, 32, id, 128, d); else memcpy(d, before, 32);
                if (memcmp(d, after, 32) != 0) return refuse(v, R_DIGEST, pos);
            }
            memcpy(argus_after, after, 32);
            have_argus = 1;
        }

        /* record digest (chain) and compared digest (replay) */
        sha2(r, REC_HDR_SIZE + (size_t)ilen + alen, NULL, 0, prev);
        {
            uint8_t h[16];
            sha256 s;
            memcpy(h, r, 4);              /* type, subsystem */
            memcpy(h + 4, r + 16, 8);     /* seq */
            memcpy(h + 12, r + 4, 4);     /* ident_len */
            sha_init(&s);
            sha_update(&s, "AIEN_TRN1_CMP", 13);
            sha_update(&s, h, 16);
            sha_update(&s, id, ilen);
            sha_final(&s, v->cmp[seq]);
            v->subsys[seq] = sub;
        }
        o += REC_HDR_SIZE + (size_t)ilen + alen;
        seq = pos;

        if (type == T_END) {
            if (CHECK(CHK_END_COUNT) && g64(id) != pos) return refuse(v, R_GAP, pos);
            if (CHECK(CHK_TRAILING) && o != n) return refuse(v, R_LENGTH, pos + 1);
            v->records = pos;
            memcpy(v->final_digest, prev, 32);
            return R_OK;
        }
    }
}

/* ---- output -------------------------------------------------------------- */
static void hex(char *out, const uint8_t *d) {
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", d[i]);
}

static void verdict_line(const Verdict *v, char *buf, size_t cap) {
    if (v->code == R_OK) {
        char rh[65], fh[65];
        hex(rh, v->run_id); hex(fh, v->final_digest);
        snprintf(buf, cap, "ok records=%llu run=%s final=%s", (unsigned long long)v->records, rh, fh);
    } else {
        snprintf(buf, cap, "refuse %d event=%llu", v->code, (unsigned long long)v->event);
    }
}

static int compare_line(const Verdict *e, const Verdict *a, char *buf, size_t cap) {
    if (e->code) { snprintf(buf, cap, "refuse expected %d event=%llu", e->code, (unsigned long long)e->event); return 1; }
    if (a->code) { snprintf(buf, cap, "refuse actual %d event=%llu", a->code, (unsigned long long)a->event); return 1; }
    uint64_t m = e->records < a->records ? e->records : a->records;
    for (uint64_t i = 0; i < m; i++) {
        if (memcmp(e->cmp[i], a->cmp[i], 32) != 0) {
            char eh[65], ah[65];
            hex(eh, e->cmp[i]); hex(ah, a->cmp[i]);
            snprintf(buf, cap, "DIVERGENCE event=%llu expected=%s actual=%s subsystem=%s",
                     (unsigned long long)(i + 1), eh, ah, subsys_name(e->subsys[i]));
            return 1;
        }
    }
    /* Both end in END at the same position with equal compared digests, so the
     * counts are equal here (END's identity carries the count). */
    snprintf(buf, cap, "MATCH through %llu", (unsigned long long)m);
    return 0;
}

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    uint8_t *p = NULL;
    size_t cap = 0, len = 0, k;
    if (!f) return NULL;
    do {
        if (len == cap) {
            uint8_t *q = realloc(p, cap = cap ? cap * 2 : 4096);
            if (!q) { free(p); fclose(f); return NULL; }
            p = q;
        }
        k = fread(p + len, 1, cap - len, f);
        len += k;
    } while (k);
    fclose(f);
    *n = len;
    return p ? p : calloc(1, 1);
}

static int load(const char *path, Verdict *v) {
    size_t n;
    uint8_t *b = slurp(path, &n);
    if (!b) { fprintf(stderr, "cannot read %s\n", path); exit(2); }
    verify(b, n, v);
    free(b);
    return v->code;
}
static void drop(Verdict *v) { free(v->cmp); free(v->subsys); }

static void rstrip(char *s) { size_t n = strlen(s); while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = 0; }

static int corpus(const char *dir) {
    char path[4096], line[8192], got[512];
    unsigned pass = 0, fail = 0;
    FILE *f;

    snprintf(path, sizeof path, "%s/expected.txt", dir);
    if (!(f = fopen(path, "r"))) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *sp;
        Verdict v;
        rstrip(line);
        if (!line[0] || line[0] == '#') continue;
        if (!(sp = strchr(line, ' '))) { fprintf(stderr, "bad line: %s\n", line); fail++; continue; }
        *sp = 0;
        snprintf(path, sizeof path, "%s/%s", dir, line);
        load(path, &v);
        verdict_line(&v, got, sizeof got);
        drop(&v);
        if (strcmp(got, sp + 1) == 0) pass++;
        else { fail++; printf("MISMATCH %s\n  expected: %s\n  got:      %s\n", line, sp + 1, got); }
    }
    fclose(f);

    snprintf(path, sizeof path, "%s/compare.txt", dir);
    if (!(f = fopen(path, "r"))) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *s1, *s2, p2[4096];
        Verdict e, a;
        rstrip(line);
        if (!line[0] || line[0] == '#') continue;
        if (!(s1 = strchr(line, ' ')) || !(s2 = strchr(s1 + 1, ' '))) { fprintf(stderr, "bad line: %s\n", line); fail++; continue; }
        *s1 = 0; *s2 = 0;
        snprintf(path, sizeof path, "%s/%s", dir, line);
        snprintf(p2, sizeof p2, "%s/%s", dir, s1 + 1);
        load(path, &e); load(p2, &a);
        compare_line(&e, &a, got, sizeof got);
        drop(&e); drop(&a);
        if (strcmp(got, s2 + 1) == 0) pass++;
        else { fail++; printf("MISMATCH %s %s\n  expected: %s\n  got:      %s\n", line, s1 + 1, s2 + 1, got); }
    }
    fclose(f);
    printf("TRN1_CONFORMANCE impl=c pass=%u fail=%u\n", pass, fail);
    return fail || !pass ? 1 : 0;
}

int main(int argc, char **argv) {
    char out[512];
    if (argc == 2 && argv[1][0] != '-') {
        Verdict v;
        int rc = load(argv[1], &v);
        verdict_line(&v, out, sizeof out);
        puts(out);
        drop(&v);
        return rc ? 1 : 0;
    }
    if (argc == 4 && strcmp(argv[1], "--compare") == 0) {
        Verdict e, a;
        int rc;
        load(argv[2], &e); load(argv[3], &a);
        rc = compare_line(&e, &a, out, sizeof out);
        puts(out);
        drop(&e); drop(&a);
        return rc;
    }
    if (argc == 3 && strcmp(argv[1], "--corpus") == 0) return corpus(argv[2]);
    fprintf(stderr, "usage: trn1_verify FILE | --compare EXP ACT | --corpus DIR\n");
    return 2;
}
