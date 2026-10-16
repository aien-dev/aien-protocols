/* pst_verify.c: reference checker for PST1, the Pi-Spark task message.
 * Spec: ../SPEC.md (contract 0.1.0, wire version 1): sections 4 and 7 for one
 * message, section 10 for a recorded session.
 *
 * Self-contained C99: its own SHA-256 (FIPS 180-4), libc only, no heap
 * anywhere (static buffers), no clock. The decoder pst_decode() is a pure
 * function of one read-only buffer; the encoder pst_encode() is a pure
 * function of one message struct. It exists to pin the format with vectors,
 * not to be linked into a runtime.
 *
 * Usage:
 *   pst_verify FILE                print one verdict line
 *   pst_verify --corpus DIR        check every DIR/expected.txt line, re-encode
 *                                  every accepted message and require the same
 *                                  bytes, then every DIR/sessions/expected.txt line;
 *                                  print PST1_CONFORMANCE impl=c pass=N fail=M
 *   pst_verify --session FILE      check one recorded session (spec section 10)
 *   pst_verify --make-vectors DIR  write the vector files, DIR/expected.txt and
 *                                  DIR/sessions/ (the directory must exist)
 *   pst_verify --session-fuzz SEED COUNT FILE...
 *                                  COUNT seeded reorderings, drops and duplications
 *                                  of the given sessions; prints the verdict counts
 *                                  and one digest of all verdict lines
 *
 * Verdict line (the format expected.txt pins):
 *   ok type=T version=V cause=H64 origin=H64 objective=H64 subject=H64
 *      parent=H32 task=H32 idem=H32 ordinal=N effect=E len=L digest=H64
 *   refuse CODE                    (CODE is a name from SPEC.md section 7)
 * (one line; Hn is n lower-case hex digits).
 * Session verdict line: ok steps=N tasks=T, or refuse CODE step=N.
 *
 * Exit status: 0 on accept / all corpus lines agree, 1 otherwise, 2 on usage
 * or I/O error.
 *
 * Mutation hooks: building with -DPST_MUTANT=K disables check K (the CHK_*
 * numbers below). tools/mutate-verifier.sh builds every mutant and requires
 * the vectors to fail each one, which shows every check is exercised.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PST_MUTANT
#define PST_MUTANT 0
#endif
#define CHECK(k) (PST_MUTANT != (k))

enum {
    CHK_MAX_TOTAL = 1, CHK_MAGIC, CHK_DOWNGRADE, CHK_VERSION, CHK_TYPE,
    CHK_RESERVED0, CHK_RESERVED1, CHK_PAYLOAD_SHORT, CHK_TRAILING, CHK_EFFECT,
    CHK_CAUSE, CHK_TASK, CHK_IDEM, CHK_OBJECTIVE, CHK_DIGEST,
    /* session rules (spec section 10.3) */
    CHK_S_SIDE, CHK_S_SUBJECT, CHK_S_IDEM_OTHER, CHK_S_IDEM_SAME, CHK_S_UNKNOWN_TASK,
    CHK_S_CONTEXT, CHK_S_REPEAT_REQUEST, CHK_S_GAP, CHK_S_REPEAT, CHK_S_SECOND_FINAL,
    CHK_S_ORDER, CHK_LAST
};

/* ---- refusal codes (spec section 7) ------------------------------------- */
enum {
    PST_OK = 0, PST_BAD_MAGIC, PST_BAD_VERSION, PST_DOWNGRADE, PST_BAD_TYPE,
    PST_WRONG_SIDE, PST_BAD_LENGTH, PST_TRAILING_BYTES, PST_RESERVED_NONZERO,
    PST_NO_CAUSE, PST_NO_TASK, PST_NO_OBJECTIVE, PST_DIGEST_MISMATCH,
    PST_BAD_EFFECT_CLASS, PST_SUBJECT_MISMATCH, PST_BAD_ORDER, PST_SECOND_FINAL,
    PST_ORDINAL_GAP, PST_ORDINAL_REPEAT, PST_IDEMPOTENCE_CONFLICT, PST_UNKNOWN_TASK,
    PST_CONTEXT_MISMATCH, PST_SESSION_FULL, PST_BAD_RECORDING, PST_CODE_COUNT
};
static const char *const code_names[PST_CODE_COUNT] = {
    "OK", "PST_BAD_MAGIC", "PST_BAD_VERSION", "PST_DOWNGRADE", "PST_BAD_TYPE",
    "PST_WRONG_SIDE", "PST_BAD_LENGTH", "PST_TRAILING_BYTES", "PST_RESERVED_NONZERO",
    "PST_NO_CAUSE", "PST_NO_TASK", "PST_NO_OBJECTIVE", "PST_DIGEST_MISMATCH",
    "PST_BAD_EFFECT_CLASS", "PST_SUBJECT_MISMATCH", "PST_BAD_ORDER", "PST_SECOND_FINAL",
    "PST_ORDINAL_GAP", "PST_ORDINAL_REPEAT", "PST_IDEMPOTENCE_CONFLICT", "PST_UNKNOWN_TASK",
    "PST_CONTEXT_MISMATCH", "PST_SESSION_FULL", "PST_BAD_RECORDING"
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
static void sha_once(const void *p, size_t n, uint8_t out[32]) {
    sha256 s; sha_init(&s); sha_update(&s, p, n); sha_final(&s, out);
}

/* ---- big-endian helpers -------------------------------------------------- */
static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t g32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void p32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static int all_zero(const uint8_t *p, size_t n) { while (n--) if (*p++) return 0; return 1; }

/* ---- the format (spec section 4) ---------------------------------------- */
#define PST_HDR       224u
#define PST_MAX_PAY   800u
#define PST_MAX_MSG   1024u
#define PST_VERSION   1u
#define PST_MAX_TYPE  14u
#define T_REQUEST     1u

enum {
    O_MAGIC = 0, O_VERSION = 4, O_TYPE = 5, O_RES0 = 6, O_CAUSE = 8, O_ORIGIN = 40,
    O_OBJECTIVE = 72, O_SUBJECT = 104, O_PARENT = 136, O_TASK = 152, O_IDEM = 168,
    O_ORDINAL = 184, O_EFFECT = 188, O_RES1 = 189, O_PLEN = 190, O_DIGEST = 192
};

typedef struct {
    uint8_t version, type;
    uint8_t cause[32], origin[32], objective[32], subject[32];
    uint8_t parent[16], task[16], idem[16];
    uint32_t ordinal;
    uint8_t effect;
    uint16_t payload_len;
    uint8_t digest[32];
    const uint8_t *payload;   /* points into the decoded buffer */
} pst_msg;

/* Decode and check one message (spec section 4.1 check order). Reads only
 * b[0..n); writes only *m. Returns PST_OK or the first refusal code. */
static int pst_decode(const uint8_t *b, size_t n, pst_msg *m) {
    size_t body;
    uint8_t d[32];

    memset(m, 0, sizeof *m);
    /* 1. length bounds (the short bound is not a mutation point: it guards every read) */
    if (n < PST_HDR) return PST_BAD_LENGTH;
    if (CHECK(CHK_MAX_TOTAL) && n > PST_MAX_MSG) return PST_BAD_LENGTH;
    /* 2. magic */
    if (CHECK(CHK_MAGIC) && memcmp(b + O_MAGIC, "PST1", 4) != 0) return PST_BAD_MAGIC;
    /* 3. version */
    if (CHECK(CHK_DOWNGRADE) && b[O_VERSION] < PST_VERSION) return PST_DOWNGRADE;
    if (CHECK(CHK_VERSION) && b[O_VERSION] > PST_VERSION) return PST_BAD_VERSION;
    /* 4. type */
    if (CHECK(CHK_TYPE) && (b[O_TYPE] == 0 || b[O_TYPE] > PST_MAX_TYPE)) return PST_BAD_TYPE;
    /* 5. reserved */
    if (CHECK(CHK_RESERVED0) && !all_zero(b + O_RES0, 2)) return PST_RESERVED_NONZERO;
    if (CHECK(CHK_RESERVED1) && b[O_RES1] != 0) return PST_RESERVED_NONZERO;
    /* 6, 7. payload length against the bytes present */
    m->payload_len = g16(b + O_PLEN);
    body = n - PST_HDR;
    if (CHECK(CHK_PAYLOAD_SHORT) && body < m->payload_len) return PST_BAD_LENGTH;
    if (CHECK(CHK_TRAILING) && body > m->payload_len) return PST_TRAILING_BYTES;
    /* 8..11. field rules */
    if (CHECK(CHK_EFFECT) && b[O_EFFECT] > 2) return PST_BAD_EFFECT_CLASS;
    if (CHECK(CHK_CAUSE) && all_zero(b + O_CAUSE, 32)) return PST_NO_CAUSE;
    if (CHECK(CHK_TASK) && all_zero(b + O_TASK, 16)) return PST_NO_TASK;
    if (CHECK(CHK_IDEM) && all_zero(b + O_IDEM, 16)) return PST_NO_TASK;
    if (CHECK(CHK_OBJECTIVE) && b[O_TYPE] == T_REQUEST && all_zero(b + O_OBJECTIVE, 32)) return PST_NO_OBJECTIVE;
    /* 12. payload digest (over the bytes present, so a mutant never reads past n) */
    sha_once(b + PST_HDR, body < m->payload_len ? body : m->payload_len, d);
    if (CHECK(CHK_DIGEST) && memcmp(d, b + O_DIGEST, 32) != 0) return PST_DIGEST_MISMATCH;

    m->version = b[O_VERSION];
    m->type = b[O_TYPE];
    memcpy(m->cause, b + O_CAUSE, 32);
    memcpy(m->origin, b + O_ORIGIN, 32);
    memcpy(m->objective, b + O_OBJECTIVE, 32);
    memcpy(m->subject, b + O_SUBJECT, 32);
    memcpy(m->parent, b + O_PARENT, 16);
    memcpy(m->task, b + O_TASK, 16);
    memcpy(m->idem, b + O_IDEM, 16);
    m->ordinal = g32(b + O_ORDINAL);
    m->effect = b[O_EFFECT];
    memcpy(m->digest, b + O_DIGEST, 32);
    m->payload = b + PST_HDR;
    return PST_OK;
}

/* Encode one message. Writes the fields exactly as given (the digest is not
 * recomputed, so a bad digest can be encoded on purpose). Returns the byte
 * count, or 0 if it does not fit in cap or the payload is over the cap. */
static size_t pst_encode(const pst_msg *m, uint8_t *out, size_t cap) {
    size_t n = PST_HDR + (size_t)m->payload_len;
    if (m->payload_len > PST_MAX_PAY || n > cap) return 0;
    memset(out, 0, PST_HDR);
    memcpy(out + O_MAGIC, "PST1", 4);
    out[O_VERSION] = m->version;
    out[O_TYPE] = m->type;
    memcpy(out + O_CAUSE, m->cause, 32);
    memcpy(out + O_ORIGIN, m->origin, 32);
    memcpy(out + O_OBJECTIVE, m->objective, 32);
    memcpy(out + O_SUBJECT, m->subject, 32);
    memcpy(out + O_PARENT, m->parent, 16);
    memcpy(out + O_TASK, m->task, 16);
    memcpy(out + O_IDEM, m->idem, 16);
    p32(out + O_ORDINAL, m->ordinal);
    out[O_EFFECT] = m->effect;
    p16(out + O_PLEN, m->payload_len);
    memcpy(out + O_DIGEST, m->digest, 32);
    if (m->payload_len) memcpy(out + PST_HDR, m->payload, m->payload_len);
    return n;
}

/* ---- session rules (spec section 10) --------------------------------------- */
#define SIDE_PI       1u
#define SIDE_SPARK    2u
#define MAX_TASKS     16u
enum { ST_REQUESTED = 1, ST_ACCEPTED, ST_QUEUED, ST_RUNNING, ST_FINAL };

typedef struct {
    uint8_t task[16], idem[16], req_digest[32];
    uint8_t cause[32], origin[32], objective[32], parent[16], effect;
    int state;
    uint64_t next_ordinal[3];  /* indexed by side; [0] unused */
} task_slot;

typedef struct { int code; unsigned long step, tasks; } session_verdict;

static int side_of(uint8_t type) { return type == 1 || type == 13 || type == 14 ? SIDE_PI : SIDE_SPARK; }

static int same_context(const task_slot *t, const pst_msg *m) {
    return memcmp(t->cause, m->cause, 32) == 0 && memcmp(t->origin, m->origin, 32) == 0 &&
           memcmp(t->objective, m->objective, 32) == 0 && memcmp(t->parent, m->parent, 16) == 0 &&
           memcmp(t->idem, m->idem, 16) == 0 && t->effect == m->effect;
}

/* Allowed step for one task (spec section 10.2). Returns the new state, or
 * 0 if the type is not allowed in state s. */
static int next_state(int s, uint8_t type) {
    switch (type) {
    case 2: return s == ST_REQUESTED ? ST_ACCEPTED : 0;
    case 3: return s == ST_ACCEPTED ? ST_QUEUED : 0;
    case 4: return s == ST_ACCEPTED || s == ST_QUEUED ? ST_RUNNING : 0;
    case 5: return s == ST_RUNNING ? ST_RUNNING : 0;
    case 7: return s == ST_RUNNING ? ST_FINAL : 0;
    case 8: case 9: return s != ST_FINAL ? ST_FINAL : 0;
    case 13: case 14: return s;
    default: return 0;   /* types 6, 10, 11, 12: no session rule yet */
    }
}

static int srefuse(session_verdict *v, int code, unsigned long step) { v->code = code; v->step = step; return code; }

/* Check one recorded session (spec section 10.4 container). Reads only
 * b[0..n); keeps its task table on the stack. Returns PST_OK or the first
 * refusal code, with the 1-based step in v->step. */
static int session_check(const uint8_t *b, size_t n, session_verdict *v) {
    task_slot tasks[MAX_TASKS];
    unsigned ntasks = 0;
    uint8_t subject[32];
    size_t o = 4;
    unsigned long step = 0;

    memset(v, 0, sizeof *v);
    memset(tasks, 0, sizeof tasks);
    if (n < 4 || memcmp(b, "PSS1", 4) != 0) return srefuse(v, PST_BAD_RECORDING, 0);
    while (o < n) {
        pst_msg m;
        task_slot *t = NULL;
        unsigned side, len, i;
        int code, ns, repeat = 0;

        step++;
        /* the container (a guard, not a protocol rule) */
        if (n - o < 3) return srefuse(v, PST_BAD_RECORDING, step);
        side = b[o];
        len = g16(b + o + 1);
        if ((side != SIDE_PI && side != SIDE_SPARK) || n - o - 3 < len) return srefuse(v, PST_BAD_RECORDING, step);
        /* 1. the single-message checks */
        code = pst_decode(b + o + 3, len, &m);
        o += 3 + (size_t)len;
        if (code != PST_OK) return srefuse(v, code, step);
        /* 2. side */
        if (CHECK(CHK_S_SIDE) && side_of(m.type) != (int)side) return srefuse(v, PST_WRONG_SIDE, step);
        /* 3. subject */
        if (step == 1) memcpy(subject, m.subject, 32);
        else if (CHECK(CHK_S_SUBJECT) && memcmp(subject, m.subject, 32) != 0) return srefuse(v, PST_SUBJECT_MISMATCH, step);
        /* 4. task */
        for (i = 0; i < ntasks; i++)
            if (memcmp(tasks[i].task, m.task, 16) == 0) { t = &tasks[i]; break; }
        if (m.type == T_REQUEST && !t) {
            for (i = 0; i < ntasks; i++)
                if (CHECK(CHK_S_IDEM_OTHER) && memcmp(tasks[i].idem, m.idem, 16) == 0)
                    return srefuse(v, PST_IDEMPOTENCE_CONFLICT, step);
            if (ntasks == MAX_TASKS) return srefuse(v, PST_SESSION_FULL, step);
            t = &tasks[ntasks++];
            memcpy(t->task, m.task, 16); memcpy(t->idem, m.idem, 16); memcpy(t->req_digest, m.digest, 32);
            memcpy(t->cause, m.cause, 32); memcpy(t->origin, m.origin, 32);
            memcpy(t->objective, m.objective, 32); memcpy(t->parent, m.parent, 16);
            t->effect = m.effect;
            t->state = ST_REQUESTED;
        } else if (m.type == T_REQUEST) {
            repeat = 1;
            if (CHECK(CHK_S_IDEM_SAME) && (memcmp(t->idem, m.idem, 16) != 0 || memcmp(t->req_digest, m.digest, 32) != 0))
                return srefuse(v, PST_IDEMPOTENCE_CONFLICT, step);
        } else if (!t) {
            if (CHECK(CHK_S_UNKNOWN_TASK)) return srefuse(v, PST_UNKNOWN_TASK, step);
            continue;   /* mutant only: ignore the message */
        }
        /* 5. context; a recognised repeat of the request stops here */
        if (CHECK(CHK_S_CONTEXT) && !same_context(t, &m)) return srefuse(v, PST_CONTEXT_MISMATCH, step);
        if (repeat && CHECK(CHK_S_REPEAT_REQUEST)) continue;
        /* 6. ordinal, per task and side */
        if (CHECK(CHK_S_GAP) && m.ordinal > t->next_ordinal[side]) return srefuse(v, PST_ORDINAL_GAP, step);
        if (CHECK(CHK_S_REPEAT) && m.ordinal < t->next_ordinal[side]) return srefuse(v, PST_ORDINAL_REPEAT, step);
        t->next_ordinal[side] = (uint64_t)m.ordinal + 1;
        /* 7. order */
        if (m.type == T_REQUEST) continue;   /* the new task is REQUESTED */
        ns = next_state(t->state, m.type);
        if (!ns) {
            if (CHECK(CHK_S_SECOND_FINAL) && t->state == ST_FINAL && (m.type == 7 || m.type == 8 || m.type == 9))
                return srefuse(v, PST_SECOND_FINAL, step);
            if (CHECK(CHK_S_ORDER)) return srefuse(v, PST_BAD_ORDER, step);
            continue;   /* mutant only: keep the state */
        }
        t->state = ns;
    }
    v->step = step;
    v->tasks = ntasks;
    return v->code = PST_OK;
}

/* ---- verdict line ---------------------------------------------------------- */
static char *hexw(char *o, const uint8_t *p, size_t n) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { *o++ = hx[p[i] >> 4]; *o++ = hx[p[i] & 15]; }
    *o = 0;
    return o;
}
static void verdict_line(int code, const pst_msg *m, char *buf, size_t cap) {
    char c[65], o[65], ob[65], s[65], pa[33], t[33], k[33], d[65];
    if (code != PST_OK) {
        snprintf(buf, cap, "refuse %s", code > 0 && code < PST_CODE_COUNT ? code_names[code] : "PST_UNKNOWN_CODE");
        return;
    }
    hexw(c, m->cause, 32); hexw(o, m->origin, 32); hexw(ob, m->objective, 32); hexw(s, m->subject, 32);
    hexw(pa, m->parent, 16); hexw(t, m->task, 16); hexw(k, m->idem, 16); hexw(d, m->digest, 32);
    snprintf(buf, cap, "ok type=%u version=%u cause=%s origin=%s objective=%s subject=%s parent=%s task=%s idem=%s ordinal=%lu effect=%u len=%u digest=%s",
             m->type, m->version, c, o, ob, s, pa, t, k, (unsigned long)m->ordinal, m->effect, m->payload_len, d);
}
static void session_line(const session_verdict *v, char *buf, size_t cap) {
    if (v->code == PST_OK) snprintf(buf, cap, "ok steps=%lu tasks=%lu", v->step, v->tasks);
    else snprintf(buf, cap, "refuse %s step=%lu", v->code > 0 && v->code < PST_CODE_COUNT ? code_names[v->code] : "PST_UNKNOWN_CODE", v->step);
}

/* ---- file I/O (outside the decoder) --------------------------------------- */
#define FILE_CAP 65536u
static uint8_t file_buf[FILE_CAP];

/* Reads the whole file into file_buf. Returns 0, or -1 on I/O error or a
 * file larger than FILE_CAP (no vector is that large). */
static int slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    size_t k;
    if (!f) return -1;
    k = fread(file_buf, 1, FILE_CAP, f);
    if (k == FILE_CAP && fgetc(f) != EOF) { fclose(f); return -1; }
    fclose(f);
    *n = k;
    return 0;
}

static int check_file(const char *path, char *line, size_t cap, int *roundtrip_ok) {
    static uint8_t again[PST_MAX_MSG];
    pst_msg m;
    size_t n, k;
    int code;
    if (slurp(path, &n)) { fprintf(stderr, "cannot read %s\n", path); return -1; }
    code = pst_decode(file_buf, n, &m);
    verdict_line(code, &m, line, cap);
    *roundtrip_ok = 1;
    if (code == PST_OK) {
        k = pst_encode(&m, again, sizeof again);
        *roundtrip_ok = k == n && memcmp(again, file_buf, n) == 0;
    }
    return code;
}

static void rstrip(char *s) { size_t n = strlen(s); while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = 0; }

static int corpus(const char *dir) {
    char path[4096], line[1024], got[1024];
    unsigned pass = 0, fail = 0;
    FILE *f;

    snprintf(path, sizeof path, "%s/expected.txt", dir);
    if (!(f = fopen(path, "r"))) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *sp;
        int rt;
        rstrip(line);
        if (!line[0] || line[0] == '#') continue;
        if (!(sp = strchr(line, ' '))) { fprintf(stderr, "bad line: %s\n", line); fail++; continue; }
        *sp = 0;
        snprintf(path, sizeof path, "%s/%s", dir, line);
        if (check_file(path, got, sizeof got, &rt) < 0) { fail++; continue; }
        if (strcmp(got, sp + 1) != 0) { fail++; printf("MISMATCH %s\n  expected: %s\n  got:      %s\n", line, sp + 1, got); }
        else if (!rt) { fail++; printf("ROUNDTRIP_MISMATCH %s\n", line); }
        else pass++;
    }
    fclose(f);

    /* recorded sessions (spec section 10), when the directory has them */
    snprintf(path, sizeof path, "%s/sessions/expected.txt", dir);
    if ((f = fopen(path, "r"))) {
        while (fgets(line, sizeof line, f)) {
            char *sp;
            size_t n;
            session_verdict v;
            rstrip(line);
            if (!line[0] || line[0] == '#') continue;
            if (!(sp = strchr(line, ' '))) { fprintf(stderr, "bad line: %s\n", line); fail++; continue; }
            *sp = 0;
            snprintf(path, sizeof path, "%s/sessions/%s", dir, line);
            if (slurp(path, &n)) { fprintf(stderr, "cannot read %s\n", path); fail++; continue; }
            session_check(file_buf, n, &v);
            session_line(&v, got, sizeof got);
            if (strcmp(got, sp + 1) != 0) { fail++; printf("MISMATCH sessions/%s\n  expected: %s\n  got:      %s\n", line, sp + 1, got); }
            else pass++;
        }
        fclose(f);
    }
    printf("PST1_CONFORMANCE impl=c pass=%u fail=%u\n", pass, fail);
    return fail || !pass ? 1 : 0;
}

/* ---- seeded random sessions (reorder, drop, duplicate) -------------------- */
#define FUZZ_FILES 8u
#define FUZZ_RECS  64u
static uint8_t fuzz_src[FUZZ_FILES][8192];
static size_t fuzz_len[FUZZ_FILES];
static uint8_t fuzz_out[8192 + PST_MAX_MSG + 3];

static uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/* Record boundaries of a well-formed recording; returns the count. */
static unsigned records(const uint8_t *b, size_t n, size_t *off, size_t *len) {
    size_t o = 4;
    unsigned k = 0;
    while (o + 3 <= n && k < FUZZ_RECS) {
        size_t l = 3 + (size_t)g16(b + o + 1);
        if (l > n - o) break;
        off[k] = o; len[k] = l; k++;
        o += l;
    }
    return k;
}

static int session_fuzz(uint64_t seed, unsigned long count, int nfiles, char **files) {
    static const char *const ops[3] = { "reorder", "drop", "duplicate" };
    unsigned long by_op[3] = { 0, 0, 0 }, ok = 0, refused = 0, i;
    uint64_t rng = seed;
    sha256 all;
    uint8_t d[32];
    char hx[65], line[128];

    if (nfiles < 1 || nfiles > (int)FUZZ_FILES) { fprintf(stderr, "need 1 to %u files\n", FUZZ_FILES); return 2; }
    for (int k = 0; k < nfiles; k++) {
        size_t n;
        if (slurp(files[k], &n) || n > sizeof fuzz_src[k]) { fprintf(stderr, "cannot read %s\n", files[k]); return 2; }
        memcpy(fuzz_src[k], file_buf, n);
        fuzz_len[k] = n;
    }
    sha_init(&all);
    for (i = 0; i < count; i++) {
        size_t off[FUZZ_RECS], len[FUZZ_RECS], o = 4;
        unsigned f = (unsigned)(splitmix(&rng) % (uint64_t)nfiles), nr, op, a, b2, r;
        const uint8_t *src = fuzz_src[f];
        session_verdict v;

        nr = records(src, fuzz_len[f], off, len);
        if (nr < 2) { fprintf(stderr, "%s: fewer than 2 records\n", files[f]); return 2; }
        op = (unsigned)(splitmix(&rng) % 3);
        a = (unsigned)(splitmix(&rng) % nr);
        b2 = (unsigned)(splitmix(&rng) % (nr - 1));
        if (b2 >= a) b2++;                          /* b2 != a */
        memcpy(fuzz_out, "PSS1", 4);
        for (r = 0; r < nr; r++) {
            unsigned take = r;
            if (op == 0) take = r == a ? b2 : r == b2 ? a : r;   /* swap a and b2 */
            if (op == 1 && r == a) continue;                      /* drop a */
            memcpy(fuzz_out + o, src + off[take], len[take]); o += len[take];
            if (op == 2 && r == b2) { memcpy(fuzz_out + o, src + off[a], len[a]); o += len[a]; }  /* copy of a after b2 */
        }
        session_check(fuzz_out, o, &v);
        session_line(&v, line, sizeof line);
        if (v.code == PST_OK) ok++; else refused++;
        by_op[op]++;
        sha_update(&all, line, strlen(line));
        sha_update(&all, "\n", 1);
    }
    sha_final(&all, d);
    hexw(hx, d, 32);
    printf("PST1_SESSION_FUZZ seed=%llu count=%lu %s=%lu %s=%lu %s=%lu ok=%lu refused=%lu verdicts=%s\n",
           (unsigned long long)seed, count, ops[0], by_op[0], ops[1], by_op[1], ops[2], by_op[2], ok, refused, hx);
    return 0;
}

/* ---- vector generator ------------------------------------------------------ */
/* Every vector starts from one well-formed message and changes one thing. The
 * expected line for an accepted vector is built from the generator's own
 * struct, not from pst_decode, so the decoder is checked against the intent. */
static uint8_t gen_payload[PST_MAX_PAY + 8];

static void fill(uint8_t *p, size_t n, uint8_t seed) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + 7 * i); }

static void base(pst_msg *m, uint8_t type, const char *text) {
    size_t len = strlen(text);
    memset(m, 0, sizeof *m);
    m->version = PST_VERSION;
    m->type = type;
    fill(m->cause, 32, 0xC1);
    fill(m->origin, 32, 0x0A);
    fill(m->objective, 32, 0x0B);
    fill(m->subject, 32, 0x5B);
    fill(m->task, 16, 0x7A);
    fill(m->idem, 16, 0x1D);
    m->ordinal = type == T_REQUEST ? 0 : 1;
    m->effect = 1;
    memcpy(gen_payload, text, len);
    m->payload = gen_payload;
    m->payload_len = (uint16_t)len;
    sha_once(gen_payload, len, m->digest);
}

static FILE *gen_expected;
static int gen_fail;

static void emit(const char *dir, const char *name, const uint8_t *b, size_t n, const char *expect) {
    char path[4096];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if (!(f = fopen(path, "wb")) || fwrite(b, 1, n, f) != n || fclose(f) != 0) {
        fprintf(stderr, "cannot write %s\n", path);
        gen_fail = 1;
        return;
    }
    fprintf(gen_expected, "%s %s\n", name, expect);
}

static void emit_ok(const char *dir, const char *name, const pst_msg *m) {
    static uint8_t out[PST_MAX_MSG];
    char line[1024];
    size_t n = pst_encode(m, out, sizeof out);
    verdict_line(PST_OK, m, line, sizeof line);
    emit(dir, name, out, n, line);
}

static void emit_bad(const char *dir, const char *name, const pst_msg *m, int at, int value, long extra, const char *code) {
    static uint8_t out[PST_MAX_MSG + 64];
    char line[128];
    size_t n = pst_encode(m, out, sizeof out);
    if (at >= 0) out[at] = (uint8_t)value;
    if (extra < 0) n -= (size_t)(-extra);            /* drop bytes from the end */
    else for (long i = 0; i < extra; i++) out[n++] = (uint8_t)(0xE0 + i);
    snprintf(line, sizeof line, "refuse %s", code);
    emit(dir, name, out, n, line);
}

/* ---- recorded-session generator (spec section 10.4) ---------------------- */
static uint8_t sess[16384];
static size_t sess_n;

static void s_begin(void) { memcpy(sess, "PSS1", 4); sess_n = 4; }

/* One message of task number tn (task id and idempotence key derive from tn). */
static void mk(pst_msg *m, uint8_t type, unsigned tn, uint32_t ordinal, const char *text) {
    base(m, type, text);
    fill(m->task, 16, (uint8_t)(0x7A + 16 * tn));
    fill(m->idem, 16, (uint8_t)(0x1D + 16 * tn));
    m->task[15] ^= (uint8_t)tn;      /* keeps task 16 apart from task 0 */
    m->idem[15] ^= (uint8_t)tn;
    m->ordinal = ordinal;
}

static void s_add(unsigned side, const pst_msg *m) {
    size_t n = pst_encode(m, sess + sess_n + 3, sizeof sess - sess_n - 3);
    if (!n) { gen_fail = 1; return; }
    sess[sess_n] = (uint8_t)side;
    p16(sess + sess_n + 1, (uint16_t)n);
    sess_n += 3 + n;
}

/* Shorthand: build and add one message. */
static void s_msg(unsigned side, uint8_t type, unsigned tn, uint32_t ordinal, const char *text) {
    pst_msg m;
    mk(&m, type, tn, ordinal, text);
    s_add(side, &m);
}

static void s_emit(const char *dir, const char *name, const char *expect) {
    char sub[4096];
    snprintf(sub, sizeof sub, "%s/sessions", dir);
    emit(sub, name, sess, sess_n, expect);
}

#define PI SIDE_PI
#define SP SIDE_SPARK
static const char RESULT32[] = "result digest stand-in: 32 bytes";   /* 32 bytes of payload */

/* request, accepted, running: the opening of a normal task (Spark ordinals 0, 1). */
static void s_open(unsigned tn) {
    s_msg(PI, 1, tn, 0, "Write a short poem about rain.");
    s_msg(SP, 2, tn, 0, "");
    s_msg(SP, 4, tn, 1, "");
}

static int make_sessions(const char *dir) {
    char path[4096];
    pst_msg m;
    snprintf(path, sizeof path, "%s/sessions/expected.txt", dir);
    if (!(gen_expected = fopen(path, "w"))) { fprintf(stderr, "cannot write %s\n", path); return 2; }
    fprintf(gen_expected,
        "# PST1 recorded sessions. Spec: ../../SPEC.md section 10 (rules) and 10.4 (container).\n"
        "# Line: <file> ok steps=N tasks=T | <file> refuse <code> step=N (1-based message position)\n"
        "# Generated by tools/pst_verify.c --make-vectors; do not edit by hand.\n");

    /* accepted sessions */
    s_begin(); s_open(0);
    s_msg(SP, 5, 0, 2, "Rain on the "); s_msg(SP, 5, 0, 3, "tin roof, "); s_msg(SP, 5, 0, 4, "soft and steady.");
    s_msg(SP, 7, 0, 5, RESULT32);
    s_emit(dir, "ok-normal-life.pss", "ok steps=7 tasks=1");

    s_begin();
    s_msg(PI, 1, 0, 0, "Index the new receipts.");
    s_msg(PI, 1, 1, 0, "Rebuild the map.");
    s_msg(SP, 2, 0, 0, "");
    s_msg(SP, 8, 1, 0, "busy");
    s_msg(SP, 3, 0, 1, "");
    s_msg(PI, 13, 0, 1, "");
    s_msg(SP, 9, 0, 2, "");
    s_msg(PI, 14, 0, 2, "");
    s_emit(dir, "ok-two-tasks-queued-cancelled.pss", "ok steps=8 tasks=2");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    s_msg(SP, 2, 0, 0, "");
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");   /* the Pi sends the same request again */
    s_msg(SP, 4, 0, 1, "");
    s_msg(SP, 7, 0, 2, RESULT32);
    s_emit(dir, "ok-repeated-request.pss", "ok steps=5 tasks=1");

    /* refused sessions: the six of the frozen first cut, then the other rules */
    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    s_msg(SP, 7, 0, 0, RESULT32);
    s_emit(dir, "bad-completed-before-accepted.pss", "refuse PST_BAD_ORDER step=2");

    s_begin(); s_open(0);
    s_msg(SP, 7, 0, 2, RESULT32); s_msg(SP, 8, 0, 3, "late failure");
    s_emit(dir, "bad-second-final.pss", "refuse PST_SECOND_FINAL step=5");

    s_begin(); s_open(0);
    s_msg(SP, 5, 0, 2, "Rain on the "); s_msg(SP, 5, 0, 4, "soft and steady.");
    s_emit(dir, "bad-chunk-skipped.pss", "refuse PST_ORDINAL_GAP step=5");

    s_begin(); s_open(0);
    s_msg(SP, 5, 0, 2, "Rain on the "); s_msg(SP, 5, 0, 2, "Rain on the ");
    s_emit(dir, "bad-chunk-repeated.pss", "refuse PST_ORDINAL_REPEAT step=5");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    mk(&m, 2, 0, 0, ""); m.subject[0] ^= 0xFF; s_add(SP, &m);
    s_emit(dir, "bad-subject-change.pss", "refuse PST_SUBJECT_MISMATCH step=2");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    s_msg(SP, 2, 0, 0, "");
    s_msg(PI, 1, 0, 0, "Write a long poem about snow.");   /* same task and key, other payload */
    s_emit(dir, "bad-idempotence-key-other-digest.pss", "refuse PST_IDEMPOTENCE_CONFLICT step=3");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    mk(&m, 1, 1, 0, "Write a short poem about rain."); fill(m.idem, 16, 0x1D); s_add(PI, &m);  /* task 1, key of task 0 */
    s_emit(dir, "bad-idempotence-key-other-task.pss", "refuse PST_IDEMPOTENCE_CONFLICT step=2");

    s_begin(); s_open(0);
    s_msg(PI, 7, 0, 1, RESULT32);
    s_emit(dir, "bad-completed-by-pi.pss", "refuse PST_WRONG_SIDE step=4");

    s_begin(); s_open(0);
    s_msg(PI, 6, 0, 1, RESULT32);
    s_emit(dir, "bad-approval-by-pi.pss", "refuse PST_WRONG_SIDE step=4");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    s_msg(SP, 2, 0, 0, "");
    s_msg(PI, 14, 1, 0, "");
    s_emit(dir, "bad-resume-unknown-task.pss", "refuse PST_UNKNOWN_TASK step=3");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    s_msg(SP, 2, 0, 0, "");
    mk(&m, 4, 0, 1, ""); m.cause[5] ^= 0x01; s_add(SP, &m);
    s_emit(dir, "bad-context-change.pss", "refuse PST_CONTEXT_MISMATCH step=3");

    s_begin(); s_open(0);
    s_msg(SP, 7, 0, 2, RESULT32); s_msg(SP, 5, 0, 3, "one more line");
    s_emit(dir, "bad-chunk-after-final.pss", "refuse PST_BAD_ORDER step=5");

    s_begin(); s_open(0);
    s_msg(SP, 6, 0, 2, RESULT32);
    s_emit(dir, "bad-approval-rule-not-yet-defined.pss", "refuse PST_BAD_ORDER step=4");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    mk(&m, 2, 0, 0, ""); s_add(SP, &m);
    sess[sess_n - (PST_HDR - O_MAGIC)] = 'X';    /* break the magic of the accepted message */
    s_emit(dir, "bad-message-in-session.pss", "refuse PST_BAD_MAGIC step=2");

    s_begin();
    for (unsigned tn = 0; tn <= MAX_TASKS; tn++) s_msg(PI, 1, tn, 0, "Count to three.");
    s_emit(dir, "bad-session-full.pss", "refuse PST_SESSION_FULL step=17");

    s_begin();
    s_msg(PI, 1, 0, 0, "Write a short poem about rain.");
    sess[sess_n++] = 3;                          /* a side byte that is neither Pi nor Spark */
    sess[sess_n++] = 0; sess[sess_n++] = 0;
    s_emit(dir, "bad-recording.pss", "refuse PST_BAD_RECORDING step=2");

    if (fclose(gen_expected) != 0) gen_fail = 1;
    return gen_fail ? 2 : 0;
}

static int make_vectors(const char *dir) {
    char path[4096];
    pst_msg m;
    snprintf(path, sizeof path, "%s/expected.txt", dir);
    if (!(gen_expected = fopen(path, "w"))) { fprintf(stderr, "cannot write %s\n", path); return 2; }
    fprintf(gen_expected,
        "# PST1 single-message vectors. Spec: ../SPEC.md (wire version 1), sections 4 and 7.\n"
        "# Line: <file> <verdict line>, verdict line as printed by tools/pst_verify.c:\n"
        "#   ok type=T version=V cause=H64 origin=H64 objective=H64 subject=H64 parent=H32\n"
        "#      task=H32 idem=H32 ordinal=N effect=E len=L digest=H64   (one line)\n"
        "#   refuse <code from SPEC.md section 7>\n"
        "# Generated by tools/pst_verify.c --make-vectors; do not edit by hand.\n");

    /* accepted */
    base(&m, 1, "Summarise the last three receipts in plain words.");
    emit_ok(dir, "ok-request.pst", &m);
    base(&m, 2, "");
    emit_ok(dir, "ok-accepted-empty.pst", &m);
    base(&m, 5, "");
    memset(gen_payload, 'x', PST_MAX_PAY);
    m.payload_len = PST_MAX_PAY; m.ordinal = 7; m.effect = 0;
    fill(m.parent, 16, 0x9E);
    sha_once(gen_payload, PST_MAX_PAY, m.digest);
    emit_ok(dir, "ok-text-chunk-1024.pst", &m);
    base(&m, 14, "");
    m.effect = 2; m.ordinal = 0xFFFFFFFFu;
    emit_ok(dir, "ok-resume-request-max-ordinal.pst", &m);

    /* refused: one rule each, in check order */
    base(&m, 1, "hello");
    emit_bad(dir, "bad-length-short-header.pst", &m, -1, 0, -(long)(5 + 1), "PST_BAD_LENGTH");
    emit_bad(dir, "bad-length-empty-file.pst", &m, -1, 0, -(long)(5 + PST_HDR), "PST_BAD_LENGTH");
    base(&m, 5, "");
    memset(gen_payload, 'y', PST_MAX_PAY);
    m.payload_len = PST_MAX_PAY;
    sha_once(gen_payload, PST_MAX_PAY, m.digest);
    emit_bad(dir, "bad-length-over-1024.pst", &m, -1, 0, 1, "PST_BAD_LENGTH");
    base(&m, 1, "hello");
    emit_bad(dir, "bad-magic.pst", &m, O_MAGIC + 3, '2', 0, "PST_BAD_MAGIC");
    emit_bad(dir, "bad-version-unknown.pst", &m, O_VERSION, 2, 0, "PST_BAD_VERSION");
    emit_bad(dir, "bad-version-downgrade.pst", &m, O_VERSION, 0, 0, "PST_DOWNGRADE");
    emit_bad(dir, "bad-type-zero.pst", &m, O_TYPE, 0, 0, "PST_BAD_TYPE");
    emit_bad(dir, "bad-type-unknown.pst", &m, O_TYPE, 0xFF, 0, "PST_BAD_TYPE");
    emit_bad(dir, "bad-reserved0.pst", &m, O_RES0 + 1, 1, 0, "PST_RESERVED_NONZERO");
    emit_bad(dir, "bad-reserved1.pst", &m, O_RES1, 0x80, 0, "PST_RESERVED_NONZERO");
    emit_bad(dir, "bad-length-mismatch.pst", &m, -1, 0, -2, "PST_BAD_LENGTH");
    emit_bad(dir, "bad-payload-len-over-800.pst", &m, O_PLEN, 0x04, 0, "PST_BAD_LENGTH");
    emit_bad(dir, "bad-trailing-byte.pst", &m, -1, 0, 1, "PST_TRAILING_BYTES");
    emit_bad(dir, "bad-effect-class.pst", &m, O_EFFECT, 3, 0, "PST_BAD_EFFECT_CLASS");
    memset(m.cause, 0, 32);
    emit_bad(dir, "bad-no-cause.pst", &m, -1, 0, 0, "PST_NO_CAUSE");
    base(&m, 1, "hello");
    memset(m.task, 0, 16);
    emit_bad(dir, "bad-no-task-id.pst", &m, -1, 0, 0, "PST_NO_TASK");
    base(&m, 1, "hello");
    memset(m.idem, 0, 16);
    emit_bad(dir, "bad-no-idempotence-key.pst", &m, -1, 0, 0, "PST_NO_TASK");
    base(&m, 1, "hello");
    memset(m.objective, 0, 32);
    emit_bad(dir, "bad-request-no-objective.pst", &m, -1, 0, 0, "PST_NO_OBJECTIVE");
    base(&m, 1, "hello");
    m.digest[31] ^= 1;
    emit_bad(dir, "bad-digest.pst", &m, -1, 0, 0, "PST_DIGEST_MISMATCH");

    if (fclose(gen_expected) != 0) gen_fail = 1;
    return gen_fail ? 2 : make_sessions(dir);
}

int main(int argc, char **argv) {
    char out[1024];
    int rt;
    if (argc == 2 && argv[1][0] != '-') {
        int code = check_file(argv[1], out, sizeof out, &rt);
        if (code < 0) return 2;
        puts(out);
        return code == PST_OK && rt ? 0 : 1;
    }
    if (argc == 3 && strcmp(argv[1], "--corpus") == 0) return corpus(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--make-vectors") == 0) return make_vectors(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--session") == 0) {
        session_verdict v;
        size_t n;
        if (slurp(argv[2], &n)) { fprintf(stderr, "cannot read %s\n", argv[2]); return 2; }
        session_check(file_buf, n, &v);
        session_line(&v, out, sizeof out);
        puts(out);
        return v.code == PST_OK ? 0 : 1;
    }
    if (argc >= 5 && strcmp(argv[1], "--session-fuzz") == 0)
        return session_fuzz(strtoull(argv[2], NULL, 10), strtoul(argv[3], NULL, 10), argc - 4, argv + 4);
    fprintf(stderr, "usage: pst_verify FILE | --session FILE | --corpus DIR | --make-vectors DIR\n"
                    "       | --session-fuzz SEED COUNT SESSION_FILE...\n");
    return 2;
}
