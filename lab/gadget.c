/*
 * Source harness of VirtualBox OSS 7.2.20 VMMDev HGCM SSM load leftover.
 * Pin peel f2792cf44f663989818507e36d3db5f978523c5e.
 *
 * vmmdevR3HgcmCmdAlloc (VMMDevHGCM.cpp:376-401) sizes the heap block with
 * uint32_t cbCmd. Live vmmdevR3HgcmCallAlloc caps cParms at 32.
 * vmmdevR3HgcmLoadState (2043-2091) reads cParms from SSM with no 32 cap,
 * then stores paGuestParms[i].enmType from the sav.
 *
 * Sizes match the pin AssertCompile comments: CMD 120, guestparm 40, svcparm 24.
 * Does not boot VirtualBox and does not parse a .sav.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LABEL "vbox-hgcm-ssm-cparms"
#define WITNESS "VBOX-HGCM-SSM-CPARMS-WITNESS"
#define PIN "7.2.20"
#define PIN_COMMIT "f2792cf44f663989818507e36d3db5f978523c5e"
#define LISTEN_PORT 19210
#define VMMDEV_MAX_HGCM_PARMS 32u
#define CANARY_LEN 64u
#define CANARY_FILL ((uint8_t)0xA5)
#define CPARMS_CONTROL 2u
#define CPARMS_LIVE_REJECT 33u
#define CPARMS_WRAP 0x4000000u

/* Pin VMMDevHGCM.cpp:247-256 comments: CMD 120, guestparm 40, svcparm 24. */
typedef struct VBOXHGCMCMD
{
    uint8_t ab[120];
} VBOXHGCMCMD;

typedef struct VBOXHGCMGUESTPARM
{
    uint32_t enmType;
    uint8_t abPad[36];
} VBOXHGCMGUESTPARM;

typedef struct VBOXHGCMSVCPARM
{
    uint8_t ab[24];
} VBOXHGCMSVCPARM;

_Static_assert(sizeof(VBOXHGCMCMD) == 120, "pin CMD size");
_Static_assert(sizeof(VBOXHGCMGUESTPARM) == 40, "pin guestparm size");
_Static_assert(sizeof(VBOXHGCMSVCPARM) == 24, "pin svcparm size");

typedef struct LabResult
{
    int wrap;
    int oob;
    int live_rejects_33;
    int load_calls_alloc_33;
    int canary_smashed;
    int control_canary_intact;
    uint32_t cb_cmd_control;
    uint32_t cb_cmd_wrap;
    uint64_t cb_cmd_wrap_64;
    uint32_t live_cap;
    char canary0_hex[9];
    char fail_reason[96];
} LabResult;

static LabResult g_lab;
static char g_json[1536];

static void die(const char *msg)
{
    perror(msg);
    abort();
}

/* Pin VMMDevHGCM.cpp:376-378 CALL path (no connect loc). uint32_t wrap is required. */
static uint32_t vmmdev_r3_hgcm_cb_cmd(uint32_t cParms)
{
    const uint32_t cbCmd = sizeof(VBOXHGCMCMD)
                           + cParms * (sizeof(VBOXHGCMGUESTPARM) + sizeof(VBOXHGCMSVCPARM));
    return cbCmd;
}

static uint64_t vmmdev_r3_hgcm_cb_cmd_u64(uint32_t cParms)
{
    return (uint64_t)sizeof(VBOXHGCMCMD)
           + (uint64_t)cParms
                 * (sizeof(VBOXHGCMGUESTPARM) + sizeof(VBOXHGCMSVCPARM));
}

static int canary_all_fill(const uint8_t *canary)
{
    for (uint32_t i = 0; i < CANARY_LEN; i++) {
        if (canary[i] != CANARY_FILL) {
            return 0;
        }
    }
    return 1;
}

static void hex4(char *out, const uint8_t *p)
{
    static const char *digits = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        out[i * 2] = digits[(p[i] >> 4) & 0xf];
        out[i * 2 + 1] = digits[p[i] & 0xf];
    }
    out[8] = '\0';
}

static uint8_t *alloc_slab(uint32_t cbCmd, size_t *total_out)
{
    size_t wlen = strlen(WITNESS) + 1;
    size_t total = (size_t)cbCmd + CANARY_LEN + wlen;
    uint8_t *slab = calloc(1, total);
    if (slab == NULL) {
        return NULL;
    }
    memset(slab + cbCmd, CANARY_FILL, CANARY_LEN);
    memcpy(slab + cbCmd + CANARY_LEN, WITNESS, wlen);
    if (total_out != NULL) {
        *total_out = total;
    }
    return slab;
}

/* Pin VMMDevHGCM.cpp:919-926 live path. */
static int live_path_accepts(uint32_t cParms)
{
    return cParms <= VMMDEV_MAX_HGCM_PARMS;
}

/* Pin vmmdevR3HgcmLoadState: SSM cParms is not capped at 32. */
static int load_path_calls_alloc(uint32_t cParms)
{
    (void)cParms;
    return 1;
}

static void fail_reason(LabResult *r, const char *why)
{
    if (r->fail_reason[0] == '\0') {
        snprintf(r->fail_reason, sizeof(r->fail_reason), "%s", why);
    }
}

static void run_control(LabResult *r)
{
    uint32_t cParms = CPARMS_CONTROL;
    uint32_t cbCmd = vmmdev_r3_hgcm_cb_cmd(cParms);
    uint8_t *slab;
    VBOXHGCMGUESTPARM *paGuestParms;
    uint8_t *canary;
    uint32_t i;

    r->cb_cmd_control = cbCmd;
    if (cbCmd != sizeof(VBOXHGCMCMD) + cParms * (40u + 24u)) {
        fail_reason(r, "control-cbcmd");
        return;
    }

    slab = alloc_slab(cbCmd, NULL);
    if (slab == NULL) {
        fail_reason(r, "control-alloc");
        return;
    }

    paGuestParms = (VBOXHGCMGUESTPARM *)(slab + sizeof(VBOXHGCMCMD));
    canary = slab + cbCmd;

    /* Pin load loop: for (i = 0; i < cParms; ++i) store enmType. */
    for (i = 0; i < cParms; i++) {
        paGuestParms[i].enmType = i + 1u;
    }

    r->control_canary_intact = canary_all_fill(canary);
    if (!r->control_canary_intact) {
        fail_reason(r, "control-canary-smashed");
    }
    free(slab);
}

static void run_live_cap(LabResult *r)
{
    r->live_cap = VMMDEV_MAX_HGCM_PARMS;
    r->live_rejects_33 = !live_path_accepts(CPARMS_LIVE_REJECT);
    r->load_calls_alloc_33 = load_path_calls_alloc(CPARMS_LIVE_REJECT);
    if (live_path_accepts(CPARMS_CONTROL) == 0) {
        fail_reason(r, "live-cap-rejects-control");
    }
    if (!r->live_rejects_33) {
        fail_reason(r, "live-cap-accepts-33");
    }
    if (!r->load_calls_alloc_33) {
        fail_reason(r, "load-path-capped");
    }
}

static void run_wrap(LabResult *r)
{
    uint32_t cParms = CPARMS_WRAP;
    uint32_t cbCmd = vmmdev_r3_hgcm_cb_cmd(cParms);
    uint64_t cb64 = vmmdev_r3_hgcm_cb_cmd_u64(cParms);
    uint8_t *slab;
    VBOXHGCMGUESTPARM *paGuestParms;
    uint8_t *canary;
    uint32_t enm;
    const char *placed;

    r->cb_cmd_wrap = cbCmd;
    r->cb_cmd_wrap_64 = cb64;
    printf("wrap cParms=%u cbCmd=%u cbCmd64=%llu sizeof_cmd=%zu\n",
           cParms,
           cbCmd,
           (unsigned long long)cb64,
           sizeof(VBOXHGCMCMD));
    fflush(stdout);

    if (cbCmd != sizeof(VBOXHGCMCMD)) {
        fail_reason(r, "wrap-no");
        return;
    }
    if ((uint64_t)cbCmd == cb64) {
        fail_reason(r, "wrap-no-size_t");
        return;
    }
    if (cb64 <= 0xffffffffull) {
        fail_reason(r, "wrap-64-too-small");
        return;
    }
    r->wrap = 1;

    slab = alloc_slab(cbCmd, NULL);
    if (slab == NULL) {
        fail_reason(r, "wrap-alloc");
        return;
    }

    /* Pin: paGuestParms = pCmd + sizeof(VBOXHGCMCMD). That is the alloc end. */
    paGuestParms = (VBOXHGCMGUESTPARM *)(slab + sizeof(VBOXHGCMCMD));
    canary = slab + cbCmd;
    if ((uint8_t *)paGuestParms != canary) {
        fail_reason(r, "guestparm-not-at-alloc-end");
        free(slab);
        return;
    }

    memcpy(&enm, WITNESS, sizeof(enm));
    /* First SSM enmType store only. Do not walk 0x4000000 slots. */
    paGuestParms[0].enmType = enm;

    r->canary_smashed = !canary_all_fill(canary);
    hex4(r->canary0_hex, canary);
    if (!r->canary_smashed) {
        fail_reason(r, "canary-intact");
        free(slab);
        return;
    }
    if (memcmp(canary, WITNESS, 4) != 0) {
        fail_reason(r, "canary-not-witness-prefix");
        free(slab);
        return;
    }
    r->oob = 1;

    placed = (const char *)(canary + CANARY_LEN);
    if (strcmp(placed, WITNESS) != 0) {
        fail_reason(r, "witness-missing");
    }
    printf("oob store canary0=%s smashed=1 witness=%s\n", r->canary0_hex, placed);
    fflush(stdout);
    free(slab);
}

static void build_json(const LabResult *r)
{
    const char *wrap = r->wrap ? "yes" : "no";
    const char *oob = r->oob ? "yes" : "no";
    const char *smashed = r->canary_smashed ? "yes" : "no";
    const char *intact = r->control_canary_intact ? "yes" : "no";
    const char *ok = (r->fail_reason[0] == '\0') ? "true" : "false";

    snprintf(
        g_json,
        sizeof(g_json),
        "{"
        "\"ok\":%s,"
        "\"label\":\"%s\","
        "\"pin\":\"%s\","
        "\"pin_commit\":\"%s\","
        "\"wrap\":\"%s\","
        "\"oob\":\"%s\","
        "\"live_cap\":%u,"
        "\"live_rejects_33\":%s,"
        "\"load_calls_alloc_33\":%s,"
        "\"canary_smashed\":\"%s\","
        "\"control_canary_intact\":\"%s\","
        "\"cb_cmd\":%u,"
        "\"cb_cmd_control\":%u,"
        "\"cb_cmd_64\":%llu,"
        "\"cparms_wrap\":%u,"
        "\"canary0_hex\":\"%s\","
        "\"fail_reason\":\"%s\","
        "\"witness\":\"%s\""
        "}",
        ok,
        LABEL,
        PIN,
        PIN_COMMIT,
        wrap,
        oob,
        r->live_cap,
        r->live_rejects_33 ? "true" : "false",
        r->load_calls_alloc_33 ? "true" : "false",
        smashed,
        intact,
        r->cb_cmd_wrap,
        r->cb_cmd_control,
        (unsigned long long)r->cb_cmd_wrap_64,
        CPARMS_WRAP,
        r->canary0_hex[0] ? r->canary0_hex : "00000000",
        r->fail_reason,
        WITNESS);
}

static void run_lab(void)
{
    memset(&g_lab, 0, sizeof(g_lab));
    run_control(&g_lab);
    run_live_cap(&g_lab);
    run_wrap(&g_lab);
    build_json(&g_lab);
    if (g_lab.fail_reason[0] == '\0') {
        printf(
            "gadget-ok wrap=yes oob=yes live-cap=%u canary-smashed=yes %s\n",
            g_lab.live_cap,
            WITNESS);
    } else {
        printf("gadget-fail %s %s\n", g_lab.fail_reason, WITNESS);
    }
    fflush(stdout);
}

static void write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) {
            return;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
}

static void send_http(int fd, int status, const char *reason, const char *ctype, const char *body)
{
    char hdr[256];
    size_t body_len = strlen(body);
    int n = snprintf(
        hdr,
        sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "X-Lab-How: gadget\r\n"
        "X-Pin: %s\r\n"
        "\r\n",
        status,
        reason,
        ctype,
        body_len,
        PIN);
    if (n > 0) {
        write_all(fd, hdr, (size_t)n);
        write_all(fd, body, body_len);
    }
}

static int parse_path(const char *req, char *path, size_t path_cap)
{
    const char *p = req;
    const char *end;
    size_t n;

    if (strncmp(p, "GET ", 4) != 0) {
        return -1;
    }
    p += 4;
    end = strchr(p, ' ');
    if (end == NULL) {
        return -1;
    }
    n = (size_t)(end - p);
    if (n == 0 || n >= path_cap) {
        return -1;
    }
    memcpy(path, p, n);
    path[n] = '\0';
    return 0;
}

int main(void)
{
    int srv;
    int opt = 1;
    struct sockaddr_in addr;

    run_lab();

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        die("socket");
    }
    if (setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        die("setsockopt");
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LISTEN_PORT);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        die("bind");
    }
    if (listen(srv, 16) != 0) {
        die("listen");
    }
    printf("gadget listen 0.0.0.0:%d label=%s\n", LISTEN_PORT, LABEL);
    fflush(stdout);

    for (;;) {
        int cfd = accept(srv, NULL, NULL);
        char req[2048];
        char path[256];
        ssize_t n;
        size_t got = 0;

        if (cfd < 0) {
            continue;
        }
        while (got < sizeof(req) - 1) {
            n = read(cfd, req + got, sizeof(req) - 1 - got);
            if (n <= 0) {
                break;
            }
            got += (size_t)n;
            req[got] = '\0';
            if (strstr(req, "\r\n\r\n") != NULL || strstr(req, "\n\n") != NULL) {
                break;
            }
        }
        req[got] = '\0';
        if (parse_path(req, path, sizeof(path)) == 0) {
            if (strcmp(path, "/ping") == 0) {
                send_http(cfd, 200, "OK", "text/plain; charset=utf-8", "pong\n");
            } else if (strcmp(path, "/lab") == 0 || strcmp(path, "/") == 0) {
                send_http(cfd, 200, "OK", "application/json", g_json);
            } else {
                send_http(cfd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n");
            }
        } else {
            send_http(cfd, 400, "Bad Request", "text/plain; charset=utf-8", "bad request\n");
        }
        close(cfd);
    }
}
