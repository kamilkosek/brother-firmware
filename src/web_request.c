#include "web_request.h"

static unsigned char lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}

static int equal(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static int equal_ci(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b && lower((unsigned char)*a) == lower((unsigned char)*b)) {
        ++a; ++b;
    }
    return *a == *b;
}

static int same_origin(const char *origin, const char *host)
{
    size_t n;
    const char *authority;
    if (!origin || !host || !*host) return 0;
    /* This printer endpoint is HTTP. HTTPS requires a separately verified
     * server scheme; do not infer it from attacker-controlled headers. */
    for (n = 0; n < 7; ++n)
        if (origin[n] != "http://"[n]) return 0;
    authority = origin + 7;
    for (n = 0; host[n]; ++n) {
        unsigned char c = (unsigned char)host[n];
        if (n >= 253 || !((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == ':' || c == '[' || c == ']')) return 0;
    }
    return equal_ci(authority, host);
}

static int content_type_ok(const char *s)
{
    const char *base = "application/x-www-form-urlencoded";
    size_t n;
    if (!s) return 0;
    for (n = 0; base[n]; ++n)
        if (!s[n] || lower((unsigned char)s[n]) != (unsigned char)base[n]) return 0;
    s += n;
    if (!*s) return 1;
    if (*s++ != ';') return 0;
    while (*s == ' ' || *s == '\t') ++s;
    return equal_ci(s, "charset=UTF-8");
}

static int hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = lower(c);
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static int decode(const unsigned char *p, size_t n, char *dst, size_t cap)
{
    size_t i, used = 0;
    for (i = 0; i < n; ++i) {
        unsigned char c = p[i];
        if (c == '%') {
            int hi, lo;
            if (n - i < 3) return 0;
            hi = hex(p[i+1]); lo = hex(p[i+2]);
            if (hi < 0 || lo < 0) return 0;
            c = (unsigned char)((hi << 4) | lo); i += 2;
        } else if (c == '+') c = ' ';
        if (c < 0x20 || c > 0x7e || used + 1 >= cap) return 0;
        dst[used++] = (char)c;
    }
    dst[used] = 0;
    return 1;
}

enum cfw_request_result cfw_validate_level_request(
    const char *method, int authenticated, const char *origin,
    const char *host, const char *content_type,
    const unsigned char *body, size_t length, struct cfw_level_request *out)
{
    static const char *const names[11] = {
        "cfw_action", "cfw_confirm", "cfw_bk", "cfw_y", "cfw_c", "cfw_m", "cfw_mask",
        "cfw_expect_bk", "cfw_expect_y", "cfw_expect_c", "cfw_expect_m"
    };
    struct cfw_level_request plan = {{0,0,0,0},15,0,{0,0,0,0},0};
    unsigned seen = 0;
    size_t start = 0;
    if (!equal(method, "POST")) return CFW_REQUEST_METHOD;
    if (authenticated != 1) return CFW_REQUEST_LOGIN;
    if (!same_origin(origin, host)) return CFW_REQUEST_ORIGIN;
    if (!content_type_ok(content_type)) return CFW_REQUEST_TYPE;
    if (!body || !out || !length || length > 1024) return CFW_REQUEST_BODY;
    while (start < length) {
        size_t end = start, sep = start, i;
        unsigned field;
        uint64_t number = 0;
        char key[24], value[24];
        while (end < length && body[end] != '&') ++end;
        while (sep < end && body[sep] != '=') ++sep;
        if (sep == start || sep == end ||
            !decode(body+start, sep-start, key, sizeof key) ||
            !decode(body+sep+1, end-sep-1, value, sizeof value))
            return CFW_REQUEST_FIELDS;
        for (field = 0; field < 11; ++field) if (equal(key, names[field])) break;
        /* Reject native B... controls, unknown fields, and duplicates. */
        if (field == 11 || (seen & (1u << field))) return CFW_REQUEST_FIELDS;
        seen |= 1u << field;
        if (field == 0) {
            if (!equal(value, "set_levels")) return CFW_REQUEST_FIELDS;
        } else if (field == 1) {
            if (!equal(value, "1")) return CFW_REQUEST_FIELDS;
        } else {
            if (!value[0]) return CFW_REQUEST_FIELDS;
            for (i = 0; value[i]; ++i) {
                if (i >= (field>=7 ? 13u : 3u) || value[i] < '0' || value[i] > '9') return CFW_REQUEST_FIELDS;
                if (number > UINT64_C(0xffffffffff)/10u) return CFW_REQUEST_FIELDS;
                number = number * 10u + (unsigned)(value[i] - '0');
                if (number > UINT64_C(0xffffffffff)) return CFW_REQUEST_FIELDS;
            }
            if (field >= 7) {
                plan.expected_total[field-7]=number;
                plan.expected_mask|=(unsigned char)(1u<<(field-7));
            } else if (field == 6) {
                if (!number || number > 15) return CFW_REQUEST_FIELDS;
                plan.selected_mask = (unsigned char)number;
                plan.mask_explicit = 1;
            } else {
                if (number > 100) return CFW_REQUEST_FIELDS;
                plan.remaining[field-2] = (unsigned char)number;
            }
        }
        if (end == length) break;
        start = end + 1;
        if (start == length) return CFW_REQUEST_FIELDS;
    }
    if ((seen & 63u) != 63u) return CFW_REQUEST_FIELDS;
    *out = plan;
    return CFW_REQUEST_OK;
}
