#ifndef CFW_WEB_REQUEST_H
#define CFW_WEB_REQUEST_H
#include <stddef.h>
#include <stdint.h>

/* Validation only. This module has no EEPROM or printer access. */
enum cfw_request_result {
    CFW_REQUEST_OK = 0,
    CFW_REQUEST_METHOD,
    CFW_REQUEST_LOGIN,
    CFW_REQUEST_ORIGIN,
    CFW_REQUEST_TYPE,
    CFW_REQUEST_BODY,
    CFW_REQUEST_FIELDS
};

struct cfw_level_request {
    unsigned char remaining[4]; /* BK, Y, C, M */
    unsigned char selected_mask; /* one-color write handlers require explicit mask */
    unsigned char mask_explicit;
    uint64_t expected_total[4]; /* optimistic concurrency check for writes */
    unsigned char expected_mask;
};

/* Inputs must be NUL-terminated except body, whose exact length is supplied.
 * Authentication must come from the native AUTH_LOGIN check, never a field.
 * On failure, *out remains unchanged. No native percentage model is implied.
 */
enum cfw_request_result cfw_validate_level_request(
    const char *method, int authenticated, const char *origin,
    const char *host, const char *content_type,
    const unsigned char *body, size_t length, struct cfw_level_request *out);
#endif
