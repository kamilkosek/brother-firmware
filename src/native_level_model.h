#ifndef CFW_NATIVE_LEVEL_MODEL_H
#define CFW_NATIVE_LEVEL_MODEL_H
#include <stdint.h>

/* R firmware's counter-to-display calculation, recovered from 40457ad6,
 * 40457a48 and 40457ab2. This code does not access hardware. */
struct cfw_native_level {
    uint64_t total;
    uint32_t sensor;
    uint32_t threshold;       /* T: 40283b4a(color) */
    uint32_t low_threshold;   /* L: 40283dde(color) */
    uint32_t baseline;        /* A: model/history dependent */
    unsigned char near;
    unsigned char gated_empty;
};

enum cfw_native_result {
    CFW_NATIVE_OK = 0,
    CFW_NATIVE_INVALID_MODEL,
    CFW_NATIVE_REQUIRES_STATE_CHANGE,
    CFW_NATIVE_UNREPRESENTABLE
};

enum cfw_native_result cfw_native_display(const struct cfw_native_level *state,
    unsigned char *percent);
/* Changes counters in a copy; never clears/forces sensor or EMPTY flags.
 * A request outside the current native branch is explicitly rejected.
 * Zero is a state flag, not a counter-only percentage in this firmware.
 */
enum cfw_native_result cfw_native_counter_plan(const struct cfw_native_level *state,
    unsigned percent, struct cfw_native_level *out);
/* Deliberate count-based calibration: selects the normal/near branch at T-L.
 * Requires the firmware's count-based sensor hook; never use alone with the
 * original optical near source. Hardware fault gates are not overridden. */
enum cfw_native_result cfw_calibration_plan(const struct cfw_native_level *state,
    unsigned percent, struct cfw_native_level *out);
#endif
