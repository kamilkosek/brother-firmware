#include "native_level_model.h"
#define MAX40 UINT64_C(0xffffffffff)

static enum cfw_native_result divisor(const struct cfw_native_level *s, uint32_t *d)
{
    if (!s || s->total > MAX40 || s->threshold <= s->baseline ||
        s->threshold - s->baseline < 100) return CFW_NATIVE_INVALID_MODEL;
    *d = (s->threshold - s->baseline) / 100;
    return CFW_NATIVE_OK;
}

enum cfw_native_result cfw_native_display(const struct cfw_native_level *s,
    unsigned char *percent)
{
    uint32_t d;
    uint64_t value;
    enum cfw_native_result result;
    if (!percent) return CFW_NATIVE_INVALID_MODEL;
    result = divisor(s, &d);
    if (result != CFW_NATIVE_OK) return result;
    if (s->gated_empty) value = 0;
    else if (s->near) {
        value = s->sensor > s->low_threshold ? 1 :
            (unsigned char)((s->low_threshold - s->sensor) / d);
        if (!value) value = 1;
    } else if (s->total <= s->baseline) value = 100;
    else if (s->total >= s->threshold) value = 1;
    else {
        value = (unsigned char)((s->threshold - s->total) / d);
        if (!value) value = 1;
    }
    if (value > 100) value = 100;
    *percent = (unsigned char)value;
    return CFW_NATIVE_OK;
}

enum cfw_native_result cfw_native_counter_plan(const struct cfw_native_level *s,
    unsigned percent, struct cfw_native_level *out)
{
    uint32_t d;
    uint64_t used;
    unsigned char shown;
    struct cfw_native_level plan;
    enum cfw_native_result result;
    if (!out || percent > 100) return CFW_NATIVE_UNREPRESENTABLE;
    result = divisor(s, &d);
    if (result != CFW_NATIVE_OK) return result;
    if (!percent || s->gated_empty) return CFW_NATIVE_REQUIRES_STATE_CHANGE;
    plan = *s;
    if (s->near) {
        used = (uint64_t)percent * d;
        if (used > s->low_threshold) return CFW_NATIVE_REQUIRES_STATE_CHANGE;
        plan.sensor = s->low_threshold - (uint32_t)used;
    } else if (percent == 100) {
        plan.total = 0;
    } else {
        used = (uint64_t)percent * d;
        if (used >= s->threshold) return CFW_NATIVE_UNREPRESENTABLE;
        plan.total = s->threshold - used;
    }
    result = cfw_native_display(&plan, &shown);
    if (result != CFW_NATIVE_OK) return result;
    if (shown != percent) return CFW_NATIVE_UNREPRESENTABLE;
    *out = plan;
    return CFW_NATIVE_OK;
}

enum cfw_native_result cfw_calibration_plan(const struct cfw_native_level *s,
    unsigned percent, struct cfw_native_level *out)
{
    struct cfw_native_level plan;
    uint32_t d;
    unsigned char shown;
    uint64_t remaining;
    enum cfw_native_result result;
    if (!out || !percent || percent > 100) return CFW_NATIVE_UNREPRESENTABLE;
    result=divisor(s,&d);
    if(result!=CFW_NATIVE_OK) return result;
    if(s->gated_empty) return CFW_NATIVE_REQUIRES_STATE_CHANGE;
    if(s->threshold<=s->low_threshold) return CFW_NATIVE_INVALID_MODEL;
    plan=*s;
    remaining=(uint64_t)percent*d;
    plan.total=percent==100 ? 0 : s->threshold-remaining;
    plan.near=plan.total >= s->threshold-s->low_threshold;
    plan.sensor=plan.near ? s->low_threshold-(uint32_t)remaining : 0;
    result=cfw_native_display(&plan,&shown);
    if(result!=CFW_NATIVE_OK || shown!=percent) return CFW_NATIVE_UNREPRESENTABLE;
    *out=plan;
    return CFW_NATIVE_OK;
}
