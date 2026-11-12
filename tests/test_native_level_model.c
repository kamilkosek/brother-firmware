#include "native_level_model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct cfw_native_level s = {0,0,10037,2007,37,0,0};
    struct cfw_native_level plan = {0}, sentinel;
    unsigned char percent = 255;
    unsigned p, a;
    for (a = 0; a < 200; ++a) {
        s.baseline = a;
        s.threshold = 100000 + 113 * a;
        s.low_threshold = 20000 + 3 * a;
        s.near = 0; s.gated_empty = 0;
        for (p = 1; p <= 100; ++p) {
            assert(cfw_native_counter_plan(&s,p,&plan) == CFW_NATIVE_OK);
            assert(cfw_native_display(&plan,&percent) == CFW_NATIVE_OK);
            assert(percent == p);
            assert(plan.sensor == s.sensor && plan.near == 0);
        }
        s.near = 1;
        for (p = 1; p <= 100; ++p) {
            enum cfw_native_result r = cfw_native_counter_plan(&s,p,&plan);
            if ((uint64_t)p * ((s.threshold-s.baseline)/100) <= s.low_threshold) {
                assert(r == CFW_NATIVE_OK);
                assert(cfw_native_display(&plan,&percent) == CFW_NATIVE_OK && percent == p);
                assert(plan.total == s.total && plan.near == 1);
            } else assert(r == CFW_NATIVE_REQUIRES_STATE_CHANGE);
            assert(cfw_calibration_plan(&s,p,&plan)==CFW_NATIVE_OK);
            assert(cfw_native_display(&plan,&percent)==CFW_NATIVE_OK && percent==p);
            assert(plan.near==(plan.total>=plan.threshold-plan.low_threshold));
        }
    }
    sentinel = plan;
    assert(cfw_native_counter_plan(&s,100,&plan) == CFW_NATIVE_REQUIRES_STATE_CHANGE);
    assert(memcmp(&plan,&sentinel,sizeof plan) == 0);
    assert(cfw_native_counter_plan(&s,0,&plan) == CFW_NATIVE_REQUIRES_STATE_CHANGE);
    assert(cfw_native_counter_plan(&s,101,&plan) == CFW_NATIVE_UNREPRESENTABLE);
    s.near = 0;
    s.total = s.threshold;
    assert(cfw_native_display(&s,&percent) == CFW_NATIVE_OK && percent == 1);
    s.total = UINT64_C(0xffffffffff);
    assert(cfw_native_display(&s,&percent) == CFW_NATIVE_OK && percent == 1);
    s.gated_empty = 1;
    assert(cfw_native_display(&s,&percent) == CFW_NATIVE_OK && percent == 0);
    assert(cfw_native_counter_plan(&s,50,&plan) == CFW_NATIVE_REQUIRES_STATE_CHANGE);
    s.threshold = s.baseline;
    percent = 255;
    assert(cfw_native_display(&s,&percent) == CFW_NATIVE_INVALID_MODEL && percent == 255);
    s.threshold = s.baseline+99;
    assert(cfw_native_display(&s,&percent) == CFW_NATIVE_INVALID_MODEL);
    puts("native level model: 60,000 branch/percentage checks and state/bounds checks passed");
    return 0;
}
