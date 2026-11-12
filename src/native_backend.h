#ifndef CFW_NATIVE_BACKEND_H
#define CFW_NATIVE_BACKEND_H
#include "native_level_model.h"
#include "web_request.h"
enum cfw_save_result {
    CFW_SAVE_OK=0, CFW_SAVE_BUSY, CFW_SAVE_STALE, CFW_SAVE_INVALID,
    CFW_SAVE_DEVICE_FAULT, CFW_SAVE_IO_ROLLED_BACK, CFW_SAVE_ROLLBACK_FAILED
};
int cfw_read_state(unsigned color,struct cfw_native_level *out);
enum cfw_save_result cfw_save_level(const struct cfw_level_request *request);
/* Physical-index order BK/C/Y/M; preserves the native ADC diagnostic sample. */
int cfw_count_based_sensor(unsigned index);
#endif
