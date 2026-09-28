#ifndef FP_ZW101_H
#define FP_ZW101_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    FP_MATCH_OK = 0,
    FP_NO_MATCH,
    FP_NO_FINGER,
    FP_SENSOR_ERROR,
} fp_result_t;

bool fp_zw101_init(int tx_pin, int rx_pin);
bool fp_zw101_has_enrollment(void);
fp_result_t fp_zw101_capture_and_match(uint32_t timeout_ms);
fp_result_t fp_zw101_enroll(uint16_t template_id);
uint8_t fp_zw101_get_enrolled_count(void);
void fp_zw101_set_enrolled_count(uint8_t count);

#endif // FP_ZW101_H
