#include "fp_zw101.h"

#if defined(ESP_PLATFORM)
#include "driver/uart.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>
#include "files.h"
#include "fs/file.h"
#include "fs/flash.h"

#define FP_UART_NUM      UART_NUM_1
#define FP_UART_BAUD     57600
#define FP_UART_BUF_SIZE 256
#define FP_DEFAULT_ADDR  0xFFFFFFFF

#define FP_PKT_HEADER_HI 0xEF
#define FP_PKT_HEADER_LO 0x01
#define FP_PKT_COMMAND   0x01
#define FP_PKT_ACK       0x07

#define FP_CMD_GENIMG    0x01
#define FP_CMD_IMG2TZ    0x02
#define FP_CMD_SEARCH    0x04
#define FP_CMD_REGMODEL  0x05
#define FP_CMD_STORE     0x06
#define FP_CMD_EMPTY     0x0D

#define FP_OK               0x00
#define FP_ERR_NO_FINGER    0x02
#define FP_ERR_NOMATCH      0x08
#define FP_ERR_NOTFOUND     0x09

static bool s_initialized = false;

bool fp_zw101_init(int tx_pin, int rx_pin) {
    if (s_initialized) {
        return true;
    }
    uart_config_t cfg = {
        .baud_rate = FP_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    if (uart_driver_install(FP_UART_NUM, FP_UART_BUF_SIZE * 2, 0, 0, NULL, 0) != ESP_OK) {
        return false;
    }
    if (uart_param_config(FP_UART_NUM, &cfg) != ESP_OK) {
        return false;
    }
    if (uart_set_pin(FP_UART_NUM, tx_pin, rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE) != ESP_OK) {
        return false;
    }
    gpio_set_pull_mode(rx_pin, GPIO_PULLUP_ONLY);
    s_initialized = true;
    return true;
}

static bool fp_send_packet(uint8_t packet_id, const uint8_t *payload, uint16_t payload_len) {
    uint8_t buf[64];
    uint16_t len_field = payload_len + 2;
    uint16_t idx = 0;

    buf[idx++] = FP_PKT_HEADER_HI;
    buf[idx++] = FP_PKT_HEADER_LO;
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR >> 24);
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR >> 16);
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR >> 8);
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR);
    buf[idx++] = packet_id;
    buf[idx++] = (uint8_t)(len_field >> 8);
    buf[idx++] = (uint8_t)(len_field & 0xFF);

    uint16_t checksum = packet_id + (uint8_t)(len_field >> 8) + (uint8_t)(len_field & 0xFF);
    for (uint16_t i = 0; i < payload_len && idx < sizeof(buf) - 2; i++) {
        buf[idx++] = payload[i];
        checksum += payload[i];
    }
    buf[idx++] = (uint8_t)(checksum >> 8);
    buf[idx++] = (uint8_t)(checksum & 0xFF);

    return uart_write_bytes(FP_UART_NUM, (const char *)buf, idx) == idx;
}

static int fp_read_packet(uint8_t *out, uint16_t out_max, uint32_t timeout_ms) {
    uint8_t hdr[9];
    int n = uart_read_bytes(FP_UART_NUM, hdr, sizeof(hdr), pdMS_TO_TICKS(timeout_ms));
    printf("ZW101 debug: read %d/%d header bytes:", n, (int)sizeof(hdr));
    for (int i = 0; i < n; i++) {
        printf(" %02X", hdr[i]);
    }
    printf("\n");
    if (n != sizeof(hdr) || hdr[0] != FP_PKT_HEADER_HI || hdr[1] != FP_PKT_HEADER_LO) {
        return -1;
    }
    uint16_t len_field = ((uint16_t)hdr[7] << 8) | hdr[8];
    if (len_field < 3 || len_field - 2 > out_max) {
        return -1;
    }
    uint16_t payload_len = len_field - 2;
    uint8_t body[64];
    n = uart_read_bytes(FP_UART_NUM, body, len_field, pdMS_TO_TICKS(timeout_ms));
    if (n != len_field) {
        return -1;
    }
    uint16_t checksum = hdr[6] + hdr[7] + hdr[8];
    for (uint16_t i = 0; i < payload_len; i++) {
        checksum += body[i];
        out[i] = body[i];
    }
    uint16_t recv_checksum = ((uint16_t)body[payload_len] << 8) | body[payload_len + 1];
    if (checksum != recv_checksum) {
        return -1;
    }
    return (int)payload_len;
}

static fp_result_t fp_confirmation_to_result(uint8_t code) {
    switch (code) {
        case FP_OK:            return FP_MATCH_OK;
        case FP_ERR_NO_FINGER:  return FP_NO_FINGER;
        case FP_ERR_NOMATCH:
        case FP_ERR_NOTFOUND:   return FP_NO_MATCH;
        default:                return FP_SENSOR_ERROR;
    }
}

static int fp_do_simple_cmd(uint8_t instr, const uint8_t *extra, uint16_t extra_len, uint32_t timeout_ms) {
    uint8_t payload[8];
    payload[0] = instr;
    if (extra_len > sizeof(payload) - 1) {
        return -1;
    }
    memcpy(payload + 1, extra, extra_len);
    if (!fp_send_packet(FP_PKT_COMMAND, payload, (uint16_t)(1 + extra_len))) {
        return -1;
    }
    uint8_t resp[16];
    int n = fp_read_packet(resp, sizeof(resp), timeout_ms);
    if (n < 1) {
        return -1;
    }
    return resp[0];
}

bool fp_zw101_has_enrollment(void) {
    return true; // TODO: replace with real TemplateNum check
}

uint8_t fp_zw101_get_enrolled_count(void) {
    file_t *f = file_search_by_fid(EF_FP_COUNT, NULL, SPECIFY_EF);
    if (!f || !file_has_data(f)) {
        return 0;
    }
    return file_get_data(f)[0];
}

void fp_zw101_set_enrolled_count(uint8_t count) {
    file_t *f = file_search_by_fid(EF_FP_COUNT, NULL, SPECIFY_EF);
    if (f) {
        file_put_data(f, CONST_BYTE_ARRAY(&count, 1));
        flash_commit();
    }
}

fp_result_t fp_zw101_capture_and_match(uint32_t timeout_ms) {
    if (!s_initialized) {
        return FP_SENSOR_ERROR;
    }

    uint32_t waited = 0;
    const uint32_t poll_interval_ms = 100;
    int conf;
    do {
        conf = fp_do_simple_cmd(FP_CMD_GENIMG, NULL, 0, 500);
        printf("ZW101 debug: GenImg returned conf=%d\n", conf);
        if (conf == FP_OK) {
            break;
        }
        if (conf != FP_ERR_NO_FINGER && conf != -1) {
            return fp_confirmation_to_result((uint8_t)conf);
        }
        vTaskDelay(pdMS_TO_TICKS(poll_interval_ms));
        waited += poll_interval_ms;
    } while (waited < timeout_ms);

    if (conf != FP_OK) {
        return FP_NO_FINGER;
    }

    uint8_t buffer_id = 0x01;
    conf = fp_do_simple_cmd(FP_CMD_IMG2TZ, &buffer_id, 1, 1000);
    if (conf != FP_OK) {
        return fp_confirmation_to_result((uint8_t)conf);
    }

    uint8_t search_params[5] = { 0x01, 0x00, 0x00, 0x00, 0xC8 };
    if (!fp_send_packet(FP_PKT_COMMAND, (uint8_t[]){ FP_CMD_SEARCH,
            search_params[0], search_params[1], search_params[2],
            search_params[3], search_params[4] }, 6)) {
        return FP_SENSOR_ERROR;
    }
    uint8_t resp[16];
    int n = fp_read_packet(resp, sizeof(resp), 1500);
    if (n < 1) {
        return FP_SENSOR_ERROR;
    }
    return fp_confirmation_to_result(resp[0]);
}

fp_result_t fp_zw101_enroll(uint16_t template_id) {
    if (!s_initialized) {
        return FP_SENSOR_ERROR;
    }

    fp_result_t r = fp_zw101_capture_and_match(300000);
    if (r == FP_SENSOR_ERROR) {
        return r;
    }

    vTaskDelay(pdMS_TO_TICKS(1500));

    int conf = fp_do_simple_cmd(FP_CMD_GENIMG, NULL, 0, 300000);
    if (conf != FP_OK) {
        return fp_confirmation_to_result((uint8_t)conf);
    }
    uint8_t buffer_id = 0x02;
    conf = fp_do_simple_cmd(FP_CMD_IMG2TZ, &buffer_id, 1, 1000);
    if (conf != FP_OK) {
        return fp_confirmation_to_result((uint8_t)conf);
    }

    conf = fp_do_simple_cmd(FP_CMD_REGMODEL, NULL, 0, 1000);
    if (conf != FP_OK) {
        return fp_confirmation_to_result((uint8_t)conf);
    }

    uint8_t store_params[3] = { 0x01, (uint8_t)(template_id >> 8), (uint8_t)(template_id & 0xFF) };
    conf = fp_do_simple_cmd(FP_CMD_STORE, store_params, 3, 1000);
    return fp_confirmation_to_result((uint8_t)conf);
}

#else // !ESP_PLATFORM

bool fp_zw101_init(int tx_pin, int rx_pin) { (void)tx_pin; (void)rx_pin; return false; }
bool fp_zw101_has_enrollment(void) { return false; }
fp_result_t fp_zw101_capture_and_match(uint32_t timeout_ms) { (void)timeout_ms; return FP_SENSOR_ERROR; }
fp_result_t fp_zw101_enroll(uint16_t template_id) { (void)template_id; return FP_SENSOR_ERROR; }
uint8_t fp_zw101_get_enrolled_count(void) { return 0; }
void fp_zw101_set_enrolled_count(uint8_t count) { (void)count; }

#endif
