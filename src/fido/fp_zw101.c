/*
 * ZW101 fingerprint unlock for pico-fido (ESP32-S3 / ESP-IDF).
 *
 * Protocol: Hi-Link "EF-01" packets (same family as AS608/R30x):
 *   Header(2) | Address(4) | PacketID(1) | Length(2) | Payload(N) | Checksum(2)
 *   Checksum = 16-bit sum of PacketID + Length bytes + Payload bytes.
 */

#include "fp_zw101.h"

#if defined(ESP_PLATFORM)

#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "files.h"
#include "fs/file.h"
#include "fs/flash.h"

#define FP_UART_NUM      UART_NUM_1
#define FP_UART_BAUD     57600
#define FP_UART_BUF_SIZE 256
#define FP_DEFAULT_ADDR  0xFFFFFFFFu

#define FP_PKT_HEADER_HI 0xEF
#define FP_PKT_HEADER_LO 0x01
#define FP_PKT_COMMAND   0x01

#define FP_CMD_GENIMG    0x01
#define FP_CMD_IMG2TZ    0x02
#define FP_CMD_SEARCH    0x04
#define FP_CMD_REGMODEL  0x05
#define FP_CMD_STORE     0x06
#define FP_CMD_EMPTY     0x0D

#define FP_OK            0x00
#define FP_ERR_NO_FINGER 0x02

#define FP_POLL_MS       150u
#define FP_MAX_FAILS     5u        // wrong-finger attempts before a pause
#define FP_LOCKOUT_MS    30000u

static volatile bool     s_armed = false;
static volatile bool     s_unlocked = false;
static volatile uint32_t s_deadline_ms = 0;

/* ---------- time / unlock state ---------- */

static uint32_t now_ms(void) {
    return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static void fp_unlock(void) {
    s_deadline_ms = now_ms() + FP_UNLOCK_MS;
    s_unlocked = true;
}

bool fp_zw101_is_armed(void) {
    return s_armed;
}

bool fp_zw101_is_unlocked(void) {
    if (!s_unlocked) {
        return false;
    }
    return (int32_t)(s_deadline_ms - now_ms()) > 0;
}

bool fp_zw101_wait_unlocked(uint32_t wait_ms) {
    if (!s_armed) {
        return true;
    }
    uint32_t start = now_ms();
    while (!fp_zw101_is_unlocked()) {
        if (!s_armed) {
            return true;
        }
        if (wait_ms == 0 || (uint32_t)(now_ms() - start) >= wait_ms) {
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    return true;
}

void fp_zw101_on_reset(void) {
    s_armed = false;
    s_unlocked = false;
}

/* ---------- saved enrollment count (flash) ---------- */

static uint8_t fp_count_load(void) {
    file_t *f = file_search_by_fid(EF_FP_COUNT, NULL, SPECIFY_EF);
    if (!f || !file_has_data(f)) {
        return 0;
    }
    uint8_t c = file_get_data(f)[0];
    return c > FP_MAX_FINGERS ? (uint8_t)FP_MAX_FINGERS : c;
}

static void fp_count_store(uint8_t count) {
    file_t *f = file_search_by_fid(EF_FP_COUNT, NULL, SPECIFY_EF);
    if (f) {
        file_put_data(f, CONST_BYTE_ARRAY(&count, 1));
        flash_commit();
    }
}

/* ---------- sensor protocol ---------- */

static bool fp_uart_init(int tx_pin, int rx_pin) {
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
    return true;
}

static bool fp_send_packet(const uint8_t *payload, uint16_t payload_len) {
    uint8_t buf[32];
    uint16_t len_field = payload_len + 2;
    uint16_t idx = 0;

    if (payload_len + 11 > sizeof(buf)) {
        return false;
    }
    buf[idx++] = FP_PKT_HEADER_HI;
    buf[idx++] = FP_PKT_HEADER_LO;
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR >> 24);
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR >> 16);
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR >> 8);
    buf[idx++] = (uint8_t)(FP_DEFAULT_ADDR);
    buf[idx++] = FP_PKT_COMMAND;
    buf[idx++] = (uint8_t)(len_field >> 8);
    buf[idx++] = (uint8_t)(len_field & 0xFF);

    uint16_t checksum = FP_PKT_COMMAND + (uint8_t)(len_field >> 8) + (uint8_t)(len_field & 0xFF);
    for (uint16_t i = 0; i < payload_len; i++) {
        buf[idx++] = payload[i];
        checksum += payload[i];
    }
    buf[idx++] = (uint8_t)(checksum >> 8);
    buf[idx++] = (uint8_t)(checksum & 0xFF);

    return uart_write_bytes(FP_UART_NUM, (const char *)buf, idx) == idx;
}

// Returns payload length (first byte = confirmation code) or -1.
static int fp_read_packet(uint8_t *out, uint16_t out_max, uint32_t timeout_ms) {
    uint8_t hdr[9];
    int n = uart_read_bytes(FP_UART_NUM, hdr, sizeof(hdr), pdMS_TO_TICKS(timeout_ms));
    if (n != (int)sizeof(hdr) || hdr[0] != FP_PKT_HEADER_HI || hdr[1] != FP_PKT_HEADER_LO) {
        return -1;
    }
    uint16_t len_field = ((uint16_t)hdr[7] << 8) | hdr[8];
    uint8_t body[32];
    if (len_field < 3 || len_field > sizeof(body) || (uint16_t)(len_field - 2) > out_max) {
        return -1;
    }
    uint16_t payload_len = len_field - 2;
    n = uart_read_bytes(FP_UART_NUM, body, len_field, pdMS_TO_TICKS(timeout_ms));
    if (n != (int)len_field) {
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

// Sends one command and returns the sensor's confirmation code, or -1 on failure.
static int fp_cmd(uint8_t instr, const uint8_t *params, uint16_t params_len, uint32_t timeout_ms) {
    uint8_t payload[8];
    if (params_len > sizeof(payload) - 1) {
        return -1;
    }
    payload[0] = instr;
    if (params_len > 0) {
        memcpy(payload + 1, params, params_len);
    }
    uart_flush_input(FP_UART_NUM);
    if (!fp_send_packet(payload, (uint16_t)(1 + params_len))) {
        return -1;
    }
    uint8_t resp[16];
    if (fp_read_packet(resp, sizeof(resp), timeout_ms) < 1) {
        return -1;
    }
    return resp[0];
}

// Captures an image. FP_OK means a finger is on the sensor.
static int fp_gen_img(void) {
    return fp_cmd(FP_CMD_GENIMG, NULL, 0, 300);
}

// Waits up to timeout_ms for a finger to be placed.
static bool fp_wait_finger(uint32_t timeout_ms) {
    uint32_t t0 = now_ms();
    do {
        if (fp_gen_img() == FP_OK) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    } while ((uint32_t)(now_ms() - t0) < timeout_ms);
    return false;
}

// Waits until the finger is lifted (or the timeout passes).
static void fp_wait_lift(uint32_t timeout_ms) {
    uint32_t t0 = now_ms();
    while ((uint32_t)(now_ms() - t0) < timeout_ms) {
        if (fp_gen_img() == FP_ERR_NO_FINGER) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

typedef enum { FP_MATCH, FP_NOMATCH, FP_ERROR } fp_match_t;

// Matches the image currently held by the sensor against the stored fingers.
static fp_match_t fp_match_current_image(void) {
    uint8_t buffer1 = 0x01;
    int c = fp_cmd(FP_CMD_IMG2TZ, &buffer1, 1, 1000);
    if (c == -1) {
        return FP_ERROR;
    }
    if (c != FP_OK) {
        return FP_NOMATCH;   // e.g. image too small / too messy to use
    }
    // BufferID, StartPage(2), PageNum(2): search only the slots we use.
    uint8_t p[5] = { 0x01, 0x00, 0x00, 0x00, (uint8_t)FP_MAX_FINGERS };
    c = fp_cmd(FP_CMD_SEARCH, p, sizeof(p), 2000);
    if (c == -1) {
        return FP_ERROR;
    }
    return c == FP_OK ? FP_MATCH : FP_NOMATCH;
}

// Enrolls a finger whose first image is already captured, into slot `id`.
static bool fp_enroll_from_first_image(uint16_t id) {
    uint8_t b1 = 0x01, b2 = 0x02;
    if (fp_cmd(FP_CMD_IMG2TZ, &b1, 1, 1000) != FP_OK) {
        return false;
    }
    printf("ZW101: lift your finger, then place the SAME finger again\n");
    fp_wait_lift(5000);
    if (!fp_wait_finger(10000)) {
        return false;
    }
    if (fp_cmd(FP_CMD_IMG2TZ, &b2, 1, 1000) != FP_OK) {
        return false;
    }
    if (fp_cmd(FP_CMD_REGMODEL, NULL, 0, 1000) != FP_OK) {
        return false;       // the two scans did not match each other
    }
    uint8_t sp[3] = { 0x01, (uint8_t)(id >> 8), (uint8_t)(id & 0xFF) };
    return fp_cmd(FP_CMD_STORE, sp, sizeof(sp), 1500) == FP_OK;
}

/* ---------- enrollment window (after each boot) ---------- */

static void fp_enrollment_window(uint8_t count) {
    // First finger: nothing to verify against yet. Later fingers: an already
    // enrolled finger must be shown first, so a stranger can't add their own.
    bool authorized = (count == 0);
    uint32_t t0 = now_ms();

    if (authorized) {
        printf("ZW101: place the finger to enroll within %u s (slot %u of %u)\n",
               (unsigned)(FP_ENROLL_WINDOW_MS / 1000), (unsigned)(count + 1), (unsigned)FP_MAX_FINGERS);
    }
    else {
        printf("ZW101: %u finger(s) enrolled. To add another, first touch an enrolled finger (%u s window)\n",
               (unsigned)count, (unsigned)(FP_ENROLL_WINDOW_MS / 1000));
    }

    while ((uint32_t)(now_ms() - t0) < FP_ENROLL_WINDOW_MS) {
        if (fp_gen_img() != FP_OK) {
            vTaskDelay(pdMS_TO_TICKS(FP_POLL_MS));
            continue;
        }
        if (!authorized) {
            if (fp_match_current_image() == FP_MATCH) {
                authorized = true;
                fp_unlock();
                printf("ZW101: verified. Now place the NEW finger\n");
                fp_wait_lift(3000);
                t0 = now_ms();      // fresh window for the new finger
            }
            else {
                vTaskDelay(pdMS_TO_TICKS(500));
            }
            continue;
        }
        if (fp_enroll_from_first_image(count)) {
            fp_count_store((uint8_t)(count + 1));
            s_armed = true;
            fp_unlock();
            printf("ZW101: finger stored (%u of %u). Unplug and replug to add another.\n",
                   (unsigned)(count + 1), (unsigned)FP_MAX_FINGERS);
        }
        else {
            printf("ZW101: enrollment failed. Unplug and replug to try again.\n");
        }
        return;     // one enrollment per boot
    }
    printf("ZW101: enrollment window closed\n");
}

/* ---------- background task ---------- */

static void fp_task(void *arg) {
    (void)arg;
    uint8_t count = fp_count_load();

    if (count == 0) {
        // Nothing enrolled as far as the key knows: clear any stale templates.
        fp_cmd(FP_CMD_EMPTY, NULL, 0, 2000);
    }
    if (count < FP_MAX_FINGERS) {
        fp_enrollment_window(count);
    }

    uint8_t fails = 0;
    while (s_armed) {
        if (fp_gen_img() != FP_OK) {
            vTaskDelay(pdMS_TO_TICKS(FP_POLL_MS));
            continue;
        }
        fp_match_t m = fp_match_current_image();
        if (m == FP_MATCH) {
            fails = 0;
            fp_unlock();
            fp_wait_lift(2000);
        }
        else if (m == FP_NOMATCH) {
            if (++fails >= FP_MAX_FAILS) {
                fails = 0;
                vTaskDelay(pdMS_TO_TICKS(FP_LOCKOUT_MS));
            }
            else {
                fp_wait_lift(1000);
            }
        }
        else {
            vTaskDelay(pdMS_TO_TICKS(500));   // sensor not answering
        }
    }
    vTaskDelete(NULL);
}

bool fp_zw101_start(int tx_pin, int rx_pin) {
    // Decide "armed" now, before the first USB request can arrive.
    s_armed = fp_count_load() > 0;
    s_unlocked = false;
    if (!fp_uart_init(tx_pin, rx_pin)) {
        printf("ZW101: UART init failed\n");
        return false;
    }
    return xTaskCreate(fp_task, "fp_zw101", 4096, NULL, 2, NULL) == pdPASS;
}

// Overrides the SDK's empty weak hook, which runs just before the main loop starts.
int picokey_init(void) {
    fp_zw101_start(FP_ZW101_TX_PIN, FP_ZW101_RX_PIN);
    return 0;
}

#else // !ESP_PLATFORM: no sensor, behave like stock pico-fido

bool fp_zw101_start(int tx_pin, int rx_pin) { (void)tx_pin; (void)rx_pin; return false; }
bool fp_zw101_is_armed(void) { return false; }
bool fp_zw101_is_unlocked(void) { return true; }
bool fp_zw101_wait_unlocked(uint32_t wait_ms) { (void)wait_ms; return true; }
void fp_zw101_on_reset(void) {}

#endif
