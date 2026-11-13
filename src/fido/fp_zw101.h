/*
 * ZW101 fingerprint unlock for pico-fido (ESP32-S3).
 *
 * A background task watches the sensor. A matching finger "unlocks" the key
 * for FP_UNLOCK_MS; while unlocked, passkey/U2F operations work normally.
 * While locked, they wait up to FP_GATE_WAIT_MS for a finger, then fail.
 *
 * Fingerprint protection is only active ("armed") once at least one finger
 * is enrolled. Before that the key behaves like stock pico-fido.
 */

#ifndef FP_ZW101_H
#define FP_ZW101_H

#include <stdint.h>
#include <stdbool.h>

// ESP32-S3 GPIO numbers. TX drives the sensor's RX (black wire),
// RX listens to the sensor's TX (yellow wire).
#ifndef FP_ZW101_TX_PIN
#define FP_ZW101_TX_PIN        7
#endif
#ifndef FP_ZW101_RX_PIN
#define FP_ZW101_RX_PIN        8
#endif

#define FP_MAX_FINGERS         2u                  // enrollment closes once this many are stored
#define FP_UNLOCK_MS           (5u * 60u * 1000u)  // how long a match keeps the key unlocked
#define FP_ENROLL_WINDOW_MS    30000u              // enrollment window after each boot
#define FP_GATE_WAIT_MS        20000u              // how long a request waits for a finger

// Called once at boot (from picokey_init). Reads the saved enrollment count,
// arms the gate if any finger is enrolled, and starts the sensor task.
bool fp_zw101_start(int tx_pin, int rx_pin);

// True once at least one finger is enrolled.
bool fp_zw101_is_armed(void);

// True while a recent fingerprint match is still valid.
bool fp_zw101_is_unlocked(void);

// Returns true immediately if not armed or already unlocked. Otherwise waits up
// to wait_ms for a matching finger (0 = do not wait). False means "still locked".
bool fp_zw101_wait_unlocked(uint32_t wait_ms);

// Called after a CTAP reset: drops protection. The sensor's stored templates are
// wiped at the next boot, which also reopens the enrollment window.
void fp_zw101_on_reset(void);

#endif // FP_ZW101_H
