#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Opaque tunnel handle returned to Swift.
 */
typedef struct NilTunnel NilTunnel;

/**
 * Tunnel configuration handed in from Swift.
 */
typedef struct NilConfig {
  const char *node_host;
  uint16_t node_port;
  const char *server_name;
  const char *measurement_hex;
  bool allow_unattested;
} NilConfig;

/**
 * Inbound write callback: inject a decapsulated IP packet into `packetFlow`. `af` = 2 (AF_INET)
 * or 30 (AF_INET6).
 */
typedef void (*NilWriteCb)(void *ctx, const uint8_t *pkt, uintptr_t len, int32_t af);

/**
 * Status callback. `state`: 0=connecting, 1=connected, 2=failed, 3=stopped.
 */
typedef void (*NilStatusCb)(void *ctx, int32_t state, const char *detail);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Start the tunnel. Returns null on a config error; otherwise an owned handle (free via
 * [`nil_stop`]). Connection is asynchronous; progress is reported through `status_cb`.
 *
 * # Safety
 * `cfg` must be a valid `NilConfig` with valid (or null) C strings; `ctx`/callbacks must stay
 * valid until `nil_stop`.
 */
struct NilTunnel *nil_start(const struct NilConfig *cfg,
                            void *ctx,
                            NilWriteCb write_cb,
                            NilStatusCb status_cb);

/**
 * Feed packets read from `packetFlow` into the tunnel. Arrays are parallel and `count` long.
 *
 * # Safety
 * `t` must be a live handle from [`nil_start`]; the arrays must be valid for `count` elements.
 */
void nil_ingest_packets(const struct NilTunnel *t,
                        const uint8_t *const *pkts,
                        const uintptr_t *lens,
                        const int32_t *_afs,
                        uintptr_t count);

/**
 * The end-to-end usable MTU negotiated through the tunnel (0 until connected).
 *
 * # Safety
 * `t` must be a live handle from [`nil_start`].
 */
uint16_t nil_negotiated_mtu(const struct NilTunnel *t);

/**
 * Stop the tunnel, join the engine thread, and free the handle.
 *
 * # Safety
 * `t` must be a handle from [`nil_start`], not used afterward. Call at most once.
 */
void nil_stop(struct NilTunnel *t);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
