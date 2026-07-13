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
 * C-ABI representation of the optional SEV-SNP firmware floor. `fmc == -1` means the deployment
 * does not require an FMC level (pre-Turin); otherwise it must fit in one byte.
 */
typedef struct NilSevSnpTcbFloor {
  int16_t fmc;
  uint8_t bootloader;
  uint8_t tee;
  uint8_t snp;
  uint8_t microcode;
} NilSevSnpTcbFloor;

/**
 * Tunnel configuration handed in from Swift.
 */
typedef struct NilConfig {
  const char *node_host;
  uint16_t node_port;
  const char *server_name;
  const char *measurement_hex;
  /**
   * SHA-256 of the node's exact TLS SPKI (32 bytes, hex); nullable only for debug fixtures.
   */
  const char *tls_spki_sha256_hex;
  /**
   * Ed25519 public key for the measurement transparency log (32 bytes, hex). Mandatory for
   * attested release builds; optional only in debug builds for local development.
   */
  const char *transparency_log_key_hex;
  const char *tee_name;
  bool allow_unattested;
  /**
   * Whether `min_tcb_sevsnp` is present. The separate bit preserves the distinction between an
   * absent policy and a valid all-zero floor with no FMC requirement.
   */
  bool has_min_tcb_sevsnp;
  struct NilSevSnpTcbFloor min_tcb_sevsnp;
  /**
   * Privacy Pass grant for this connection, redeemed in the container app and passed as hex.
   * `grant_hex` is the unblinded token bytes; `grant_nonce_hex` is the 32-byte RA-TLS freshness
   * nonce the node must bind into its attestation report. Both nullable/empty: when absent the
   * engine falls back to an empty token + a fresh random nonce (unauthenticated/Phase-1 path).
   */
  const char *grant_hex;
  const char *grant_nonce_hex;
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
 * Number of inbound packets dropped because the bounded queue was full/closed or the packet
 * exceeded the defensive size cap. This counter contains no endpoint or user identifier.
 *
 * # Safety
 * `t` must be a live handle from [`nil_start`].
 */
uint64_t nil_dropped_packets(const struct NilTunnel *t);

/**
 * Node-assigned inner IPv4 as a host integer whose bytes are in network order (`10.74.0.2` is
 * `0x0a4a0002`), or zero until connected/when the peer did not assign one.
 *
 * # Safety
 * `t` must be a live handle from [`nil_start`].
 */
uint32_t nil_assigned_ipv4(const struct NilTunnel *t);

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
