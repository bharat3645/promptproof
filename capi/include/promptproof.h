/*
 * C ABI for promptproof — a data-plane prompt-injection & exfiltration
 * scanner. See https://github.com/bharat3645/promptproof for the full
 * project; this header documents the stable extern "C" surface exported by
 * the promptproof-capi crate (built as libpromptproof_capi.{so,a}).
 *
 * Link against the built library and include this header:
 *
 *   cc -Iinclude your_program.c -Ltarget/release -lpromptproof_capi -o your_program
 *
 * (On Linux, also set LD_LIBRARY_PATH=target/release when linking against
 * the shared library, or link the static one instead.)
 */

#ifndef PROMPTPROOF_H
#define PROMPTPROOF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Scan `len` bytes at `input` for prompt-injection and exfiltration
 * signals. Returns a heap-allocated, NUL-terminated JSON report string —
 * the same shape as `promptproof scan --json` emits, e.g.:
 *
 *   {"source":"<capi>","verdict":"dangerous","score":9,
 *    "stats":{"bytes":42,"chars":40,"invisible_chars":0},
 *    "findings":[{"id":"instruction.ignore-previous", ...}]}
 *
 * `input` may be NULL only if `len` is 0 (an empty buffer). The bytes need
 * not be valid UTF-8 — invalid sequences are lossily replaced, never a hard
 * failure.
 *
 * Returns NULL if `input` is NULL while `len` is nonzero.
 *
 * The returned pointer must be freed with promptproof_free_string(), and
 * only with promptproof_free_string() — never with C's free(), since the
 * allocation was made by Rust's allocator.
 */
char *promptproof_scan(const unsigned char *input, size_t len);

/*
 * Free a string previously returned by promptproof_scan(). Passing NULL is
 * a safe no-op, matching C's free(NULL) convention. Passing any pointer not
 * returned by promptproof_scan(), or freeing the same pointer twice, is
 * undefined behavior.
 */
void promptproof_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* PROMPTPROOF_H */
