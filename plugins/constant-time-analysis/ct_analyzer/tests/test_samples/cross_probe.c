/**
 * Freestanding division sample for cross-compilation tests.
 *
 * Deliberately includes no headers. The triage fixtures include <stdint.h>,
 * which drags in the target's libc headers, so cross-compiling them needs a
 * cross sysroot installed — on a CI runner without one, clang fails with
 * "bits/libc-header-start.h file not found" and the test reports a regression
 * that is really a missing package. Nothing about verifying that a division
 * instruction reaches the assembly requires a libc.
 */

/* Secret-dependent division: the point of the probe. */
long probe_divide(long dividend, long divisor) {
    return dividend / divisor;
}

unsigned long probe_modulo(unsigned long dividend, unsigned long divisor) {
    return dividend % divisor;
}
