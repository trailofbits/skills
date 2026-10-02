/* Header-free matrix fixture: cross-target compilation needs no target libc. */
unsigned divide_secret(unsigned secret, unsigned divisor) {
    return secret / divisor;
}

unsigned branch_secret(unsigned secret) {
    if (secret > 7) return secret - 1;
    return secret + 1;
}
