	.text
	.type SecretKey_wipe,@function
SecretKey_wipe:
	stp	x29, x30, [sp, #-64]!
	mov	x29, sp
	str	x19, [sp, #16]
	ldp	x29, x30, [sp], #64
	ret
