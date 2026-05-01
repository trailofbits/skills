	.text
	.type SecretKey_wipe,@function
SecretKey_wipe:
	subq	$64, %rsp
	movq	%rax, -8(%rsp)
	movq	%r12, -16(%rsp)
	retq
