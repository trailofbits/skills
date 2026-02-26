	.text
	.type SecretKey_leaf,@function
SecretKey_leaf:
	# Leaf function: no subq frame allocation, uses x86-64 red zone.
	# Stores sensitive data to [rsp-8] and [rsp-16] without zeroing.
	# Exercises check_red_zone() → STACK_RETENTION (high).
	movq	%rdi, -8(%rsp)
	movq	%rsi, -16(%rsp)
	retq
