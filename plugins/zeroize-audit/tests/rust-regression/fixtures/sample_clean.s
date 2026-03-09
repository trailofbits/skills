	.text
	.type telemetry_write,@function
telemetry_write:
	# Non-sensitive function: name does not match any sensitive object.
	# Even with dangerous patterns, is_sensitive_function returns False → 0 findings.
	subq	$32, %rsp
	movq	$0, -8(%rsp)
	retq
