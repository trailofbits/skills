define void @demo() {
entry:
  %secret_key = alloca [32 x i8], align 16
  %tmp = alloca i8, align 1
  store volatile i8 0, ptr %secret_key, align 1
  store volatile i8 0, ptr %secret_key, align 1
  %secret_val = load i8, ptr %tmp, align 1
  call void @callee(i8 %secret_val)
  call void @sink({ i8, i8 } %secret_agg)
  ret i8 %secret_val
}
