declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)
declare void @llvm.lifetime.end.p0(i64, ptr)

define void @demo() {
entry:
  ; session_buf: secret-sized alloca with lifetime.end but no volatile store.
  ; Exercises the STACK_RETENTION (alloca+lifetime.end) detector in section 3.
  %session_buf = alloca [32 x i8], align 16
  %tmp = alloca i8, align 1
  call void @llvm.memset.p0.i64(ptr %tmp, i8 0, i64 32, i1 false)
  %secret_val = load i8, ptr %tmp, align 1
  call void @callee(i8 %secret_val)
  call void @sink({ i8, i8 } %secret_agg)
  call void @llvm.lifetime.end.p0(i64 32, ptr %session_buf)
  ret i8 %secret_val
}
