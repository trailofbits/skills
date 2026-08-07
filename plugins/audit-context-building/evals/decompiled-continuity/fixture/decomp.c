/*
 * Ghidra decompiler output. Target: MIPS32 big-endian, embedded RTOS.
 * Exported from the firmware image; only the functions below were recovered.
 * Calls to addresses outside this listing had no body in the image (ROM thunks,
 * unresolved library code) and are shown as raw FUN_ / thunk_ symbols.
 *
 * Addresses are 32-bit on the target and the decompiler emits them as int;
 * they are typedef'd to a pointer-sized integer here so the listing reads
 * cleanly on a 64-bit host.
 */

typedef unsigned char  undefined1;
typedef unsigned int   uint;
typedef unsigned int   undefined4;
typedef long           addr_t;

extern undefined1 DAT_8042c000[512];  /* .bss, adjacent symbols at +0x200 */
extern undefined4 DAT_8042bff0;
extern int        DAT_8042c400;

/* WARNING: unresolved external. No body in image. */
extern undefined4 FUN_80103f80(addr_t param_1, uint *param_2);

/* WARNING: unresolved external. No body in image. */
extern void thunk_FUN_801001c0(void *param_1, void *param_2, uint param_3);


undefined4 FUN_80104a2c(addr_t param_1, uint param_2)
{
    uint  local_len;
    undefined4 uVar1;

    if (param_2 < 8) {
        return 0xffffffff;
    }

    uVar1 = FUN_80103f80(param_1, &local_len);
    if (uVar1 != 0) {
        return 0xffffffff;
    }

    thunk_FUN_801001c0(DAT_8042c000, (void *)(param_1 + 8), local_len);

    DAT_8042bff0 = uVar1;
    return 0;
}


undefined4 FUN_80104b18(addr_t param_1, uint param_2)
{
    undefined4 uVar1;

    if (DAT_8042c400 == 0) {
        return 0xffffffff;
    }

    uVar1 = FUN_80104a2c(param_1, param_2);
    if (uVar1 == 0) {
        DAT_8042c400 = DAT_8042c400 + 1;
    }

    return uVar1;
}


void FUN_80104b90(void)
{
    int    iVar1;
    uint   uVar2;
    addr_t local_buf;

    while (1) {
        iVar1 = FUN_80103f80(0, &uVar2);
        if (iVar1 != 0) {
            break;
        }

        local_buf = (addr_t)DAT_8042c000;
        FUN_80104b18(local_buf, uVar2);
    }

    return;
}
