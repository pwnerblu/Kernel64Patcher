/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#ifdef __gnu_linux__
    #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

static uint32_t arm64_branch_instruction(uintptr_t from, uintptr_t to) {
  return from > to ? 0x18000000 - (from - to) / 4 : 0x14000000 + (to - from) / 4;
}

// iOS 15 "%s: firmware validation failed %d\" @%s:%d SPU Firmware Validation Patch
int get_SPUFirmwareValidation_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char rootvpString[43] = "\"%s: firmware validation failed %d\" @%s:%d";
    void* ent_loc = memmem(kernel_buf,kernel_len,rootvpString,42);
    if(!ent_loc) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" ref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
        printf("%s: Could not find firmware validation function start\n",__FUNCTION__);
        return -1;
    }
    xref_stuff = xref64code(kernel_buf,0,(addr_t)GET_OFFSET(kernel_len, beg_func), beg_func);
    if(!xref_stuff) {
        printf("%s: Could not find previous xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found function xref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t next_bl = step64_back(kernel_buf, xref_stuff, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    beg_func = bof64(kernel_buf,0,next_bl);
    if(!beg_func) {
        printf("%s: Could not find start of firmware validation function\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching SPU Firmware Validation at %p\n\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0;
    return 0;
}

// iOS 15 rootvp not authenticated after mounting Patch
int get_RootVPNotAuthenticatedAfterMounting_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char rootVPString[40] = "rootvp not authenticated after mounting";
    char md0String[3] = "md0";
    void* ent_loc = memmem(kernel_buf,kernel_len,md0String,3);
    if(!ent_loc) {
        printf("%s: Could not find \"md0\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"md0\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff_md = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff_md) {
        printf("%s: Could not find \"md0\" xref\n",__FUNCTION__);
        return -1;
    }
    // this path wasn't working so i had to do this, the cbz before md0
    /*
    printf("%s: Found \"md0\" ref at %p\n",__FUNCTION__,(void*)xref_stuff_md);
    addr_t next_bl = step64(kernel_buf, xref_stuff_md + 0x8, 100, INSN_CALL);
    if(!next_bl) {
        // Newer devices will fail here, so using another string is required
        printf("%s: Failed to use \"md0\", swapping to \"rootvp not authenticated after mounting\"\n",__FUNCTION__);
        ent_loc = memmem(kernel_buf,kernel_len,rootVPString,39);
        if(!ent_loc) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" string\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
        addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
        if(!xref_stuff) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" xref\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str xref at %p\n",__FUNCTION__,(void*)xref_stuff);
        addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
        if(!beg_func) {
            printf("%s: Could not find function start\n",__FUNCTION__);
            return -1;
        }
        beg_func = beg_func + 0xA98;
        printf("%s: Found function start at %p\n",__FUNCTION__,(void*)beg_func);
        next_bl = step64(kernel_buf, beg_func, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    } else {
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }

    printf("%s: Patching ROOTVP at %p\n\n", __FUNCTION__,(void*)(next_bl + 0x4));
    *(uint32_t *) (kernel_buf + next_bl + 0x4) = 0xD503201F;
    */
    
    printf("%s: Patching ROOTVP at %p\n\n", __FUNCTION__,(void*)(xref_stuff_md + 0xC));
    // bl #0x243934 to movz x0, #0x1
    *(uint32_t *) (kernel_buf + xref_stuff_md - 0xC) = 0xD2800020;

    // bl #0xffffffffffbf0714 (strncmp) to movz x0, #0
    *(uint32_t *) (kernel_buf + xref_stuff_md + 0x18) = 0xD2800000;
    return 0;
}

// iOS 15 AMFI Kernel Patch
int get_AMFIInitializeLocalSigningPublicKey_patch(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char AMFIString[52] = "\"AMFI: %s: unable to obtain local signing public key";
    void* ent_loc = memmem(kernel_buf,kernel_len,AMFIString,51);
    if(!ent_loc) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key ref at %p\n",__FUNCTION__,(void*)xref_stuff);

    printf("%s: Patching \"Local Signing Public Key\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff + 0x4));
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0xD503201F;
    
    return 0;
}

// tested on an ipad 6 on ios 13.7, this was done to avoid wait like 2 or 10 minutes when it is booting
int disableTouchidSensor(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    addr_t xref_stuff;
    addr_t beg_func;
    void *str_stuff;

    printf("[*] Patching AppleBiometricSensor\n");
    str_stuff = memmem(kernel_buf, kernel_len, "_sepTransactResponse", 21);
    if (!str_stuff)
    {
        printf("[-] Failed to find _sepTransactResponse\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000; // mov w0, #0
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F0FFF; // retab
    printf("[+] Patched AppleBiometricSensor\n");

    return 0;
}

// containermanagerd haxx
int containermanagerd_patch(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    addr_t xref_stuff;
    addr_t xref_stuff2;
    addr_t xref_stuff3;
    addr_t beg_func;
    addr_t beg_func2;
    addr_t beg_func3;
    void *str_stuff;
    void *str_stuff2;
    void *str_stuff3;
    printf("[*] Patching -[MCMFileManager createDirectoryAtURL:withIntermediateDirectories:mode:class:error:]\n");
    str_stuff = memmem(kernel_buf, kernel_len, "-[MCMFileManager createDirectoryAtURL:withIntermediateDirectories:mode:class:error:]", 84);
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000; // mov w0, #0
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    printf("[*] Patched -[MCMFileManager createDirectoryAtURL:withIntermediateDirectories:mode:class:error:]\n");
    return 0;
}

// cryptex validation patch (improved)
int cryptex_patch(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    addr_t xref_stuff;
    addr_t xref_stuff2;
    addr_t xref_stuff3;
    addr_t beg_func;
    addr_t beg_func2;
    addr_t beg_func3;
    void *str_stuff;
    void *str_stuff2;
    void *str_stuff3;
    printf("[*] Patching Img4DecodeGetPropertyData\n");
    str_stuff = memmem(kernel_buf, kernel_len, "Img4DecodeGetPropertyData: [%d %s]", 34);
    if (!str_stuff)
    {
        printf("[-] Failed to find Img4DecodeGetPropertyData: [%%d %%s]\n");
        printf("[*] Assuming this is a kernel for iOS 17.4 or later, using string Img4DecodePerformTrustEvaluationWithCallbacks: %%d instead\n");
        str_stuff = memmem(kernel_buf, kernel_len, "Img4DecodePerformTrustEvaluationWithCallbacks: %d", 49);
        if (!str_stuff)
        {
            printf("[-] Failed to find Img4DecodePerformTrustEvaluationWithCallbacks: %%d\n");
            return -1;
        }
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000; // mov w0, #0
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    printf("[+] Patched Img4DecodeGetPropertyData\n");
    return 0;
}

// cryptex validation patch (improved)
int cryptex_patch_arm64e(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    addr_t xref_stuff;
    addr_t xref_stuff2;
    addr_t xref_stuff3;
    addr_t beg_func;
    addr_t beg_func2;
    addr_t beg_func3;
    void *str_stuff;
    void *str_stuff2;
    void *str_stuff3;
    printf("[*] Patching Img4DecodeGetPropertyData\n");
    str_stuff = memmem(kernel_buf, kernel_len, "Img4DecodeGetPropertyData: [%d %s]", 34);
    if (!str_stuff)
    {
        printf("[-] Failed to find Img4DecodeGetPropertyData: [%%d %%s]\n");
        printf("[*] Assuming this is a kernel for iOS 17.4 or later, using string Img4DecodePerformTrustEvaluationWithCallbacks: %%d instead\n");
        str_stuff = memmem(kernel_buf, kernel_len, "Img4DecodePerformTrustEvaluationWithCallbacks: %d", 49);
        if (!str_stuff)
        {
            printf("[-] Failed to find Img4DecodePerformTrustEvaluationWithCallbacks: %%d\n");
            return -1;
        }
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000; // mov w0, #0
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F0FFF; // retab
    printf("[+] Patched Img4DecodeGetPropertyData\n");
    return 0;
}

int ios17_patch(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    addr_t xref_stuff;
    addr_t beg_func;
    addr_t mov_x2_x0;
    addr_t bl_instr;
    addr_t cbnz_instr;
    void *str_stuff;
    uint32_t instr;
    
    printf("[*] Patching loading identity to handle\n");
    
    // Find the "Loading identity" string
    str_stuff = memmem(kernel_buf, kernel_len, "%s%s:%s%s%s%s%u:%s%u:%s Loading identity %s to handle %d%s\n", 60);
    if(!str_stuff) {
        printf("%s: Could not find \"AppleSEPKeyStore: Loading identity to handle\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found string at %p\n",__FUNCTION__, GET_OFFSET(kernel_len, str_stuff));
    
    // Find the xref to this string
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    if(!xref_stuff) {
        printf("%s: Could not find \"AppleSEPKeyStore: Loading identity to handle\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found xref at %p\n",__FUNCTION__, (void*)xref_stuff);
    
    // Find the function start
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    if(!beg_func) {
        printf("%s: Could not find function start\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found function start at %p\n",__FUNCTION__, (void*)beg_func);
    
    // Find "mov x2, x0" (encoding: 0xaa0003e2)
    // This searches forward from function start
    mov_x2_x0 = step64(kernel_buf, beg_func, 390, 0xaa0003e2, 0xFFFFFFFF);
    if(!mov_x2_x0) {
        printf("%s: Could not find \"mov x2, x0\"\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"mov x2, x0\" at %p\n",__FUNCTION__, (void*)mov_x2_x0);
    
    // Find the BL instruction immediately after "mov x2, x0"
    // BL has encoding 0x94000000 (unconditional call)
    bl_instr = step64(kernel_buf, mov_x2_x0 + 0x4, 50, INSN_CALL);
    if(!bl_instr) {
        printf("%s: Could not find BL after \"mov x2, x0\"\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found BL at %p\n",__FUNCTION__, (void*)bl_instr);
    
    // The CBNZ should be immediately after the BL (very next instruction)
    cbnz_instr = bl_instr + 0x4;
    instr = *(uint32_t *)(kernel_buf + cbnz_instr);
    
    // Verify it's a CBNZ/CBZ instruction
    // CBNZ/CBZ mask: 0x7E000000, base: 0x34000000
    if((instr & 0x7E000000) != 0x34000000) {
        printf("%s: Instruction at %p is not CBNZ/CBZ (got 0x%08x)\n",__FUNCTION__, (void*)cbnz_instr, instr);
        return -1;
    }
    printf("%s: Found CBNZ at %p with instruction 0x%08x\n",__FUNCTION__, (void*)cbnz_instr, instr);
    
    // Convert first CBNZ to CBZ by flipping bit 24 (0x01000000)
    // CBNZ W0: 0x35000000 + immediate
    // CBZ W0:  0x34000000 + immediate
    // Difference is bit 24
    uint32_t cbz_instr = instr ^ 0x01000000;
    
    //printf("%s: Converting first CBNZ (0x%08x) at %p to CBZ (0x%08x)\n",
    //       __FUNCTION__, instr, (void*)cbnz_instr, cbz_instr);
    //*(uint32_t *)(kernel_buf + cbnz_instr) = cbz_instr;
    
    // Find the second CBNZ after the first one (not immediate, search forward)
    addr_t second_cbnz = step64(kernel_buf, cbnz_instr + 0x4, 100, 0x34000000, 0x7E000000);
    if(!second_cbnz) {
        printf("%s: Could not find second CBNZ after first\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found second CBNZ at %p\n",__FUNCTION__, (void*)second_cbnz);
    
    // Get the second CBNZ instruction and verify it's a CBNZ/CBZ
    uint32_t second_instr = *(uint32_t *)(kernel_buf + second_cbnz);
    if((second_instr & 0x7E000000) != 0x34000000) {
        printf("%s: Second instruction at %p is not CBNZ/CBZ (got 0x%08x)\n",__FUNCTION__, (void*)second_cbnz, second_instr);
        return -1;
    }
    printf("%s: Found second CBNZ at %p with instruction 0x%08x\n",__FUNCTION__, (void*)second_cbnz, second_instr);
    
    // Convert second CBNZ to CBZ by flipping bit 24 (0x01000000)
    uint32_t second_cbz_instr = second_instr ^ 0x01000000;
    
    printf("%s: Converting second CBNZ (0x%08x) at %p to CBZ (0x%08x)\n",
           __FUNCTION__, second_instr, (void*)second_cbnz, second_cbz_instr);
    *(uint32_t *)(kernel_buf + second_cbnz - 0x8) = 0xd503201f; // nop
    //*(uint32_t *)(kernel_buf + second_cbnz - 0x4) = 0xd503201f; // nop
    *(uint32_t *)(kernel_buf + second_cbnz) = second_cbz_instr;
    
    printf("[+] Patched loading identity to handle\n");
    return 0;
}

// cryptex validation patch (improved)
int libimg4_patch_174(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    addr_t xref_stuff;
    addr_t xref_stuff2;
    addr_t xref_stuff3;
    addr_t beg_func;
    addr_t beg_func2;
    addr_t beg_func3;
    void *str_stuff;
    void *str_stuff2;
    void *str_stuff3;
    printf("[*] Patching Img4DecodePerformTrustEvaluationWithCallbacks\n");
    str_stuff = memmem(kernel_buf, kernel_len, "Img4DecodePerformTrustEvaluationWithCallbacks: %d", 49);
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000; // mov w0, #0
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F0FFF; // retab
    printf("[+] Patched Img4DecodePerformTrustEvaluationWithCallbacks\n");
    return 0;
}

// based on seprmvr, thank you so much mineek, i implemented it because here are linux users. 
int fuck_the_sep(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    addr_t xref_stuff;
    addr_t beg_func;
    void *str_stuff;
    
    void* xnu_vers = memmem(kernel_buf,kernel_len,"root:xnu-",9);
    int kernel_vers = atoi(xnu_vers+9);

    printf("[*] Patching sks timeout strike\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleKeyStore: sks timeout strike %d", 36);
    if (!str_stuff)
    {
        printf("[-] Failed to find sks timeout strike\n");
        return -1;
    }

    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched sks timeout strike\n");

    printf("[*] Patching SEP Panicked\n");
    str_stuff = memmem(kernel_buf, kernel_len, "\x1b[35m ***** SEP Panicked! dumping log. *****\x1b[0m", 36);
    // on ios 12.4 kernel sep panicked not work for me. so it just jump this. 
    int errorsad = 1;
    if (!str_stuff)
    {
        printf("[-] Failed to find SEP Panicked\n");
        errorsad = 0;
    }

    if (errorsad == 1)
    {
        xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
        beg_func = bof64(kernel_buf, 0, xref_stuff);
        *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
        *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
        printf("[+] Patched SEP Panicked\n");
    }
    
    printf("[*] Patching AppleKeyStore: operation failed\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleKeyStore: operation %s(pid: %d se", 38);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleKeyStore: operation failed\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    while (*(uint32_t *)(kernel_buf + xref_stuff) != 0xD63F0100)
    {
        xref_stuff -= 0x4;
    }
    *(uint32_t *)(kernel_buf + xref_stuff) = 0xD2800000;
    printf("[+] Patched AppleKeyStore: operation failed\n");

    if (kernel_vers == 4903) {
        // did everything needed already for iOS 12
        printf("%s: quitting...\n", __FUNCTION__);
        return 0;
    }

    printf("[*] Patching AppleMesaSEPDriver\n");
    str_stuff = memmem(kernel_buf, kernel_len, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleMesaSEPDriver\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleMesaSEPDriver\n");

    //AppleSEP:WARNING: EP0 received unsolicited message
    printf("[*] Patching AppleSEP:WARNING: EP0 received unsolicited message\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleSEP:WARNING: EP0 received unsolicited message", 48);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleSEP:WARNING: EP0 received unsolicited message\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleSEP:WARNING: EP0 received unsolicited message\n");

    //SEP/OS failed to boot at stage
    printf("[*] Patching SEP/OS failed to boot at stage\n");
    str_stuff = memmem(kernel_buf, kernel_len, "\"SEP/OS failed to boot at stage %d\\nFirmware type: %s\"@/BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleSEPManager", 96);
    if (!str_stuff)
    {
        printf("[-] Failed to find SEP/OS failed to boot at stage\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched SEP/OS failed to boot at stage\n");

    //AppleBiometricSensor: RECOVERY: Reason %d, Last command 0x%x
    printf("[*] Patching AppleBiometricSensor: RECOVERY\n");
    str_stuff = memmem(kernel_buf, kernel_len, "AppleBiometricSensor: RECOVERY: Reason %d, Last command 0x%x", 57);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleBiometricSensor: RECOVERY\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleBiometricSensor: RECOVERY\n");

    //ERROR: %s: _sensorErrorCounter:%u --> reset\n
    printf("[*] Patching _sensorErrorCounter: --> reset\n");
    str_stuff = memmem(kernel_buf, kernel_len, "ERROR: %s: _sensorErrorCounter:%u --> reset\\n", 41);
    if (!str_stuff)
    {
        printf("[-] Failed to find _sensorErrorCounter: --> reset\n");
        return -1;
    }
    xref_stuff = xref64(kernel_buf, 0, kernel_len, (addr_t)GET_OFFSET(kernel_len, str_stuff));
    beg_func = bof64(kernel_buf, 0, xref_stuff);
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched _sensorErrorCounter: --> reset\n");
    
    //ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d\n\n
    printf("[*] Patching ERROR: AssertMacros\n");
    str_stuff = memmem(kernel_buf, kernel_len, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        printf("[-] Failed to find ERROR: AssertMacros\n");
        return -1;
    }
    int done = 0;
    while (!done)
    {
        xref_stuff = xref64(kernel_buf, xref_stuff + 1, kernel_len, (addr_t)GET_OFFSET(klen, str_stuff));
        if (xref_stuff == 0)
        {
            done = 1;
            break;
        }
        beg_func = bof64(kernel_buf, 0, xref_stuff);
        if (*(uint32_t *)(kernel_buf + beg_func + 0x18) == 0xb4000293)
        {
            printf("[+] Skipped ERROR: AssertMacros at 0x%llx\n", beg_func);
            continue;
        }
        *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
        *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
        printf("[+] Patched ERROR: AssertMacros at 0x%llx\n", beg_func);
    }
    printf("[+] Patched ERROR: AssertMacros\n");
    printf("%s: quitting...\n", __FUNCTION__);

    return 0;

}

// aslr
int pathAslr(void* kernel_buf,size_t kernel_len) {
    
    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[7] = "__XHDR";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string, 7);
    if(!ent_loc) {
        printf("%s: Could not find \"__XHDR, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"__XHDR\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len, ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find \"__XHDR\" xref\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"__XHDR\" xref at %p\n",__FUNCTION__,(void*)ent_ref);
    addr_t start_func = bof64(kernel_buf,0, ent_ref);
    if(!start_func) {
        printf("%s: Could not find load load_code_signature start\n",__FUNCTION__);
        return -1;
    }

    // check for ios 15
    uint32_t tbnz1_ref = step64_back(kernel_buf, (start_func + 0x374), 150 * 4, 0x36000000, 0x7E000000);
    uint32_t instMemValToCheck = *((uint32_t *)(kernel_buf + (tbnz1_ref - 0x4))); // on ios 15 before the tbnz function it has the ldrb function that we need to path

    if (instMemValToCheck == 0x394122C8)
    {
        printf("ios 15 Detected!\n");
        printf("%s: Patched ldrb    w8, [x22, #0x48] to mov x8, #0x20 at %p\n",__FUNCTION__, (void*) tbnz1_ref);
        *((uint32_t *)(kernel_buf + (tbnz1_ref - 0x4))) = 0xD2800408;
        return 0;
    }
    
    ent_ref = xref64code(kernel_buf,0,(addr_t)GET_OFFSET(kernel_len, start_func), start_func);
    if(!ent_ref) {
        printf("%s: Could not find load_code_signature xref to load_machfile\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found function xref at %p\n",__FUNCTION__,(void*)ent_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, ent_ref, 150 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    uint32_t memValToCheck = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x8))); // ios 14 is 8 bytes before
    uint32_t memValToCheck4 = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4))); // ios 13 is 4 bytes before
    
    if ((memValToCheck == 0xd2800408) || (memValToCheck4 == 0xd2800419) || (memValToCheck4 == 0xd2800408)) {
        printf("Detected, ASLR was already patched Omitting\n");
        return 0;
    } else if (memValToCheck == 0x394122c8) {
        *((uint32_t *)(kernel_buf + (tbnz_ref - 0x8))) = 0xd2800408; // ios 14 the ldrb instruction to path is 8 byte before the tbnz
    } else if (memValToCheck4 == 0x394122c8) {
        *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4))) = 0xd2800408; // ios 13 the ldrb instruction to path is 4 byte before the tbnz
    } else if (memValToCheck4 == 0xb9404a99) {
        *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4))) = 0xd2800419; // ios 11 the ldr instruction to path is 4 byte before the tbnz and it uses w25.
    } else {
        printf("we couldn't find the instruction to path");
        return -1;
    }

    printf("%s: Patched ldrb    w8, [x22, #0x48] at %p\n",__FUNCTION__, (void*) tbnz_ref);
    return 0;
}

size_t find_pattern(const unsigned char *buffer, size_t buflen, const unsigned char *pattern, const unsigned char *mask, size_t pattern_len) {
    size_t i, j;

    for (i = 0; i < buflen - pattern_len + 1; ++i) {
        for (j = 0; j < pattern_len; ++j) {
            if ((buffer[i + j] & mask[j]) != (pattern[j] & mask[j])) {
                break;
            }
        }
        if (j == pattern_len) {
            printf("Pattern found at offset: %zu\n", i);
            //printf("value in hexadecimal: %p\n", (void *)buffer[i]);
            return i;
        }
    }
    return 0; // Return 0 if pattern is not found
}

int pathPtrace(void* kernel_buf,size_t kernel_len) {
    printf("looking for the bytes in %p\n", kernel_buf);
    unsigned char pattern[] = { 0xB3, 0x62, 0x01, 0x91, 0xE0, 0x03, 0x13, 0xAA, 0x35, 0x7B, 0xF3, 0x97, 0xA8, 0x6A, 0x42, 0xB9, 0x68, 0x29, 0x50, 0x37, 0x08, 0x01, 0x14, 0x32 }; // ios 15
    unsigned char mask[]    = { 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x0F, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xF0, 0x00, 0xF0, 0xFF, 0x0F, 0x00, 0xF0, 0xFF, 0x00, 0xF0, 0xFF, 0xFF };
    
    unsigned char pattern14[] = { 0xE0, 0x03, 0x15, 0xAA, 0x02, 0x00, 0x80, 0x52, 0x08, 0x11, 0xF4, 0x97, 0x88, 0x4A, 0x41, 0xB9, 0xA8, 0xFC, 0x57, 0x37, 0x08, 0x01, 0x14, 0x32 };
    unsigned char mask14[] =    { 0xF0, 0xFF, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0xF0, 0xFF, 0xFF };

    unsigned char pattern13[] = { 0xE0, 0x03, 0x15, 0xAA, 0x02, 0x00, 0x80, 0x52, 0x08, 0x11, 0xF4, 0x97, 0x88, 0x4A, 0x41, 0xB9, 0xA8, 0xFC, 0x57, 0x37, 0x08, 0x01, 0x14, 0x32 };
    unsigned char mask13[] =    { 0xF0, 0xFF, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0x00, 0xF0, 0xFF, 0x00, 0xF0, 0xFF, 0xFF };
    /* // ios 15
        add x19, x21, #0x58
        mov x0, x19
        bl #0xffffffffffcdecdc // pc + 0xffffffffffcdecdc
        ldr w8, [x21, #0x268]
        tbnz w8, #0xa, #0x53c // pc + 0x53c
    */

    size_t pattern_len = sizeof(pattern);
    size_t buffer = find_pattern(kernel_buf, kernel_len, pattern, mask, pattern_len);

    if (buffer != 0) {
        //printf("Byte value at address %p: 0x%02X\n", (void *)(kernel_buf + buffer), *(unsigned char *)(kernel_buf + buffer + 12));
        *(uint32_t *) (kernel_buf + buffer + 12) = 0x52800008;
        *(uint32_t *) (kernel_buf + buffer + 16) = 0xd503201f;

        printf("Patching \"ptrace debugger method\"\n\n");
        return 0;
    } else {
        printf("We couldn't found the bytes of ptrace path, we are going to try with bytes for ios 14\n");
    }
    
    size_t pattern_len14 = sizeof(pattern14);
    buffer = find_pattern(kernel_buf, kernel_len, pattern14, mask14, pattern_len14);

    if (buffer != 0) {
        *(uint32_t *) (kernel_buf + buffer - 0x70) = 0xd2800000;
        *(uint32_t *) (kernel_buf + buffer - 0x6C) = 0x14000025; // b 0x94 to return correctly

        printf("Patching \"ptrace debugger method\"\n\n");
        return 0;
    } else {
        printf("We couldn't found the bytes of ptrace path for ios 14, we are going to try with bytes for ios 13\n");
    }



    size_t pattern_len13 = sizeof(pattern13);
    buffer = find_pattern(kernel_buf, kernel_len, pattern13, mask13, pattern_len13);

    if (buffer != 0) {

        *(uint32_t *) (kernel_buf + buffer - 0x8C) = 0xd2800000;
        *(uint32_t *) (kernel_buf + buffer - 0x88) = 0x140000ac; // b 0x2B0 to return correctly

        printf("Patching \"ptrace debugger method\"\n\n");
        return 0;
    } else {
        printf("We couldn't found the bytes of ptrace path for ios 13\n");
    }

    return -1;
}

int panic007Path(void* kernel_buf,size_t kernel_len) {
    unsigned char pattern[] = { 0x2a, 0x7d, 0x09, 0x53, 0x4a, 0x01, 0x1c, 0x12, 0x2b, 0x79, 0x1f, 0x53, 0x6b, 0x01, 0x15, 0x12, 0x68, 0x01, 0x08, 0x2a, 0x08, 0x01, 0x0a, 0x2a};
    unsigned char mask[]    = { 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xf0, 0xff, 0x00, 0xff, 0xf0, 0xff };
    
    size_t pattern_len = sizeof(pattern);
    size_t buffer = 0x0;
    buffer = find_pattern(kernel_buf, kernel_len, pattern, mask, pattern_len);
    
    if (buffer == 0) {
        printf("We couldn't found the bytes of panic007 path\n");
        return -1;
    }

    *(uint32_t *) (kernel_buf + buffer + 0x10) = 0xd503201f;
    
    printf("panic007 path applied\n");
}

int pathSnapshot(void* kernel_buf,size_t kernel_len) { // ios 15.8.2 iphone8,1 kernel

    printf("%s: Entering ...\n",__FUNCTION__);

    const char failed_to_jhash_insert[] = "%s:%d: %s failed to jhash_insert the root inode, error %d";
    void* ent_loc = memmem(kernel_buf,kernel_len,failed_to_jhash_insert,strlen(failed_to_jhash_insert));
    if(!ent_loc) {
        printf("%s: Could not find \"Failed to jhash_insert the root inode\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"Failed to jhash_insert the root inode\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"apfs_vfsop_mount\" xref\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"apfs_vfsop_mount call to Failed to jhash_insert the root inode str\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    printf("%s: Patching \"snapshot\" at %p\n\n", __FUNCTION__,(void*)(ent_ref + 0x14));
    
    uint32_t instMemValToCheck = *((uint32_t *)(kernel_buf + (ent_ref + 0x14))); // on ios 15 should be ldr w8, [sp, #0x80]
    if (instMemValToCheck != 0xb94083e8) {// e88340b9
        printf("[!] couldn't found the correct instruction to path snapshot at");
        return 0;
    }

    *(uint32_t *) (kernel_buf + ent_ref + 0x14) = 0xd2800008;
    return 0;
}

// load firmware which are not signed like AOP.img4, Homer.img4, etc. ios 15
int bypassFirmwareValidate15(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[23] = "firmware authenticated";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string,23);
    if(!ent_loc) {
        printf("%s: Could not find \"firmware authenticated, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"firmware authenticated\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"firmware authenticated\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"firmware authenticated\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    printf("%s: Patching \"firmware authenticated\" at %p\n\n", __FUNCTION__,(void*)(ent_ref + 0x24));
    *(uint32_t *) (kernel_buf + ent_ref + 0x24) = 0xd2800000;

    return 0;
}

// load firmware which are not signed like AOP.img4, Homer.img4, etc. ios 14
int bypassFirmwareValidate(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[55] = "Img4DecodePerformTrustEvaluationWithCallbacks: [%d %s]";
    void* found = memmem(kernel_buf,kernel_len,img4_sig_check_string,54);
    if(!found) {
        printf("%s: Could not find \"%%s::%%s() Img4DecodePerformTrustEvaluationWithCallbacks\" string\n",__FUNCTION__);
        return -1;
    }

    char img4_wrapped_Image4_payload[27] = "trust evaluation succeeded";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_wrapped_Image4_payload,26);
    if(!ent_loc) {
        printf("%s: Could not find \"trust evaluation succeeded\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"trust evaluation succeeded\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"trust evaluation succeeded\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"trust evaluation succeeded\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    // Search backward for the BL (branch-and-link) to the validation function
    addr_t validation_bl = step64_back(kernel_buf, ent_ref, 100 * 4, 0xFC000000, 0xFC000000); // BL mask
    if(!validation_bl) {
        printf("%s: Could not find validation BL, trying conditional branch\n",__FUNCTION__);
        // Try to find a CBZ/CBNZ that gates the error path instead
        addr_t cbz_ref = step64_back(kernel_buf, ent_ref, 50 * 4, 0x34000000, 0x7E000000);
        if(cbz_ref) {
            printf("%s: Found conditional branch at %p, NOPing it\n",__FUNCTION__,(void*)cbz_ref);
            *(uint32_t *)(kernel_buf + cbz_ref) = 0xd503201f;
            return 0;
        }
        printf("%s: Could not find any viable patch point\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found validation call at %p\n",__FUNCTION__,(void*)validation_bl);
    
    // NOP out the BL (replace with NOP so it skips the validation call entirely)
    printf("%s: NOPing validation call at %p\n",__FUNCTION__,(void*)validation_bl);
    *(uint32_t *)(kernel_buf + validation_bl) = 0xd503201f;

    return 0;
}

// load firmware which are not signed like AOP.img4, Homer.img4, etc. ios 13
int bypassFirmwareValidate13(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char first_string[45] = "Image4: Encrypted payloads are not supported";
    void* found = memmem(kernel_buf,kernel_len,first_string,44);
    if(!found) {
        printf("%s: Could not find \"Image4: Encrypted payloads are not supported, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"Image4: Encrypted payloads are not supported\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,found));
    addr_t found_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, found));

    if(!found_ref) {
        printf("%s: Could not find \"xref of Image4: Encrypted payloads are not supported\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"Image4: Encrypted payloads are not supported\" xref at %p\n",__FUNCTION__,(void*)found);

    printf("%s: Patching \"patching step 1\" at %p\n\n", __FUNCTION__,(void*)(found_ref + 0x50));
    *(uint32_t *) (kernel_buf + found_ref + 0x50) = 0xd503201f;
    printf("%s: Patching \"patching step 2\" at %p\n\n", __FUNCTION__,(void*)(found_ref - 0x50));
    *(uint32_t *) (kernel_buf + found_ref - 0x50) = 0xd503201f;

   char second_string[34] = "Image4: Payload hash check failed";
    void* second_found = memmem(kernel_buf,kernel_len,second_string,33);
    if(!second_found) {
        printf("%s: Could not find \"Image4: Payload hash check failed, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Found \"Image4: Payload hash check failed\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,second_found));
    addr_t second_found_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, second_found));

    if(!second_found_ref) {
        printf("%s: Could not find \"xref of Image4: Payload hash check failed\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"Image4: Payload hash check failed\" xref at %p\n",__FUNCTION__,(void*)second_found_ref);

    printf("%s: Patching \"patching step 3\" at %p\n\n", __FUNCTION__,(void*)(second_found_ref - 0x08));
    *(uint32_t *) (kernel_buf + second_found_ref - 0x08) = 0x17ffff96;

    return 0;
}

//iOS 14 AppleFirmwareUpdate img4 signature check
int get_AppleFirmwareUpdate_img4_signature_check(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[56] = "%s::%s() Performing img4 validation outside of workloop";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string,55);
    if(!ent_loc) {
        printf("%s: Could not find \"%%s::%%s() Performing img4 validation outside of workloop\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s::%%s() Performing img4 validation outside of workloop\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"%%s::%%s() Performing img4 validation outside of workloop\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s::%%s() Performing img4 validation outside of workloop\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    printf("%s: Patching \"%%s::%%s() Performing img4 validation outside of workloop\" at %p\n\n", __FUNCTION__,(void*)(ent_ref + 0xc));
    *(uint32_t *) (kernel_buf + ent_ref + 0xc) = 0xD2800000;

    return 0;
}

static addr_t
cbz_ref64_back(const uint8_t *buf, addr_t start, size_t length) {

    //find cbz/cbnz
    uint32_t cbz_mask = 0x7E000000;
    uint32_t instr = 0;
    uint32_t imm = 0;
    addr_t cbz = start;
    while (cbz) {
        instr = *(uint32_t *) (buf + cbz);
        if ((instr & cbz_mask) == 0x34000000) {
            imm = ((instr & 0x00FFFFFF) >> 5) << 2;
            if (cbz + imm == start)
                return cbz;
        }
        cbz -= 4;
    }
    return 0;
}

//iOS 15 "could not authenticate personalized root hash!" patch
int get_could_not_authenticate_personalized_root_hash_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    //get target offset for new branch
    char roothash_authenticated_string[sizeof("successfully validated on-disk root hash")] = "successfully validated on-disk root hash";

    unsigned char *roothash_authenticated_loc = memmem(kernel_buf, kernel_len, roothash_authenticated_string, sizeof("successfully validated on-disk root hash") - 1);
    if(!roothash_authenticated_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_authenticated_string);
        return -1;
    }

    for (; *roothash_authenticated_loc != 0; roothash_authenticated_loc--);
    roothash_authenticated_loc++;
    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_authenticated_string, GET_OFFSET(kernel_len, roothash_authenticated_loc));

    addr_t roothash_authenticated_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_authenticated_loc));
    if(!roothash_authenticated_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_authenticated_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_authenticated_string, (void*) roothash_authenticated_ref);

    //get previous cbz
    addr_t branch_target = step64_back(kernel_buf, roothash_authenticated_ref, 20 * 4, 0x34000000, 0x7E000000);
    if(!branch_target) {
        printf("%s: Could not find previous cbz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found previous cbz at %p\n",__FUNCTION__, (void*) branch_target);
    branch_target++;

    //get patching offset for new branch
    char roothash_failed_string[sizeof("could not authenticate personalized root hash!")] = "could not authenticate personalized root hash!";

    unsigned char *roothash_failed_loc = memmem(kernel_buf, kernel_len, roothash_failed_string, sizeof("could not authenticate personalized root hash!") - 1);
    if(!roothash_failed_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_failed_string);
        return -1;
    }

    for (; *roothash_failed_loc != 0; roothash_failed_loc--);
    roothash_failed_loc++;
    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_failed_string, GET_OFFSET(kernel_len, roothash_failed_loc));

    addr_t roothash_failed_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_failed_loc));
    if(!roothash_failed_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_failed_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_failed_string, (void*) roothash_failed_ref);

    addr_t patch_loc = 0;

    for (int i = 0; i < 16; i++, roothash_failed_ref -= 4) {
        if (cbz_ref64_back(kernel_buf, roothash_failed_ref, roothash_failed_ref)) {
            printf("%s: Found cbz target at %p\n", __FUNCTION__, (void*) roothash_failed_ref);
            patch_loc = roothash_failed_ref;
            break;
        }
    }

    if (!patch_loc) {
        printf("%s: Could not find cbz target\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Patching root hash check at %p\n",__FUNCTION__, (void*) patch_loc);
    *((uint32_t *) (kernel_buf + patch_loc)) = arm64_branch_instruction((uintptr_t) patch_loc, (uintptr_t) branch_target);

    return 0;
}

int get_root_volume_seal_is_broken_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    char roothash_authenticated_string[sizeof("\"root volume seal is broken %p\\n\"")] = "\"root volume seal is broken %p\\n\"";

    unsigned char *roothash_authenticated_loc = memmem(kernel_buf, kernel_len, roothash_authenticated_string, sizeof("\"root volume seal is broken %p\\n\"") - 1);
    if(!roothash_authenticated_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_authenticated_string);
        return -1;
    }

    for (; *roothash_authenticated_loc != 0; roothash_authenticated_loc--);
    roothash_authenticated_loc++;

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_authenticated_string, GET_OFFSET(kernel_len, roothash_authenticated_loc));

    addr_t roothash_authenticated_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_authenticated_loc));
    if(!roothash_authenticated_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_authenticated_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_authenticated_string, (void*) roothash_authenticated_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, roothash_authenticated_ref, 20 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);

    printf("%s: Patching tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    *((uint32_t *) (kernel_buf + tbnz_ref)) = 0xd503201f;
    printf("%s: Patched tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    return 0;
}

// NEW: Patch "unencrypted data volume is not allowed" @%s:%d
int get_unencrypted_data_volume_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    char unencrypted_data_volume_string[sizeof("\"unencrypted data volume is not allowed\" @%s:%d")] = "\"unencrypted data volume is not allowed\" @%s:%d";

    unsigned char *unencrypted_data_volume_loc = memmem(kernel_buf, kernel_len, unencrypted_data_volume_string, sizeof("\"unencrypted data volume is not allowed\" @%s:%d") - 1);
    if(!unencrypted_data_volume_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, unencrypted_data_volume_string);
        return -1;
    }

    for (; *unencrypted_data_volume_loc != 0; unencrypted_data_volume_loc--);
    unencrypted_data_volume_loc++;

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, unencrypted_data_volume_string, GET_OFFSET(kernel_len, unencrypted_data_volume_loc));

    addr_t unencrypted_data_volume_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, unencrypted_data_volume_loc));
    if(!unencrypted_data_volume_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, unencrypted_data_volume_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, unencrypted_data_volume_string, (void*) unencrypted_data_volume_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, unencrypted_data_volume_ref, 20 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);

    printf("%s: Patching tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    *((uint32_t *) (kernel_buf + tbnz_ref)) = 0xd503201f;
    printf("%s: Patched tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);
    return 0;
}

int get_update_rootfs_rw_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    char update_rootfs_rw_string[sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all")] = "%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all";
    unsigned char *update_rootfs_rw_loc = memmem(kernel_buf, kernel_len, update_rootfs_rw_string, sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all") - 1);
    
    if(!update_rootfs_rw_loc) {
        
        char update_rootfs_rw_string[sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all")] = "%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all";
        unsigned char *update_rootfs_rw_loc = memmem(kernel_buf, kernel_len, update_rootfs_rw_string, sizeof("%s:%d: %ss%d:%.0lld Updating mount to read/write mode is not all") - 1);
        if (!update_rootfs_rw_loc)
        {
            printf("%s: Could not find \"%s\" string\n", __FUNCTION__, update_rootfs_rw_string);
            return -1;

        }
        
    }


    for (; *update_rootfs_rw_loc != 0; update_rootfs_rw_loc--);
    update_rootfs_rw_loc++;

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, update_rootfs_rw_string, GET_OFFSET(kernel_len, update_rootfs_rw_loc));

    addr_t update_rootfs_rw_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, update_rootfs_rw_loc));
    if(!update_rootfs_rw_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, update_rootfs_rw_string);
        return -1;
    }

    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, update_rootfs_rw_string, (void*) update_rootfs_rw_ref);

    addr_t tbnz_ref = step64_back(kernel_buf, update_rootfs_rw_ref, 200 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref);

    addr_t tbnz_ref2 = step64_back(kernel_buf, tbnz_ref - 4, 200 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref2) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref2);

    printf("%s: Patching tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref2);
    *((uint32_t *) (kernel_buf + tbnz_ref2)) = 0xd503201f;
    printf("%s: Patched tbnz at %p\n",__FUNCTION__, (void*) tbnz_ref2);

    return 0;
}

int get_amfi_out_of_my_way_patch(void* kernel_buf,size_t kernel_len) {
    
    printf("%s: Entering ...\n",__FUNCTION__);
    
    void* xnu = memmem(kernel_buf,kernel_len,"root:xnu-",9);
    int kernel_vers = atoi(xnu+9);
    printf("%s: Kernel-%d inputted\n",__FUNCTION__, kernel_vers);
    char amfiString[33] = "entitlements too small";
    int stringLen = 22;
    if (kernel_vers >= 7938) { // Using "entitlements too small" fails on iOS 15 Kernels
        strncpy(amfiString, "Internal Error: No cdhash found.", 33);
        stringLen = 32;
    }
    void* ent_loc = memmem(kernel_buf,kernel_len,amfiString,stringLen);
    if(!ent_loc) {
        printf("%s: Could not find %s string\n",__FUNCTION__, amfiString);
        return -1;
    }
    printf("%s: Found %s str loc at %p\n",__FUNCTION__,amfiString,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find %s xref\n",__FUNCTION__,amfiString);
        return -1;
    }
    printf("%s: Found %s str ref at %p\n",__FUNCTION__,amfiString,(void*)ent_ref);
    addr_t next_bl = step64(kernel_buf, ent_ref, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    if(kernel_vers>3789) { 
        next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }
    addr_t function = follow_call64(kernel_buf, next_bl);
    if(!function) {
        printf("%s: Could not find function bl\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching AMFI at %p\n",__FUNCTION__,(void*)function);
    *(uint32_t *)(kernel_buf + function) = 0x320003E0;
    *(uint32_t *)(kernel_buf + function + 0x4) = 0xD65F03C0;
    return 0;
}

int is_root_hash_authentication_required_ios_patch(void* kernel_buf,size_t kernel_len) {
    char authentication_required_string[sizeof("is_root_hash_authentication_required_ios")] = "is_root_hash_authentication_required_ios";

    unsigned char *authentication_required_loc = memmem(kernel_buf, kernel_len, authentication_required_string, sizeof("is_root_hash_authentication_required_ios") - 1);

    if(!authentication_required_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, authentication_required_string);
        return -1;
    }

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, authentication_required_string, GET_OFFSET(kernel_len, authentication_required_loc));

    addr_t authentication_required_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, authentication_required_loc));
    
    if(!authentication_required_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, authentication_required_string);
        return -1;
    }

    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, authentication_required_string, (void*) authentication_required_ref);
    addr_t function = bof64(kernel_buf, 0, authentication_required_ref);
    
    printf("%s: Patching is_root_hash_authentication_required_ios at %p\n",__FUNCTION__,(void*)function);
    
    *(uint32_t *)(kernel_buf + function) = 0xD2800000;
    *(uint32_t *)(kernel_buf + function + 0x4) = 0xD65F0FFF;
    return 0;
}

int get_aks_patch(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n", __FUNCTION__);

    // ================================================================
    // Patch AppleKeyStoreUserClient::externalMethod — selector gate
    // ================================================================
    //
    // CONTEXT:
    // iOS 17.0 tether downgrade on iPhone XR with ephemeral storage.
    // keybagd never loads, so ALL AKS handlers (sel 1+) fail natively.
    // This includes sel 17/35 (extended/opaque state queries that return
    // DER-encoded device state) — their failure makes SpringBoard show
    // a passcode screen even when sel 7 correctly reports noPin.
    //
    // Gate logic:
    //   sel == 0           → native dispatch (open/init, always works)
    //   sel == 7           → write scalarOutput[0] = 0x6, return 0
    //   sel == 17          → write DER {ss=4, sls=3} to structureOutput, return 0
    //   sel == 35          → write DER full state to structureOutput, return 0
    //   all others (1+)    → return 0 (fake success, no output)
    //
    // Implementation:
    //   1. Find zero-padding code cave at end of __TEXT_EXEC
    //   2. Write gate code + DER data blobs into the cave
    //   3. Replace pacibsp at externalMethod entry with B to the cave
    //
    // VALUE: 0x6 = noPin(0x2) | beenUnlocked(0x4), locked(0x1) clear.
    //   _MKBDeviceUnlockedSinceBoot reads scalarOutput[0] bit 2.
    //
    // ABI (IOExternalMethodArguments, LP64 layout):
    //   +0x48  scalarOutput         (uint64_t *)
    //   +0x50  scalarOutputCount    (uint32_t)
    //   +0x58  structureOutput      (void *)
    //   +0x60  structureOutputSize  (uint64_t)
    //
    // DER sel 17 (21 bytes): SET { SEQUENCE { "ss", INTEGER 4 },
    //                               SEQUENCE { "sls", INTEGER 3 } }
    //
    // DER sel 35 (157 bytes): SET of 14 members:
    //   bh=-6, cxw=0, lt=0, mua=0, sas=0, sb=0, sfa=0, sgpe=0,
    //   sgs=0, sls=3, sms=0, srcd=0, ss=6, uuid=0(16 bytes)
    //
    // On entry to externalMethod (ARM64e):
    //   x0 = self, x1 = selector (w1), x2 = args
    //
    // bof64() returns the `sub sp` after pacibsp.
    // ================================================================

    printf("%s: Patching AppleKeyStoreUserClient externalMethod (selector gate)...\n", __FUNCTION__);

    // --- Step 1: Find externalMethod via AKS operation string xref ---

    char applekeystore_string[sizeof("%s%s:%s%s%s%s%u:%s%u:%s operation %s(sel: %d ret: %x%s)%s")] =
        "%s%s:%s%s%s%s%u:%s%u:%s operation %s(sel: %d ret: %x%s)%s";
    unsigned char *applekeystore_loc = memmem(kernel_buf, kernel_len,
        applekeystore_string,
        sizeof("%s%s:%s%s%s%s%u:%s%u:%s operation %s(sel: %d ret: %x%s)%s") - 1);

    if (!applekeystore_loc) {
        printf("%s: Could not find AppleKeyStore operation string, trying alternate...\n", __FUNCTION__);
        char applekeystore_string2[sizeof("%s:%spid:%d,%s:%s%s%s%s%s%u:%s operation %s(sel: %d ret: %x%s)%s\n")] =
            "%s:%spid:%d,%s:%s%s%s%s%s%u:%s operation %s(sel: %d ret: %x%s)%s\n";
        applekeystore_loc = memmem(kernel_buf, kernel_len,
            applekeystore_string2,
            sizeof("%s:%spid:%d,%s:%s%s%s%s%s%u:%s operation %s(sel: %d ret: %x%s)%s\n") - 1);
    }

    if (!applekeystore_loc) {
        printf("%s: Could not find AppleKeyStore operation string\n", __FUNCTION__);
        return -1;
    }

    printf("%s: Found AppleKeyStore operation string at %p\n",
        __FUNCTION__, GET_OFFSET(kernel_len, applekeystore_loc));

    addr_t applekeystore_ref = xref64(kernel_buf, 0, kernel_len,
        (addr_t)GET_OFFSET(kernel_len, applekeystore_loc));
    if (!applekeystore_ref) {
        printf("%s: Could not find AppleKeyStore operation xref, continuing...\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found AppleKeyStore operation xref at %p\n",
        __FUNCTION__, (void*)applekeystore_ref);

    addr_t func_start = bof64(kernel_buf, 0, applekeystore_ref);
    if (!func_start) {
        printf("%s: Could not find externalMethod function start, continuing...\n", __FUNCTION__);
        return 0;
    }
    printf("%s: Found externalMethod sub sp at %p\n",
        __FUNCTION__, (void*)func_start);

    addr_t pacibsp_addr = func_start - 0x4;
    uint32_t maybe_pacibsp = *(uint32_t*)((uint8_t*)kernel_buf + pacibsp_addr);
    if (maybe_pacibsp != 0xD503237F) {
        printf("%s: WARNING: expected pacibsp (0xD503237F) at %p, got 0x%08x\n",
            __FUNCTION__, (void*)pacibsp_addr, maybe_pacibsp);
        return -1;
    }
    printf("%s: Confirmed pacibsp at %p\n", __FUNCTION__, (void*)pacibsp_addr);

    // --- Step 2: Find code cave at end of __TEXT_EXEC ---
    //
    // Walk Mach-O load commands manually (no mach-o/loader.h dependency).
    // Mach-O 64 header: 32 bytes. Load command: cmd(4) cmdsize(4).
    // LC_SEGMENT_64 = 0x19: segname(+8,16) fileoff(+40,8) filesize(+48,8)

    printf("%s: Searching for code cave in __TEXT_EXEC padding...\n", __FUNCTION__);

    uint8_t *buf = (uint8_t*)kernel_buf;
    uint32_t ncmds  = *(uint32_t*)(buf + 16);
    uint32_t lc_off = 32;

    uint64_t text_exec_fileoff  = 0;
    uint64_t text_exec_filesize = 0;
    int found_text_exec = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd     = *(uint32_t*)(buf + lc_off);
        uint32_t cmdsize = *(uint32_t*)(buf + lc_off + 4);

        if (cmd == 0x19) {  // LC_SEGMENT_64
            char *segname = (char*)(buf + lc_off + 8);
            if (strncmp(segname, "__TEXT_EXEC", 10) == 0) {
                text_exec_fileoff  = *(uint64_t*)(buf + lc_off + 40);
                text_exec_filesize = *(uint64_t*)(buf + lc_off + 48);
                found_text_exec = 1;
                printf("%s: __TEXT_EXEC: fileoff=0x%llx, filesize=0x%llx\n",
                    __FUNCTION__,
                    (unsigned long long)text_exec_fileoff,
                    (unsigned long long)text_exec_filesize);
                break;
            }
        }

        if (cmdsize == 0) break;
        lc_off += cmdsize;
    }

    if (!found_text_exec) {
        printf("%s: Could not find __TEXT_EXEC segment\n", __FUNCTION__);
        return -1;
    }

    // Scan backwards from end of __TEXT_EXEC to find last non-zero word
    uint64_t text_exec_end = text_exec_fileoff + text_exec_filesize;
    addr_t cave_addr = 0;

    for (uint64_t off = text_exec_end - 4; off >= text_exec_fileoff; off -= 4) {
        uint32_t w = *(uint32_t*)(buf + off);
        if (w != 0) {
            cave_addr = (addr_t)(off + 4);
            break;
        }
    }

    if (!cave_addr) {
        printf("%s: Could not find code cave\n", __FUNCTION__);
        return -1;
    }

    uint64_t cave_size = text_exec_end - cave_addr;
    printf("%s: Code cave at file offset 0x%llx (%llu bytes available)\n",
        __FUNCTION__, (unsigned long long)cave_addr, (unsigned long long)cave_size);

    // Total cave usage: 46 instructions (184 bytes) + 21 bytes DER17 + 157 bytes DER35 = 362 bytes
    if (cave_size < 362) {
        printf("%s: Code cave too small (%llu bytes, need 362)\n",
            __FUNCTION__, (unsigned long long)cave_size);
        return -1;
    }

    // Verify branch distances within +/-128MB
    int64_t fwd_distance  = (int64_t)cave_addr - (int64_t)pacibsp_addr;
    int64_t back_distance = (int64_t)func_start - (int64_t)(cave_addr + 0xB4);

    if (fwd_distance < -(1 << 27) || fwd_distance >= (1 << 27) ||
        back_distance < -(1 << 27) || back_distance >= (1 << 27)) {
        printf("%s: Code cave too far for B instruction\n", __FUNCTION__);
        return -1;
    }

    // --- Step 3: Write gate code + DER data into code cave ---
    //
    // Gate layout (46 instructions = 184 bytes code + 178 bytes DER data):
    //
    //   +0x000  pacibsp                        ; restore PAC we overwrote
    //   +0x004  cbz w1, native (+0x0B4)       ; sel 0 → native dispatch
    //   +0x008  cmp w1, #7                    ; sel == 7?
    //   +0x00C  b.eq sel7 (+0x028)            ; yes → scalar lock state shim
    //   +0x010  cmp w1, #17                   ; sel == 17?
    //   +0x014  b.eq sel17 (+0x048)           ; yes → DER state shim
    //   +0x018  cmp w1, #35                   ; sel == 35?
    //   +0x01C  b.eq sel35 (+0x070)           ; yes → DER full state shim
    //   +0x020  mov x0, #0                    ; all other sel: fake success
    //   +0x024  retab                         ;
    //
    //   sel7: (+0x028)
    //   +0x028  cbz x2, ret0                  ; args NULL → succeed
    //   +0x02C  ldr x8, [x2, #0x48]           ; scalarOutput ptr
    //   +0x030  cbz x8, ret0                  ; NULL → skip
    //   +0x034  ldr w9, [x2, #0x50]           ; scalarOutputCount
    //   +0x038  cbz w9, ret0                  ; 0 → skip
    //   +0x03C  mov x10, #6                   ; noPin | beenUnlocked
    //   +0x040  str x10, [x8]                 ; scalarOutput[0] = 0x6
    //   +0x044  b ret0                        ;
    //
    //   sel17: (+0x048)
    //   +0x048  cbz x2, ret0                  ; args NULL → succeed
    //   +0x04C  ldr x8, [x2, #0x58]           ; structureOutput ptr
    //   +0x050  cbz x8, ret0                  ; NULL → skip
    //   +0x054  ldr x9, [x2, #0x60]           ; structureOutputSize (64-bit)
    //   +0x058  cmp x9, #21                   ; need 21 bytes
    //   +0x05C  b.lo ret0                     ; too small → skip
    //   +0x060  adr x10, der17_data (+0x0B8)  ; PC-relative addr of DER blob
    //   +0x064  mov x11, #21                  ; byte count
    //   +0x068  mov x13, x11                  ; save size for store
    //   +0x06C  b copy_loop (+0x098)          ; shared copy routine
    //
    //   sel35: (+0x070)
    //   +0x070  cbz x2, ret0                  ; args NULL → succeed
    //   +0x074  ldr x8, [x2, #0x58]           ; structureOutput ptr
    //   +0x078  cbz x8, ret0                  ; NULL → skip
    //   +0x07C  ldr x9, [x2, #0x60]           ; structureOutputSize (64-bit)
    //   +0x080  cmp x9, #157                  ; need 157 bytes (0x9D)
    //   +0x084  b.lo ret0                     ; too small → skip
    //   +0x088  adr x10, der35_data (+0x0CD)  ; PC-relative addr of DER blob
    //   +0x08C  mov x11, #157                 ; byte count
    //   +0x090  mov x13, x11                  ; save size for store
    //   +0x094  b copy_loop (+0x098)          ;
    //
    //   copy_loop: (+0x098)
    //   +0x098  ldrb w12, [x10], #1           ; load DER byte, post-increment
    //   +0x09C  strb w12, [x8], #1            ; store to structureOutput
    //   +0x0A0  subs x11, x11, #1             ; decrement counter
    //   +0x0A4  b.ne copy_loop               ; loop until done
    //   +0x0A8  str x13, [x2, #0x60]          ; update structureOutputSize
    //
    //   ret0: (+0x0AC)
    //   +0x0AC  mov x0, #0                    ; kIOReturnSuccess
    //   +0x0B0  retab                         ;
    //
    //   native: (+0x0B4)
    //   +0x0B4  B sub_sp                      ; → externalMethod prologue
    //
    //   der17_data: (+0x0B8)  21 bytes of DER for sel 17
    //   der35_data: (+0x0CD)  157 bytes of DER for sel 35
    //

    printf("%s: Writing gate code at 0x%llx...\n",
        __FUNCTION__, (unsigned long long)cave_addr);

    uint32_t *cave = (uint32_t*)(buf + cave_addr);

    // +0x000: pacibsp
    cave[0]  = 0xD503237F;

    // +0x004: cbz w1, native (+0x0B4); offset=0xB0; imm19=0xB0/4=44
    cave[1]  = 0x34000581;

    // +0x008: cmp w1, #7
    cave[2]  = 0x71001C3F;

    // +0x00C: b.eq sel7 (+0x028); offset=0x1C; imm19=7
    cave[3]  = 0x540000E0;

    // +0x010: cmp w1, #17
    cave[4]  = 0x7100443F;

    // +0x014: b.eq sel17 (+0x048); offset=0x34; imm19=13
    cave[5]  = 0x540001A0;

    // +0x018: cmp w1, #35
    cave[6]  = 0x71008C3F;

    // +0x01C: b.eq sel35 (+0x070); offset=0x54; imm19=21
    cave[7]  = 0x540002A0;

    // +0x020: mov x0, #0 — all other selectors: fake success
    cave[8]  = 0xD2800000;

    // +0x024: retab
    cave[9]  = 0xD65F0FFF;

    // --- sel7: scalar lock state shim ---

    // +0x028: cbz x2, ret0 (+0x0AC); offset=0x84; imm19=33
    cave[10] = 0xB4000422;

    // +0x02C: ldr x8, [x2, #0x48] — scalarOutput
    cave[11] = 0xF9402448;

    // +0x030: cbz x8, ret0 (+0x0AC); offset=0x7C; imm19=31
    cave[12] = 0xB40003E8;

    // +0x034: ldr w9, [x2, #0x50] — scalarOutputCount
    cave[13] = 0xB9405049;

    // +0x038: cbz w9, ret0 (+0x0AC); offset=0x74; imm19=29
    cave[14] = 0x340003A9;

    // +0x03C: mov x10, #6 — noPin | beenUnlocked
    cave[15] = 0xD28000CA;

    // +0x040: str x10, [x8] — scalarOutput[0] = 0x6
    cave[16] = 0xF900010A;

    // +0x044: b ret0 (+0x0AC); offset=0x68; imm26=26
    cave[17] = 0x1400001A;

    // --- sel17: DER state shim (ss=4, sls=3) ---

    // +0x048: cbz x2, ret0 (+0x0AC); offset=0x64; imm19=25
    cave[18] = 0xB4000322;

    // +0x04C: ldr x8, [x2, #0x58] — structureOutput ptr
    cave[19] = 0xF9402C48;

    // +0x050: cbz x8, ret0 (+0x0AC); offset=0x5C; imm19=23
    cave[20] = 0xB40002E8;

    // +0x054: ldr x9, [x2, #0x60] — structureOutputSize (64-bit)
    cave[21] = 0xF9403049;

    // +0x058: cmp x9, #21 — need 21 bytes for sel 17 DER
    cave[22] = 0xF100553F;

    // +0x05C: b.lo ret0 (+0x0AC); offset=0x50; imm19=20; cond=3(LO)
    cave[23] = 0x54000283;

    // +0x060: adr x10, der17_data (+0x0B8); delta=0x58=88
    cave[24] = 0x100002CA;

    // +0x064: mov x11, #21
    cave[25] = 0xD28002AB;

    // +0x068: mov x13, x11
    cave[26] = 0xAA0B03ED;

    // +0x06C: b copy_loop (+0x098); offset=0x2C; imm26=11
    cave[27] = 0x1400000B;

    // --- sel35: DER full state shim ---

    // +0x070: cbz x2, ret0 (+0x0AC); offset=0x3C; imm19=15
    cave[28] = 0xB40001E2;

    // +0x074: ldr x8, [x2, #0x58] — structureOutput ptr
    cave[29] = 0xF9402C48;

    // +0x078: cbz x8, ret0 (+0x0AC); offset=0x34; imm19=13
    cave[30] = 0xB40001A8;

    // +0x07C: ldr x9, [x2, #0x60] — structureOutputSize (64-bit)
    cave[31] = 0xF9403049;

    // +0x080: cmp x9, #157 — need 157 bytes (0x9D) for sel 35 DER
    cave[32] = 0xF102753F;

    // +0x084: b.lo ret0 (+0x0AC); offset=0x28; imm19=10; cond=3(LO)
    cave[33] = 0x54000143;

    // +0x088: adr x10, der35_data (+0x0CD); delta=0x45=69
    cave[34] = 0x3000022A;

    // +0x08C: mov x11, #157
    cave[35] = 0xD28013AB;

    // +0x090: mov x13, x11
    cave[36] = 0xAA0B03ED;

    // +0x094: b copy_loop (+0x098); offset=0x04; imm26=1
    cave[37] = 0x14000001;

    // --- copy_loop: byte-copy DER into structureOutput ---

    // +0x098: ldrb w12, [x10], #1
    cave[38] = 0x3840154C;

    // +0x09C: strb w12, [x8], #1
    cave[39] = 0x3800150C;

    // +0x0A0: subs x11, x11, #1 (64-bit)
    cave[40] = 0xF100056B;

    // +0x0A4: b.ne copy_loop (+0x098); offset=-0x0C; cond=1(NE)
    cave[41] = 0x54FFFFA1;

    // +0x0A8: str x13, [x2, #0x60] — update structureOutputSize
    cave[42] = 0xF900304D;

    // --- ret0: return kIOReturnSuccess ---

    // +0x0AC: mov x0, #0
    cave[43] = 0xD2800000;

    // +0x0B0: retab
    cave[44] = 0xD65F0FFF;

    // --- native: branch to original externalMethod prologue ---

    // +0x0B4: B func_start (sub sp)
    {
        int64_t offset = (int64_t)func_start - (int64_t)(cave_addr + 0xB4);
        cave[45] = 0x14000000 | (((uint32_t)(offset >> 2)) & 0x3FFFFFF);
    }

    printf("%s: Gate code written (46 instructions, 184 bytes)\n", __FUNCTION__);

    // --- Step 3b: Write DER data blobs after the code ---
    //
    // der17_data at cave+0x0B8: 21 bytes — SET { SEQUENCE{"ss",4}, SEQUENCE{"sls",3} }
    // der35_data at cave+0x0CD: 157 bytes — SET of 14 members (full AKS state)

    uint8_t *cave_bytes = (uint8_t*)(buf + cave_addr);

    // Sel 17 DER: {ss=4, sls=3} — 21 bytes
    static const uint8_t der17[21] = {
        0x31, 0x13,                                     // SET, length 19
        0x30, 0x07, 0x0C, 0x02, 0x73, 0x73, 0x02, 0x01, 0x04,  // SEQUENCE{"ss", INTEGER 4}
        0x30, 0x08, 0x0C, 0x03, 0x73, 0x6C, 0x73, 0x02, 0x01, 0x03  // SEQUENCE{"sls", INTEGER 3}
    };
    memcpy(cave_bytes + 0xB8, der17, 21);

    printf("%s: Wrote sel 17 DER data at cave+0xB8 (21 bytes, ss=4 sls=3)\n", __FUNCTION__);

    // Sel 35 DER: full 14-member state — 157 bytes (DER SET, sorted by encoding)
    // Members (sorted): bh=-6, lt=0, sb=0, ss=6, cxw=0, mua=0, sas=0, sfa=0,
    //                    sgs=0, sls=3, sms=0, sgpe=0, srcd=0, uuid=zeros(16)
    static const uint8_t der35[157] = {
        0x31, 0x81, 0x9A,                               // SET, length 154 (long form)
        0x30, 0x07, 0x0C, 0x02, 0x62, 0x68, 0x02, 0x01, 0xFA,  // bh = -6
        0x30, 0x07, 0x0C, 0x02, 0x6C, 0x74, 0x02, 0x01, 0x00,  // lt = 0
        0x30, 0x07, 0x0C, 0x02, 0x73, 0x62, 0x02, 0x01, 0x00,  // sb = 0
        0x30, 0x07, 0x0C, 0x02, 0x73, 0x73, 0x02, 0x01, 0x06,  // ss = 6
        0x30, 0x08, 0x0C, 0x03, 0x63, 0x78, 0x77, 0x02, 0x01, 0x00,  // cxw = 0
        0x30, 0x08, 0x0C, 0x03, 0x6D, 0x75, 0x61, 0x02, 0x01, 0x00,  // mua = 0
        0x30, 0x08, 0x0C, 0x03, 0x73, 0x61, 0x73, 0x02, 0x01, 0x00,  // sas = 0
        0x30, 0x08, 0x0C, 0x03, 0x73, 0x66, 0x61, 0x02, 0x01, 0x00,  // sfa = 0
        0x30, 0x08, 0x0C, 0x03, 0x73, 0x67, 0x73, 0x02, 0x01, 0x00,  // sgs = 0
        0x30, 0x08, 0x0C, 0x03, 0x73, 0x6C, 0x73, 0x02, 0x01, 0x03,  // sls = 3
        0x30, 0x08, 0x0C, 0x03, 0x73, 0x6D, 0x73, 0x02, 0x01, 0x00,  // sms = 0
        0x30, 0x09, 0x0C, 0x04, 0x73, 0x67, 0x70, 0x65, 0x02, 0x01, 0x00,  // sgpe = 0
        0x30, 0x09, 0x0C, 0x04, 0x73, 0x72, 0x63, 0x64, 0x02, 0x01, 0x00,  // srcd = 0
        0x30, 0x18, 0x0C, 0x04, 0x75, 0x75, 0x69, 0x64, 0x04, 0x10,        // uuid = zeros
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(cave_bytes + 0xCD, der35, 157);

    printf("%s: Wrote sel 35 DER data at cave+0xCD (157 bytes, ss=6 sls=3 bh=-6)\n", __FUNCTION__);

    // --- Step 4: Replace pacibsp with B to gate ---

    {
        int64_t offset = (int64_t)cave_addr - (int64_t)pacibsp_addr;
        uint32_t b_to_cave = 0x14000000 | (((uint32_t)(offset >> 2)) & 0x3FFFFFF);

        *(uint32_t*)(buf + pacibsp_addr) = b_to_cave;

        printf("%s: Replaced pacibsp at 0x%llx with B 0x%llx (insn: 0x%08x)\n",
            __FUNCTION__,
            (unsigned long long)pacibsp_addr,
            (unsigned long long)cave_addr,
            b_to_cave);
    }

    printf("%s: === Selector gate patch applied ===\n", __FUNCTION__);
    printf("%s:   Sel 0       → native dispatch\n", __FUNCTION__);
    printf("%s:   Sel 7       → scalarOutput[0]=0x6, return 0\n", __FUNCTION__);
    printf("%s:   Sel 17      → DER {ss=4, sls=3} → structureOutput (21 bytes)\n", __FUNCTION__);
    printf("%s:   Sel 35      → DER full state → structureOutput (157 bytes)\n", __FUNCTION__);
    printf("%s:   All others  → return 0 (fake success)\n", __FUNCTION__);
    printf("%s:   Gate at     → 0x%llx (362 bytes: 184 code + 178 data)\n",
        __FUNCTION__, (unsigned long long)cave_addr);

    return 0;
}

int launchd_path_patch(void* kernel_buf,size_t kernel_len) {

    char launchd_path_string[sizeof("/sbin/launchd")] = "/sbin/launchd";

    unsigned char *launchd_path_loc = memmem(kernel_buf, kernel_len, launchd_path_string, sizeof("/sbin/launchd") - 1);

    if(!launchd_path_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, launchd_path_string);
        return -1;
    }

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, launchd_path_string, GET_OFFSET(kernel_len, launchd_path_loc));

    addr_t addr = (addr_t)GET_OFFSET(kernel_len, launchd_path_loc);

    printf("%s: Patching launchd at %p\n",__FUNCTION__,(void*)addr);

    *(uint32_t *)(launchd_path_loc) = 0x69626A2F;
    *(uint32_t *)(launchd_path_loc + 0x4) = 0x616C2F6E;
    *(uint32_t *)(launchd_path_loc + 0x8) = 0x68636E75;
    *(uint32_t *)(launchd_path_loc + 0x12) = 0x64;
    return 0;
}

int tfp0_patch(void* kernel_buf,size_t kernel_len) {

    char pineapple_pizza_string[sizeof("Just like pineapple on pizza, this task/thread port doesn't belong here.")] = "Just like pineapple on pizza, this task/thread port doesn't belong here.";

    unsigned char *pineapple_pizza_loc = memmem(kernel_buf, kernel_len, pineapple_pizza_string, sizeof("Just like pineapple on pizza, this task/thread port doesn't belong here.") - 1);

    if(!pineapple_pizza_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, pineapple_pizza_string);
        return -1;
    }

    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, pineapple_pizza_string, GET_OFFSET(kernel_len, pineapple_pizza_loc));

    addr_t pineapple_pizza_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, pineapple_pizza_loc));
    
    if(!pineapple_pizza_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, pineapple_pizza_string);
        return -1;
    }
    
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, pineapple_pizza_string, (void*) pineapple_pizza_ref);
    
    addr_t beq = step64(kernel_buf, pineapple_pizza_ref, 100, INSN_BEQ);
    
    if(!beq) {
        printf("%s: Could not find b.eq\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found b.eq at %p\n",__FUNCTION__, (void*) beq);
    
    addr_t caller_equals_victim = beq - 0x4;
    
    printf("%s: Patching tfp0 at %p\n",__FUNCTION__,(void*)caller_equals_victim);
    
    *(uint32_t *)(kernel_buf + caller_equals_victim) = 0xEB1F03FF;
    return 0;
};

int force_developer_mode(void* kernel_buf,size_t kernel_len) {
    char devmode_status_string[sizeof("AMFI: trying to get developer mode status from ACM\n")] = "AMFI: trying to get developer mode status from ACM\n";
    
    unsigned char *devmode_status_loc = memmem(kernel_buf, kernel_len, devmode_status_string, sizeof("AMFI: trying to get developer mode status from ACM\n") - 1);
    
    if(!devmode_status_loc) {
        printf("%s: Could not find \"AMFI: trying to get developer mode status from ACM\"\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"AMFI: trying to get developer mode status from ACM\" str loc at %p\n",__FUNCTION__, (void*) GET_OFFSET(kernel_len, devmode_status_loc));
    
    addr_t devmode_status_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, devmode_status_loc));
    
    if(!devmode_status_ref) {
        printf("%s: Could not find \"AMFI: trying to get developer mode status from ACM\" xref\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Found \"AMFI: trying to get developer mode status from ACM\" xref at %p\n",__FUNCTION__, (void*) devmode_status_ref);
    
    addr_t cbz = step64_back(kernel_buf, devmode_status_ref, 100, INSN_CBZ);
    
    if(!cbz) {
        printf("%s: Could not find cbz\n",__FUNCTION__);
        return -1;
    }
    
    printf("%s: Patching developer mode at %p\n",__FUNCTION__,(void*)cbz);
    
    *(uint32_t *)(kernel_buf + cbz) = 0x14000000 + ((*(uint32_t *)(kernel_buf + cbz) & 0x03ffffff) >> 5); // force branching
    
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Version: MOD edwin ;]" "\n");
        printf("Usage: %s <kernel_in> <kernel_out> <args>\n",argv[0]);
        printf("\t-a\t\tPatch AMFI\n");
        printf("\t-f\t\tPatch AppleFirmwareUpdate img4 signature check\n");
        printf("\t-s\t\tPatch SPUFirmwareValidation (iOS 15 Only)\n");
        printf("\t-b\t\tBypassFirmwareValidate (IOS14 TESTED), add -b13 -b15 if you want to path ios 13, 15\n");
        printf("\t-r\t\tPatch RootVPNotAuthenticatedAfterMounting (iOS 15 Only)\n");
        printf("\t-w\t\tPatch image4 validation callback (iOS 15+ Only)\n");
        printf("\t-we\t\tPatch image4 validation callback for arm64e (iOS 15+ Only)\n");
        printf("\t-o\t\tPatch could_not_authenticate_personalized_root_hash (iOS 15 Only)\n");
        printf("\t-e\t\tPatch root volume seal is broken (iOS 15 Only)\n");
        printf("\t-u\t\tPatch update_rootfs_rw (iOS 15 Only)\n");
        printf("\t-ue\t\tPatch unencrypted data volume is not allowed (iOS 15 Only)\n");
        printf("\t-p\t\tPatch AMFIInitializeLocalSigningPublicKey (iOS 15 Only)\n");
        printf("\t-h\t\tPatch is_root_hash_authentication_required_ios (iOS 16 only)\n");
        printf("\t-l\t\tPatch launchd path\n");
        //printf("\t-t\t\tPatch tfp0\n");
        printf("\t-d\t\tPatch developer mode\n"); 
        //printf("\t-k\t\tPatch fuckthesep, based on seprmvr\n");
        printf("\t-g\t\tPatch to Disable snapshots\n");
        printf("\t-n\t\tPatch to disable touchIdSensor\n");
        printf("\t-c\t\tPatch to Disable ASLR\n");
        printf("\t-t\t\tPatch to Disable Debugger Detection by patching Ptrace\n");

        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);

    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-a") == 0) {
            printf("Kernel: Adding AMFI_get_out_of_my_way patch...\n");
            get_amfi_out_of_my_way_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-f") == 0) {
            printf("Kernel: Adding AppleFirmwareUpdate img4 signature check patch...\n");
            get_AppleFirmwareUpdate_img4_signature_check(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-s") == 0) {
            printf("Kernel: Adding SPUFirmwareValidation patch...\n");
            get_SPUFirmwareValidation_patch(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-b") == 0) {
            printf("Kernel: Adding tbypassFirmwareValidate patch...\n");
            bypassFirmwareValidate(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-b13") == 0) {
            printf("Kernel: Adding tbypassFirmwareValidate patch...\n");
            bypassFirmwareValidate13(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-i") == 0) {
            printf("Kernel: Adding funny patches...\n");
            get_aks_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-kb") == 0) {
            printf("Kernel: Adding iOS 17 bag patches...\n");
            ios17_patch(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-b15") == 0) {
            printf("Kernel: Adding tbypassFirmwareValidate patch...\n");
            bypassFirmwareValidate15(kernel_buf,kernel_len);
        }

        if(strcmp(argv[i], "-p") == 0) {
            printf("Kernel: Adding AMFIInitializeLocalSigningPublicKey patch...\n");
            get_AMFIInitializeLocalSigningPublicKey_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-r") == 0) {
            printf("Kernel: Adding RootVPNotAuthenticatedAfterMounting patch...\n");
            get_RootVPNotAuthenticatedAfterMounting_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-w") == 0) {
            printf("Kernel: Adding image4 callback patch...\n");
            cryptex_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-we") == 0) {
            printf("Kernel: Adding image4 callback patch (arm64e)...\n");
            cryptex_patch_arm64e(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-li") == 0) {
            printf("libimg4: doing libimage4 validations patch...\n");
            libimg4_patch_174(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-o") == 0) {
            printf("Kernel: Adding could_not_authenticate_personalized_root_hash patch...\n");
            get_could_not_authenticate_personalized_root_hash_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-e") == 0) {
            printf("Kernel: Adding root volume seal is broken patch...\n");
            get_root_volume_seal_is_broken_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-u") == 0) {
            printf("Kernel: Adding update_rootfs_rw patch...\n");
            get_update_rootfs_rw_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-ue") == 0) {
            printf("Kernel: Adding unencrypted data volume patch...\n");
            get_unencrypted_data_volume_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-h") == 0) {
            printf("Kernel: Adding is_root_hash_authentication_required_ios patch...\n");
            is_root_hash_authentication_required_ios_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-l") == 0) {
            printf("Kernel: Adding launchd patch...\n");
            launchd_path_patch(kernel_buf,kernel_len);
        }/*
        if(strcmp(argv[i], "-t") == 0) {
            printf("Kernel: Adding tfp0 patch...\n");
            tfp0_patch(kernel_buf,kernel_len);
        }*/
         if(strcmp(argv[i], "-d") == 0) {
            printf("Kernel: Adding force developer mode patch...\n");
            force_developer_mode(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-k") == 0) {
            printf("Kernel: SEP patcher...\n");
            fuck_the_sep(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-n") == 0) {
            printf("Kernel: touch id patcher...\n");
            disableTouchidSensor(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-ct") == 0) {
            printf("containermanagerd: SEP patcher part 1...\n");
            containermanagerd_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-c") == 0) {
            printf("Kernel: Adding ASLR patch...\n");
            pathAslr(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-t") == 0) {
            printf("Kernel: Adding ptrace Debugger Detection patch...\n");
            pathPtrace(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-v") == 0) {
            printf("Kernel: Adding panic007 patch...\n");
            panic007Path(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-g") == 0) {
            printf("Kernel: Adding snapshot patch patch...\n");
            pathSnapshot(kernel_buf,kernel_len);
        }
    }
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}
