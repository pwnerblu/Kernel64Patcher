/*
 * MobileActivationPatcher.c
 *
 * Patches mobileactivationd for iOS 17.0 tether downgrade (A13 / iPhone SE 2)
 * when SEP is non-functional.
 *
 * Patch 1: collectSIK: — force the firmware data path instead of AKS/SEP SIK
 *   In -[MACollectionInterface collectSIK:], a MobileGestalt boolean determines
 *   whether to use _aks_sik_collection (SEP) or _copyPersonalizedFirmwareData (disk).
 *   We patch the TBZ (conditional branch on bit test) to an unconditional B so the
 *   firmware data path is always taken, bypassing the dead SEP.
 *
 * Patch 2: collectSigningAttestation: — skip SEP-based key attestation
 *   -[MACollectionInterface collectSigningAttestation:] calls signingKey (SEP)
 *   then _security_create_system_key_attestation. Without SEP, signingKey returns
 *   nil and the method errors. We patch it to return nil attestation + nil error
 *   (graceful skip), so the caller can proceed without attestation data.
 *
 * Uses patchfinder64.c from Kernel64Patcher for instruction scanning/xref finding.
 *
 * Build:
 *   gcc MobileActivationPatcher.c patchfinder64.c -o MobileActivationPatcher
 *
 * Usage:
 *   ./MobileActivationPatcher <mobileactivationd_in> <mobileactivationd_out>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

typedef unsigned long long addr_t;
#include "patchfinder64.c"

#define GET_OFFSET(base, loc) (((uintptr_t)(loc) - (uintptr_t)(base)))

static uint64_t g_vm_base = 0;

/* ------------------------------------------------------------------ */
/* Mach-O helpers                                                      */
/* ------------------------------------------------------------------ */

static uint64_t get_text_segment_base(const uint8_t *buf) {
    uint32_t ncmds = *(uint32_t *)(buf + 16);
    uint32_t off = 32; /* past mach_header_64 */
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd     = *(uint32_t *)(buf + off);
        uint32_t cmdsize = *(uint32_t *)(buf + off + 4);
        if (cmd == 0x19) { /* LC_SEGMENT_64 */
            char *segname = (char *)(buf + off + 8);
            if (strncmp(segname, "__TEXT", 6) == 0 && segname[6] == '\0') {
                return *(uint64_t *)(buf + off + 24); /* vmaddr */
            }
        }
        if (cmdsize == 0) break;
        off += cmdsize;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Custom xref finder for userland Mach-O                              */
/* ------------------------------------------------------------------ */
/*
 * patchfinder64's xref64 computes ADRP values using file offsets,
 * but ADRP immediates encode virtual address pages. For a binary with
 * __TEXT vmaddr != 0 (e.g. 0x100000000), we need to add the VM base
 * to the file offset when computing the ADRP page and target.
 */
static addr_t xref64_va(const uint8_t *buf, addr_t start, addr_t end,
                         addr_t what_fileoff, uint64_t vm_base) {
    uint64_t what_va = vm_base + what_fileoff;
    uint64_t value[32];
    memset(value, 0, sizeof(value));

    end &= ~3;
    for (addr_t i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;

        if ((op & 0x9F000000) == 0x90000000) {
            /* ADRP: page = sign_extend(immhi:immlo) << 12 + (PC & ~0xFFF) */
            int32_t adr = (int32_t)(((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8));
            uint64_t pc_va = vm_base + i;
            value[reg] = ((int64_t)adr << 1) + (pc_va & ~0xFFFULL);
            continue;
        } else if ((op & 0xFF000000) == 0x91000000) {
            /* ADD Xd, Xn, #imm{, shift} */
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) imm <<= 12;
            else if (shift > 1) continue;
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            /* LDR Xt, [Xn, #imm] */
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            if (!imm) continue;
            value[reg] = value[rn] + imm;
        } else {
            value[reg] = 0;
            continue;
        }

        if (value[reg] == what_va) {
            return i;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* ARM64 instruction helpers                                           */
/* ------------------------------------------------------------------ */

static inline int is_tbz(uint32_t insn) {
    return (insn & 0x7F000000) == 0x36000000;
}

static inline int is_cbz(uint32_t insn) {
    return (insn & 0xFF000000) == 0x34000000 || /* CBZ W */
           (insn & 0xFF000000) == 0xB4000000;   /* CBZ X */
}

static inline int is_bl(uint32_t insn) {
    return (insn & 0xFC000000) == 0x94000000;
}

static inline int is_b(uint32_t insn) {
    return (insn & 0xFC000000) == 0x14000000;
}

static inline int is_ret_or_retab(uint32_t insn) {
    return insn == 0xD65F03C0 || /* RET */
           insn == 0xD65F0FFF;   /* RETAB */
}

/* Encode B <offset> where offset is in bytes, signed */
static inline uint32_t encode_b(int64_t byte_offset) {
    uint32_t imm26 = (uint32_t)((byte_offset >> 2) & 0x3FFFFFF);
    return 0x14000000 | imm26;
}

/* Extract the branch target from a TBZ/TBNZ instruction */
static inline int64_t tbz_target_offset(uint32_t insn) {
    int32_t imm14 = (int32_t)((insn >> 5) & 0x3FFF);
    if (imm14 & 0x2000) imm14 |= (int32_t)0xFFFFC000; /* sign extend */
    return (int64_t)imm14 << 2;
}

/* ------------------------------------------------------------------ */
/* Patch 1: Force SIK firmware data path in collectSIK:               */
/* ------------------------------------------------------------------ */
/*
 * In -[MACollectionInterface collectSIK:]:
 *   ...
 *   bl   _objc_msgSend$boolValue
 *   tbz  w0, #0, <firmware_data_path>   ; <-- PATCH THIS to unconditional B
 *   mov  x1, #0
 *   mov  x0, #0
 *   ...
 *   bl   _aks_sik_collection            ; SEP call (will fail)
 *   cbz  w0, <success>
 *   adrp+add "Failed to perform SIK collection: 0x%08x"
 *
 * We find "Failed to perform SIK collection" string xref, walk backwards to
 * find the CBZ (success check), then the BL (_aks_sik_collection), then the
 * TBZ before it, and patch the TBZ to an unconditional B to its original target.
 */
static int patch_collectSIK(void *buf, size_t len) {
    printf("[*] Patch 1: Force SIK firmware data path in collectSIK:\n");

    /* Find "-[MACollectionInterface collectSIK:]" method name string */
    char method_str[] = "-[MACollectionInterface collectSIK:]";
    uint8_t *str_loc = memmem(buf, len, method_str, sizeof(method_str) - 1);
    if (!str_loc) {
        printf("[-] Could not find collectSIK: method string\n");
        return -1;
    }
    addr_t str_addr = GET_OFFSET(buf, str_loc);
    printf("[+] Found method string at 0x%llx\n", str_addr);

    /* Find xref to this string in code — it's referenced from within collectSIK: */
    addr_t xref = xref64_va(buf, 0, len, str_addr, g_vm_base);
    if (!xref) {
        printf("[-] Could not find xref to method string\n");
        return -1;
    }
    printf("[+] Found method string xref at 0x%llx\n", xref);

    /* Find function start (bof64 looks for ADD x29, SP pattern) */
    addr_t func_body = bof64(buf, 0, xref);
    if (!func_body) {
        printf("[-] Could not find collectSIK: function start\n");
        return -1;
    }
    printf("[+] Found function body at 0x%llx\n", func_body);

    uint32_t *code = (uint32_t *)buf;

    /*
     * Scan forward from function start to find the TBZ w0, #0, <target>
     * This is after: bl _objc_msgSend$boolValue; tbz w0, #0, <fw_path>
     * and before: bl _aks_sik_collection
     * It should be within ~40 instructions of function start.
     */
    addr_t tbz_addr = 0;
    for (int i = 0; i <= 50; i++) {
        addr_t check = func_body + (i * 4);
        if (check >= len) break;
        uint32_t insn = code[check / 4];
        if (is_tbz(insn) && (insn & 0x1F) == 0) { /* TBZ w0/x0 */
            uint32_t bit5 = (insn >> 19) & 0x1F;
            uint32_t b5   = (insn >> 31) & 1;
            if ((bit5 | (b5 << 5)) == 0) {
                tbz_addr = check;
                break;
            }
        }
    }
    if (!tbz_addr) {
        printf("[-] Could not find TBZ w0, #0 (firmware data branch)\n");
        return -1;
    }

    uint32_t tbz_insn = code[tbz_addr / 4];
    int64_t tbz_target = tbz_target_offset(tbz_insn);
    printf("[+] Found TBZ w0, #0 at 0x%llx (target offset: %+lld)\n",
           tbz_addr, tbz_target);

    /* Patch: replace TBZ with unconditional B to the same target */
    uint32_t b_insn = encode_b(tbz_target);
    code[tbz_addr / 4] = b_insn;

    printf("[+] Patched TBZ -> B at 0x%llx (0x%08x -> 0x%08x)\n",
           tbz_addr, tbz_insn, b_insn);
    printf("[+] collectSIK: will now always use firmware data path (no SEP)\n");

    return 0;
}

/* ------------------------------------------------------------------ */
/* Patch 2: Skip signing key attestation in collectSigningAttestation: */
/* ------------------------------------------------------------------ */
/*
 * -[MACollectionInterface collectSigningAttestation:]:
 *   pacibsp
 *   sub    sp, sp, #0x40
 *   ...
 *   bl     _objc_msgSend$signingKey
 *   cbz    x0, <error_no_key>          ; signingKey is nil (SEP dead)
 *   ...
 *   bl     _security_create_system_key_attestation
 *   ...
 *
 * Without SEP, signingKey returns nil → method errors → activation fails.
 *
 * Patch: Make the method return (nil_attestation, nil_error) immediately.
 * Replace the prologue with:
 *   mov x0, #0       ; return nil (no attestation data)
 *   retab             ; return (arm64e)
 *
 * The caller in the session/activation info builder checks if attestation
 * is nil and can proceed without it (the attestation field is omitted from
 * the activation request).
 */
static int patch_collectSigningAttestation(void *buf, size_t len) {
    printf("[*] Patch 2: Skip signing key attestation\n");

    /* Find "-[MACollectionInterface collectSigningAttestation:]" string */
    char method_str[] = "-[MACollectionInterface collectSigningAttestation:]";
    uint8_t *str_loc = memmem(buf, len, method_str, sizeof(method_str) - 1);
    if (!str_loc) {
        printf("[-] Could not find collectSigningAttestation: method string\n");
        return -1;
    }
    addr_t str_addr = GET_OFFSET(buf, str_loc);
    printf("[+] Found method string at 0x%llx\n", str_addr);

    /* Find xref to this string — it's referenced from within the method */
    addr_t xref = xref64_va(buf, 0, len, str_addr, g_vm_base);
    if (!xref) {
        printf("[-] Could not find xref to method string\n");
        return -1;
    }
    printf("[+] Found method string xref at 0x%llx\n", xref);

    /* Find function start (bof64 looks for ADD x29, SP pattern) */
    addr_t func_start = bof64(buf, 0, xref);
    if (!func_start) {
        printf("[-] Could not find function start\n");
        return -1;
    }
    printf("[+] Found function start (sub sp) at 0x%llx\n", func_start);

    /* pacibsp should be right before the sub sp */
    addr_t pacibsp_addr = func_start - 4;
    uint32_t *code = (uint32_t *)buf;
    uint32_t maybe_pac = code[pacibsp_addr / 4];
    if (maybe_pac != 0xD503237F) {
        printf("[-] Expected pacibsp at 0x%llx, got 0x%08x\n",
               pacibsp_addr, maybe_pac);
        return -1;
    }
    printf("[+] Confirmed pacibsp at 0x%llx\n", pacibsp_addr);

    /* Patch: replace pacibsp + sub sp with mov x0, #0 + retab */
    code[pacibsp_addr / 4] = 0xD2800000;  /* mov x0, #0 */
    code[func_start / 4]   = 0xD65F0FFF;  /* retab */

    printf("[+] Patched collectSigningAttestation: at 0x%llx to return nil\n",
           pacibsp_addr);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Patch 3: Skip PCRT collection SEP dependency                        */
/* ------------------------------------------------------------------ */
/*
 * -[MACollectionInterface collectPCRT:] may also call into SEP.
 * "Failed to collect PCRT" / "Failed to collect PCRT: %ld"
 * Find and patch similarly if needed.
 */
static int patch_collectPCRT(void *buf, size_t len) {
    printf("[*] Patch 3: Skip PCRT collection\n");

    char method_str[] = "-[MACollectionInterface collectPCRT:]";
    uint8_t *str_loc = memmem(buf, len, method_str, sizeof(method_str) - 1);
    if (!str_loc) {
        printf("[!] collectPCRT: method string not found (may not exist), skipping\n");
        return 0;
    }
    addr_t str_addr = GET_OFFSET(buf, str_loc);
    printf("[+] Found collectPCRT method string at 0x%llx\n", str_addr);

    addr_t xref = xref64_va(buf, 0, len, str_addr, g_vm_base);
    if (!xref) {
        printf("[!] No xref for collectPCRT method string, skipping\n");
        return 0;
    }

    addr_t func_start = bof64(buf, 0, xref);
    if (!func_start) {
        printf("[!] Could not find collectPCRT function start, skipping\n");
        return 0;
    }

    addr_t pacibsp_addr = func_start - 4;
    uint32_t *code = (uint32_t *)buf;
    if (code[pacibsp_addr / 4] != 0xD503237F) {
        printf("[!] No pacibsp before collectPCRT, skipping\n");
        return 0;
    }

    code[pacibsp_addr / 4] = 0xD2800000;  /* mov x0, #0 */
    code[func_start / 4]   = 0xD65F0FFF;  /* retab */

    printf("[+] Patched collectPCRT: at 0x%llx to return nil\n", pacibsp_addr);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) {
    printf("MobileActivationPatcher — iOS 17.0 tether downgrade activation fix\n");
    printf("Targets: mobileactivationd (arm64e)\n\n");

    if (argc < 3) {
        printf("Usage: %s <mobileactivationd_in> <mobileactivationd_out>\n", argv[0]);
        return 1;
    }

    /* Read input binary */
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen input");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t len = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    void *buf = malloc(len);
    if (!buf) {
        perror("malloc");
        fclose(fp);
        return 1;
    }
    fread(buf, 1, len, fp);
    fclose(fp);

    printf("Loaded %s (%zu bytes)\n", argv[1], len);

    /* Verify it's a Mach-O 64-bit */
    uint32_t magic = *(uint32_t *)buf;
    if (magic != 0xFEEDFACF) {
        printf("Error: not a 64-bit Mach-O (magic: 0x%08x)\n", magic);
        free(buf);
        return 1;
    }

    uint64_t text_base = get_text_segment_base(buf);
    g_vm_base = text_base;
    printf("__TEXT vmaddr: 0x%llx\n\n", (unsigned long long)text_base);

    /* Apply patches */
    int errors = 0;

    if (patch_collectSIK(buf, len) != 0) {
        printf("[-] FAILED: collectSIK patch\n\n");
        errors++;
    } else {
        printf("[+] OK: collectSIK patch\n\n");
    }

    if (patch_collectSigningAttestation(buf, len) != 0) {
        printf("[-] FAILED: collectSigningAttestation patch\n\n");
        errors++;
    } else {
        printf("[+] OK: collectSigningAttestation patch\n\n");
    }

    if (patch_collectPCRT(buf, len) != 0) {
        printf("[-] FAILED: collectPCRT patch\n\n");
        errors++;
    } else {
        printf("[+] OK: collectPCRT patch\n\n");
    }

    if (errors > 0) {
        printf("WARNING: %d patch(es) failed\n", errors);
    }

    /* Write output */
    printf("Writing patched binary to %s...\n", argv[2]);
    fp = fopen(argv[2], "wb");
    if (!fp) {
        perror("fopen output");
        free(buf);
        return 1;
    }
    fwrite(buf, 1, len, fp);
    fclose(fp);
    free(buf);

    /* Copy permissions */
    struct stat st;
    if (stat(argv[1], &st) == 0) {
        chmod(argv[2], st.st_mode);
    }

    printf("Done. %d/%d patches applied.\n", 3 - errors, 3);
    return errors > 0 ? 1 : 0;
}
