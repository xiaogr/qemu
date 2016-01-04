/*
 * Non-Volatile Dual In-line Memory Module Virtualization Implementation
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *  Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *
 * NVDIMM specifications and some documents can be found at:
 * NVDIMM ACPI device and NFIT are introduced in ACPI 6:
 *      http://www.uefi.org/sites/default/files/resources/ACPI_6.0.pdf
 * NVDIMM Namespace specification:
 *      http://pmem.io/documents/NVDIMM_Namespace_Spec.pdf
 * DSM Interface Example:
 *      http://pmem.io/documents/NVDIMM_DSM_Interface_Example.pdf
 * Driver Writer's Guide:
 *      http://pmem.io/documents/NVDIMM_Driver_Writers_Guide.pdf
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_NVDIMM_H
#define QEMU_NVDIMM_H

#include "hw/mem/pc-dimm.h"

#define NVDIMM_DEBUG 0
#define nvdimm_debug(fmt, ...)                                \
    do {                                                      \
        if (NVDIMM_DEBUG) {                                   \
            fprintf(stderr, "nvdimm: " fmt, ## __VA_ARGS__);  \
        }                                                     \
    } while (0)

#define TYPE_NVDIMM             "nvdimm"

#define NVDIMM_DSM_MEM_FILE     "etc/acpi/nvdimm-mem"

/* IO port 0x0a18 - 0xa20 in guest are reserved for NVDIMM ACPI emulation. */
#define NVDIMM_ACPI_IO_BASE     0x0a18
#define NVDIMM_ACPI_IO_LEN      8

/*
 * AcpiNVDIMMState:
 * @is_enabled: detect if NVDIMM support is enabled.
 *
 * @dsm_mem: the data of the fw_cfg file NVDIMM_DSM_MEM_FILE.
 *
 * The dsm memory is allocated by BIOS and patched into ACPI binary code.
 * @low_dsm_mem_addr: the low 32 bits of DSM memory.
 * @high_dsm_mem_addr: the high 32 bits of DSM memory.
 *
 * @io_mr: the IO region used by OSPM to transfer control to QEMU.
 */
struct AcpiNVDIMMState {
    bool is_enabled;

    GArray *dsm_mem;

    uint32_t low_dsm_mem_addr;
    uint32_t high_dsm_mem_addr;

    MemoryRegion io_mr;
};
typedef struct AcpiNVDIMMState AcpiNVDIMMState;

void nvdimm_init_acpi_state(AcpiNVDIMMState *state, MemoryRegion *io,
                            FWCfgState *fw_cfg, Object *owner);
void nvdimm_build_acpi(GArray *table_offsets, GArray *table_data,
                       GArray *linker, uint8_t revision);
#endif
