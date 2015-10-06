/*
 * Non-Volatile Dual In-line Memory Module Virtualization Implementation
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *  Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_NVDIMM_H
#define QEMU_NVDIMM_H

#include "hw/mem/dimm.h"

/* Memory region 0xFF00000 ~ 0xFFF00000 is reserved for NVDIMM ACPI. */
#define NVDIMM_ACPI_MEM_BASE   0xFF000000ULL
#define NVDIMM_ACPI_MEM_SIZE   0xF00000ULL

#define TYPE_NVDIMM "nvdimm"
#define NVDIMM(obj) \
    OBJECT_CHECK(NVDIMMDevice, (obj), TYPE_NVDIMM)

struct NVDIMMDevice {
    /* private */
    DIMMDevice parent_obj;

    /* public */
    uint64_t label_size;
    void *label_data;
    MemoryRegion nvdimm_mr;
};
typedef struct NVDIMMDevice NVDIMMDevice;

/*
 * NVDIMMState:
 * @base: address in guest address space where NVDIMM ACPI memory begins.
 * @page_size: the page size of target platform.
 * @mr: NVDIMM ACPI memory address space container.
 */
struct NVDIMMState {
    ram_addr_t base;
    uint64_t page_size;
    MemoryRegion mr;
};
typedef struct NVDIMMState NVDIMMState;

void nvdimm_init_memory_state(NVDIMMState *state, MemoryRegion*system_memory,
                              MachineState *machine , uint64_t page_size);
void nvdimm_build_acpi_table(NVDIMMState *state, GArray *table_offsets,
                             GArray *table_data, GArray *linker);
#endif
