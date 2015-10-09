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

#endif
