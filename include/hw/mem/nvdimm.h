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

#include "hw/mem/dimm.h"

/*
 * The minimum label data size is required by NVDIMM Namespace
 * specification, please refer to chapter 2 Namespaces:
 *   "NVDIMMs following the NVDIMM Block Mode Specification use an area
 *    at least 128KB in size, which holds around 1000 labels."
 */
#define MIN_NAMESPACE_LABEL_SIZE      (128UL << 10)

#define TYPE_NVDIMM      "nvdimm"
#define NVDIMM(obj)      OBJECT_CHECK(NVDIMMDevice, (obj), TYPE_NVDIMM)
#define NVDIMM_CLASS(oc) OBJECT_CLASS_CHECK(NVDIMMClass, (oc), TYPE_NVDIMM)
#define NVDIMM_GET_CLASS(obj) OBJECT_GET_CLASS(NVDIMMClass, (obj), \
                                               TYPE_NVDIMM)

struct NVDIMMDevice {
    /* private */
    DIMMDevice parent_obj;

    /* public */

    /*
     * the size of label data in NVDIMM device which is presented to
     * guest via __DSM "Get Namespace Label Size" command.
     */
    uint64_t label_size;

    /*
     * the address of label data which is read by __DSM "Get Namespace
     * Label Data" command and written by __DSM "Set Namespace Label
     * Data" command.
     */
    void *label_data;

    /*
     * it's the PMEM region in NVDIMM device, which is presented to
     * guest via ACPI NFIT and _FIT method if NVDIMM hotplug is supported.
     */
    MemoryRegion nvdimm_mr;
};
typedef struct NVDIMMDevice NVDIMMDevice;

struct NVDIMMClass {
    /* private */
    DIMMDeviceClass parent_class;

    /* public */
    /* read @size bytes from NVDIMM label data at @offset into @buf. */
    void (*read_label_data)(NVDIMMDevice *nvdimm, void *buf,
                            uint64_t size, uint64_t offset);
    /* write @size bytes from @buf to NVDIMM label data at @offset. */
    void (*write_label_data)(NVDIMMDevice *nvdimm, const void *buf,
                             uint64_t size, uint64_t offset);
};
typedef struct NVDIMMClass NVDIMMClass;

#endif
