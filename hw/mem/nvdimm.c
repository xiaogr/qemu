/*
 * Non-Volatile Dual In-line Memory Module Virtualization Implementation
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *  Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *
 * Currently, it only supports PMEM Virtualization.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include "qapi/visitor.h"
#include "hw/mem/nvdimm.h"

static MemoryRegion *nvdimm_get_memory_region(DIMMDevice *dimm)
{
    NVDIMMDevice *nvdimm = NVDIMM(dimm);

    return memory_region_size(&nvdimm->nvdimm_mr) ? &nvdimm->nvdimm_mr : NULL;
}

static void nvdimm_realize(DIMMDevice *dimm, Error **errp)
{
    MemoryRegion *mr;
    NVDIMMDevice *nvdimm = NVDIMM(dimm);
    uint64_t size;

    nvdimm->label_size = MIN_NAMESPACE_LABEL_SIZE;

    mr = host_memory_backend_get_memory(dimm->hostmem, errp);
    size = memory_region_size(mr);

    if (size <= nvdimm->label_size) {
        char *path = object_get_canonical_path_component(OBJECT(dimm->hostmem));
        error_setg(errp, "the size of memdev %s (0x%" PRIx64 ") is too small"
                   " to contain nvdimm namespace label (0x%" PRIx64 ")", path,
                   memory_region_size(mr), nvdimm->label_size);
        return;
    }

    memory_region_init_alias(&nvdimm->nvdimm_mr, OBJECT(dimm), "nvdimm-memory",
                             mr, 0, size - nvdimm->label_size);
    nvdimm->label_data = memory_region_get_ram_ptr(mr) +
                         memory_region_size(&nvdimm->nvdimm_mr);
}

static void nvdimm_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    DIMMDeviceClass *ddc = DIMM_CLASS(oc);

    /* nvdimm hotplug has not been supported yet. */
    dc->hotpluggable = false;

    ddc->realize = nvdimm_realize;
    ddc->get_memory_region = nvdimm_get_memory_region;
}

static TypeInfo nvdimm_info = {
    .name          = TYPE_NVDIMM,
    .parent        = TYPE_DIMM,
    .instance_size = sizeof(NVDIMMDevice),
    .class_init    = nvdimm_class_init,
};

static void nvdimm_register_types(void)
{
    type_register_static(&nvdimm_info);
}

type_init(nvdimm_register_types)
