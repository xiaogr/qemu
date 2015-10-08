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
#include "internal.h"

static int nvdimm_built_list(Object *obj, void *opaque)
{
    GSList **list = opaque;

    if (object_dynamic_cast(obj, TYPE_NVDIMM)) {
        DeviceState *dev = DEVICE(obj);

        /* only realized NVDIMMs matter */
        if (dev->realized) {
            *list = g_slist_append(*list, dev);
        }
    }

    object_child_foreach(obj, nvdimm_built_list, opaque);
    return 0;
}

GSList *nvdimm_get_built_list(void)
{
    GSList *list = NULL;

    object_child_foreach(qdev_get_machine(), nvdimm_built_list, &list);
    return list;
}

static MemoryRegion *nvdimm_get_memory_region(DIMMDevice *dimm)
{
    NVDIMMDevice *nvdimm = NVDIMM(dimm);

    return memory_region_size(&nvdimm->nvdimm_mr) ? &nvdimm->nvdimm_mr : NULL;
}

static void nvdimm_realize(DIMMDevice *dimm, Error **errp)
{
    MemoryRegion *mr;
    NVDIMMDevice *nvdimm = NVDIMM(dimm);
    uint64_t reserved_label_size, size;

    nvdimm->label_size = MIN_NAMESPACE_LABEL_SIZE;
    reserved_label_size = nvdimm->reserve_label_data ? nvdimm->label_size : 0;

    mr = host_memory_backend_get_memory(dimm->hostmem, errp);
    size = memory_region_size(mr);

    if (size <= reserved_label_size) {
        char *path = object_get_canonical_path_component(OBJECT(dimm->hostmem));
        error_setg(errp, "the size of memdev %s (0x%" PRIx64 ") is too small"
                   " to contain nvdimm namespace label (0x%" PRIx64 ")", path,
                   memory_region_size(mr), nvdimm->label_size);
        return;
    }

    memory_region_init_alias(&nvdimm->nvdimm_mr, OBJECT(dimm), "nvdimm-memory",
                             mr, 0, size - reserved_label_size);

    if (reserved_label_size) {
        nvdimm->label_data = memory_region_get_ram_ptr(mr) +
                             memory_region_size(&nvdimm->nvdimm_mr);
    }
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

static bool nvdimm_get_reserve_label_data(Object *obj, Error **errp)
{
    NVDIMMDevice *nvdimm = NVDIMM(obj);

    return nvdimm->reserve_label_data;
}

static void nvdimm_set_reserve_label_data(Object *obj, bool value, Error **errp)
{
    NVDIMMDevice *nvdimm = NVDIMM(obj);

    nvdimm->reserve_label_data = value;
}

static void nvdimm_init(Object *obj)
{
    object_property_add_bool(obj, "reserve-label-data",
                             nvdimm_get_reserve_label_data,
                             nvdimm_set_reserve_label_data, NULL);
}

static TypeInfo nvdimm_info = {
    .name          = TYPE_NVDIMM,
    .parent        = TYPE_DIMM,
    .instance_size = sizeof(NVDIMMDevice),
    .instance_init = nvdimm_init,
    .class_init    = nvdimm_class_init,
};

static void nvdimm_register_types(void)
{
    type_register_static(&nvdimm_info);
}

type_init(nvdimm_register_types)
