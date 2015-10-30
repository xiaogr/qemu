/*
 * Dimm device for Memory Hotplug
 *
 * Copyright ProfitBricks GmbH 2012
 * Copyright (C) 2014 Red Hat Inc
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

#include "hw/mem/pc-dimm.h"
#include "qemu/config-file.h"
#include "qapi/visitor.h"
#include "qemu/range.h"
#include "sysemu/numa.h"
#include "sysemu/kvm.h"
#include "trace.h"
#include "hw/virtio/vhost.h"

typedef struct dimms_capacity {
     uint64_t size;
     Error    **errp;
} dimms_capacity;

static int existing_dimms_capacity_internal(Object *obj, void *opaque)
{
    dimms_capacity *cap = opaque;
    uint64_t *size = &cap->size;

    if (object_dynamic_cast(obj, TYPE_DIMM)) {
        DeviceState *dev = DEVICE(obj);

        if (dev->realized) {
            (*size) += object_property_get_int(obj, DIMM_SIZE_PROP,
                cap->errp);
        }

        if (cap->errp && *cap->errp) {
            return 1;
        }
    }
    object_child_foreach(obj, existing_dimms_capacity_internal, opaque);
    return 0;
}

static uint64_t existing_dimms_capacity(Error **errp)
{
    dimms_capacity cap;

    cap.size = 0;
    cap.errp = errp;

    existing_dimms_capacity_internal(qdev_get_machine(), &cap);
    return cap.size;
}

void dimm_memory_plug(DeviceState *dev, MemoryHotplugState *hpms,
                         MemoryRegion *mr, uint64_t align, Error **errp)
{
    int slot;
    MachineState *machine = MACHINE(qdev_get_machine());
    DIMMDevice *dimm = DIMM(dev);
    Error *local_err = NULL;
    uint64_t dimms_capacity = 0;
    uint64_t addr;

    addr = object_property_get_int(OBJECT(dimm), DIMM_ADDR_PROP, &local_err);
    if (local_err) {
        goto out;
    }

    addr = dimm_get_free_addr(hpms->base,
                                 memory_region_size(&hpms->mr),
                                 !addr ? NULL : &addr, align,
                                 memory_region_size(mr), &local_err);
    if (local_err) {
        goto out;
    }

    dimms_capacity = existing_dimms_capacity(&local_err);
    if (local_err) {
        goto out;
    }

    if (dimms_capacity + memory_region_size(mr) >
        machine->maxram_size - machine->ram_size) {
        error_setg(&local_err, "not enough space, currently 0x%" PRIx64
                   " in use of total hot pluggable 0x" RAM_ADDR_FMT,
                   dimms_capacity, machine->maxram_size - machine->ram_size);
        goto out;
    }

    object_property_set_int(OBJECT(dev), addr, DIMM_ADDR_PROP, &local_err);
    if (local_err) {
        goto out;
    }
    trace_mhp_dimm_assigned_address(addr);

    slot = object_property_get_int(OBJECT(dev), DIMM_SLOT_PROP, &local_err);
    if (local_err) {
        goto out;
    }

    slot = dimm_get_free_slot(slot == DIMM_UNASSIGNED_SLOT ? NULL : &slot,
                                 machine->ram_slots, &local_err);
    if (local_err) {
        goto out;
    }
    object_property_set_int(OBJECT(dev), slot, DIMM_SLOT_PROP, &local_err);
    if (local_err) {
        goto out;
    }
    trace_mhp_dimm_assigned_slot(slot);

    if (kvm_enabled() && !kvm_has_free_slot(machine)) {
        error_setg(&local_err, "hypervisor has no free memory slots left");
        goto out;
    }

    if (!vhost_has_free_slot()) {
        error_setg(&local_err, "a used vhost backend has no free"
                               " memory slots left");
        goto out;
    }

    memory_region_add_subregion(&hpms->mr, addr - hpms->base, mr);
    vmstate_register_ram(mr, dev);
    numa_set_mem_node_id(addr, memory_region_size(mr), dimm->node);

out:
    error_propagate(errp, local_err);
}

void dimm_memory_unplug(DeviceState *dev, MemoryHotplugState *hpms,
                           MemoryRegion *mr)
{
    DIMMDevice *dimm = DIMM(dev);

    numa_unset_mem_node_id(dimm->addr, memory_region_size(mr), dimm->node);
    memory_region_del_subregion(&hpms->mr, mr);
    vmstate_unregister_ram(mr, dev);
}

int qmp_dimm_device_list(Object *obj, void *opaque)
{
    MemoryDeviceInfoList ***prev = opaque;

    if (object_dynamic_cast(obj, TYPE_DIMM)) {
        DeviceState *dev = DEVICE(obj);

        if (dev->realized) {
            MemoryDeviceInfoList *elem = g_new0(MemoryDeviceInfoList, 1);
            MemoryDeviceInfo *info = g_new0(MemoryDeviceInfo, 1);
            DIMMDeviceInfo *di = g_new0(DIMMDeviceInfo, 1);
            DeviceClass *dc = DEVICE_GET_CLASS(obj);
            DIMMDevice *dimm = DIMM(obj);

            if (dev->id) {
                di->has_id = true;
                di->id = g_strdup(dev->id);
            }
            di->hotplugged = dev->hotplugged;
            di->hotpluggable = dc->hotpluggable;
            di->addr = dimm->addr;
            di->slot = dimm->slot;
            di->node = dimm->node;
            di->size = object_property_get_int(OBJECT(dimm), DIMM_SIZE_PROP,
                                               NULL);
            di->memdev = object_get_canonical_path(OBJECT(dimm->hostmem));

            info->dimm = di;
            elem->value = info;
            elem->next = NULL;
            **prev = elem;
            *prev = &elem->next;
        }
    }

    object_child_foreach(obj, qmp_dimm_device_list, opaque);
    return 0;
}

ram_addr_t get_current_ram_size(void)
{
    MemoryDeviceInfoList *info_list = NULL;
    MemoryDeviceInfoList **prev = &info_list;
    MemoryDeviceInfoList *info;
    ram_addr_t size = ram_size;

    qmp_dimm_device_list(qdev_get_machine(), &prev);
    for (info = info_list; info; info = info->next) {
        MemoryDeviceInfo *value = info->value;

        if (value) {
            switch (value->kind) {
            case MEMORY_DEVICE_INFO_KIND_DIMM:
                size += value->dimm->size;
                break;
            default:
                break;
            }
        }
    }
    qapi_free_MemoryDeviceInfoList(info_list);

    return size;
}

static int dimm_slot2bitmap(Object *obj, void *opaque)
{
    unsigned long *bitmap = opaque;

    if (object_dynamic_cast(obj, TYPE_DIMM)) {
        DeviceState *dev = DEVICE(obj);
        if (dev->realized) { /* count only realized DIMMs */
            DIMMDevice *d = DIMM(obj);
            set_bit(d->slot, bitmap);
        }
    }

    object_child_foreach(obj, dimm_slot2bitmap, opaque);
    return 0;
}

int dimm_get_free_slot(const int *hint, int max_slots, Error **errp)
{
    unsigned long *bitmap = bitmap_new(max_slots);
    int slot = 0;

    object_child_foreach(qdev_get_machine(), dimm_slot2bitmap, bitmap);

    /* check if requested slot is not occupied */
    if (hint) {
        if (*hint >= max_slots) {
            error_setg(errp, "invalid slot# %d, should be less than %d",
                       *hint, max_slots);
        } else if (!test_bit(*hint, bitmap)) {
            slot = *hint;
        } else {
            error_setg(errp, "slot %d is busy", *hint);
        }
        goto out;
    }

    /* search for free slot */
    slot = find_first_zero_bit(bitmap, max_slots);
    if (slot == max_slots) {
        error_setg(errp, "no free slots available");
    }
out:
    g_free(bitmap);
    return slot;
}

static gint dimm_addr_sort(gconstpointer a, gconstpointer b)
{
    DIMMDevice *x = DIMM(a);
    DIMMDevice *y = DIMM(b);
    Int128 diff = int128_sub(int128_make64(x->addr), int128_make64(y->addr));

    if (int128_lt(diff, int128_zero())) {
        return -1;
    } else if (int128_gt(diff, int128_zero())) {
        return 1;
    }
    return 0;
}

static int dimm_built_list(Object *obj, void *opaque)
{
    GSList **list = opaque;

    if (object_dynamic_cast(obj, TYPE_DIMM)) {
        DeviceState *dev = DEVICE(obj);
        if (dev->realized) { /* only realized DIMMs matter */
            *list = g_slist_insert_sorted(*list, dev, dimm_addr_sort);
        }
    }

    object_child_foreach(obj, dimm_built_list, opaque);
    return 0;
}

uint64_t dimm_get_free_addr(uint64_t address_space_start,
                               uint64_t address_space_size,
                               uint64_t *hint, uint64_t align, uint64_t size,
                               Error **errp)
{
    GSList *list = NULL, *item;
    uint64_t new_addr, ret = 0;
    uint64_t address_space_end = address_space_start + address_space_size;

    g_assert(QEMU_ALIGN_UP(address_space_start, align) == address_space_start);

    if (!address_space_size) {
        error_setg(errp, "memory hotplug is not enabled, "
                         "please add maxmem option");
        goto out;
    }

    if (hint && QEMU_ALIGN_UP(*hint, align) != *hint) {
        error_setg(errp, "address must be aligned to 0x%" PRIx64 " bytes",
                   align);
        goto out;
    }

    if (QEMU_ALIGN_UP(size, align) != size) {
        error_setg(errp, "backend memory size must be multiple of 0x%"
                   PRIx64, align);
        goto out;
    }

    assert(address_space_end > address_space_start);
    object_child_foreach(qdev_get_machine(), dimm_built_list, &list);

    if (hint) {
        new_addr = *hint;
    } else {
        new_addr = address_space_start;
    }

    /* find address range that will fit new DIMM */
    for (item = list; item; item = g_slist_next(item)) {
        DIMMDevice *dimm = item->data;
        uint64_t dimm_size = object_property_get_int(OBJECT(dimm),
                                                     DIMM_SIZE_PROP,
                                                     errp);
        if (errp && *errp) {
            goto out;
        }

        if (ranges_overlap(dimm->addr, dimm_size, new_addr, size)) {
            if (hint) {
                DeviceState *d = DEVICE(dimm);
                error_setg(errp, "address range conflicts with '%s'", d->id);
                goto out;
            }
            new_addr = QEMU_ALIGN_UP(dimm->addr + dimm_size, align);
        }
    }
    ret = new_addr;

    if (new_addr < address_space_start) {
        error_setg(errp, "can't add memory [0x%" PRIx64 ":0x%" PRIx64
                   "] at 0x%" PRIx64, new_addr, size, address_space_start);
    } else if ((new_addr + size) > address_space_end) {
        error_setg(errp, "can't add memory [0x%" PRIx64 ":0x%" PRIx64
                   "] beyond 0x%" PRIx64, new_addr, size, address_space_end);
    }

out:
    g_slist_free(list);
    return ret;
}

static Property dimm_properties[] = {
    DEFINE_PROP_UINT64(DIMM_ADDR_PROP, DIMMDevice, addr, 0),
    DEFINE_PROP_UINT32(DIMM_NODE_PROP, DIMMDevice, node, 0),
    DEFINE_PROP_INT32(DIMM_SLOT_PROP, DIMMDevice, slot,
                      DIMM_UNASSIGNED_SLOT),
    DEFINE_PROP_END_OF_LIST(),
};

static void dimm_get_size(Object *obj, Visitor *v, void *opaque,
                          const char *name, Error **errp)
{
    int64_t value;
    MemoryRegion *mr;
    DIMMDevice *dimm = DIMM(obj);

    mr = host_memory_backend_get_memory(dimm->hostmem, errp);
    value = memory_region_size(mr);

    visit_type_int(v, &value, name, errp);
}

static void dimm_check_memdev_is_busy(Object *obj, const char *name,
                                      Object *val, Error **errp)
{
    MemoryRegion *mr;

    mr = host_memory_backend_get_memory(MEMORY_BACKEND(val), errp);
    if (memory_region_is_mapped(mr)) {
        char *path = object_get_canonical_path_component(val);
        error_setg(errp, "can't use already busy memdev: %s", path);
        g_free(path);
    } else {
        qdev_prop_allow_set_link_before_realize(obj, name, val, errp);
    }
}

static void dimm_init(Object *obj)
{
    DIMMDevice *dimm = DIMM(obj);

    object_property_add(obj, DIMM_SIZE_PROP, "int", dimm_get_size,
                        NULL, NULL, NULL, &error_abort);
    object_property_add_link(obj, DIMM_MEMDEV_PROP, TYPE_MEMORY_BACKEND,
                             (Object **)&dimm->hostmem,
                             dimm_check_memdev_is_busy,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE,
                             &error_abort);
}

static void dimm_realize(DeviceState *dev, Error **errp)
{
    DIMMDevice *dimm = DIMM(dev);

    if (!dimm->hostmem) {
        error_setg(errp, "'" DIMM_MEMDEV_PROP "' property is not set");
        return;
    }
    if (((nb_numa_nodes > 0) && (dimm->node >= nb_numa_nodes)) ||
        (!nb_numa_nodes && dimm->node)) {
        error_setg(errp, "'DIMM property " DIMM_NODE_PROP " has value %"
                   PRIu32 "' which exceeds the number of numa nodes: %d",
                   dimm->node, nb_numa_nodes ? nb_numa_nodes : 1);
        return;
    }
}

static MemoryRegion *dimm_get_memory_region(DIMMDevice *dimm)
{
    return host_memory_backend_get_memory(dimm->hostmem, &error_abort);
}

static void dimm_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    DIMMDeviceClass *ddc = DIMM_CLASS(oc);

    dc->realize = dimm_realize;
    dc->props = dimm_properties;
    dc->desc = "DIMM memory module";

    ddc->get_memory_region = dimm_get_memory_region;
}

static TypeInfo dimm_info = {
    .name          = TYPE_DIMM,
    .parent        = TYPE_DEVICE,
    .instance_size = sizeof(DIMMDevice),
    .instance_init = dimm_init,
    .class_init    = dimm_class_init,
    .class_size    = sizeof(DIMMDeviceClass),
};

static void dimm_register_types(void)
{
    type_register_static(&dimm_info);
}

type_init(dimm_register_types)
