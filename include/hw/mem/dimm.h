/*
 * Dimm device abstraction
 *
 * Copyright ProfitBricks GmbH 2012
 * Copyright (C) 2013-2014 Red Hat Inc
 *
 * Authors:
 *  Vasilis Liaskovitis <vasilis.liaskovitis@profitbricks.com>
 *  Igor Mammedov <imammedo@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_DIMM_H
#define QEMU_DIMM_H

#include "exec/memory.h"
#include "sysemu/hostmem.h"
#include "hw/qdev.h"

#define TYPE_DIMM "dimm"
#define DIMM(obj) \
    OBJECT_CHECK(DIMMDevice, (obj), TYPE_DIMM)
#define DIMM_CLASS(oc) \
    OBJECT_CLASS_CHECK(DIMMDeviceClass, (oc), TYPE_DIMM)
#define DIMM_GET_CLASS(obj) \
    OBJECT_GET_CLASS(DIMMDeviceClass, (obj), TYPE_DIMM)

#define DIMM_ADDR_PROP "addr"
#define DIMM_SLOT_PROP "slot"
#define DIMM_NODE_PROP "node"
#define DIMM_SIZE_PROP "size"
#define DIMM_MEMDEV_PROP "memdev"

#define DIMM_UNASSIGNED_SLOT -1

/**
 * DIMMDevice:
 * @addr: starting guest physical address, where @DIMMDevice is mapped.
 *         Default value: 0, means that address is auto-allocated.
 * @node: numa node to which @DIMMDevice is attached.
 * @slot: slot number into which @DIMMDevice is plugged in.
 *        Default value: -1, means that slot is auto-allocated.
 * @hostmem: host memory backend providing memory for @DIMMDevice
 */
typedef struct DIMMDevice {
    /* private */
    DeviceState parent_obj;

    /* public */
    uint64_t addr;
    uint32_t node;
    int32_t slot;
    HostMemoryBackend *hostmem;
} DIMMDevice;

/**
 * DIMMDeviceClass:
 * @get_memory_region: returns #MemoryRegion associated with @dimm
 */
typedef struct DIMMDeviceClass {
    /* private */
    DeviceClass parent_class;

    /* public */
    MemoryRegion *(*get_memory_region)(DIMMDevice *dimm);
} DIMMDeviceClass;

/**
 * MemoryHotplugState:
 * @base: address in guest RAM address space where hotplug memory
 * address space begins.
 * @mr: hotplug memory address space container
 */
typedef struct MemoryHotplugState {
    ram_addr_t base;
    MemoryRegion mr;
} MemoryHotplugState;

uint64_t dimm_get_free_addr(uint64_t address_space_start,
                               uint64_t address_space_size,
                               uint64_t *hint, uint64_t align, bool gap,
                               uint64_t size, Error **errp);

int dimm_get_free_slot(const int *hint, int max_slots, Error **errp);

int qmp_dimm_device_list(Object *obj, void *opaque);
void dimm_memory_plug(DeviceState *dev, MemoryHotplugState *hpms,
                         MemoryRegion *mr, uint64_t align, bool gap,
                         Error **errp);
void dimm_memory_unplug(DeviceState *dev, MemoryHotplugState *hpms,
                           MemoryRegion *mr);
#endif
