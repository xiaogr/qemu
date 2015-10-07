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

static MemoryRegion *pc_dimm_get_memory_region(DIMMDevice *dimm)
{
    return host_memory_backend_get_memory(dimm->hostmem, &error_abort);
}

static void pc_dimm_class_init(ObjectClass *oc, void *data)
{
    DIMMDeviceClass *ddc = DIMM_CLASS(oc);

    ddc->get_memory_region = pc_dimm_get_memory_region;
}

static TypeInfo pc_dimm_info = {
    .name          = TYPE_PC_DIMM,
    .parent        = TYPE_DIMM,
    .class_init    = pc_dimm_class_init,
};

static void pc_dimm_register_types(void)
{
    type_register_static(&pc_dimm_info);
}

type_init(pc_dimm_register_types)
