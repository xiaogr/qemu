/*
 * NVDIMM ACPI Implementation
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *  Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *
 * NFIT is defined in ACPI 6.0: 5.2.25 NVDIMM Firmware Interface Table (NFIT)
 * and the DSM specification can be found at:
 *       http://pmem.io/documents/NVDIMM_DSM_Interface_Example.pdf
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

#include "qemu-common.h"
#include "hw/acpi/acpi.h"
#include "hw/acpi/aml-build.h"
#include "hw/mem/nvdimm.h"

/*
 * System Physical Address Range Structure
 *
 * It describes the system physical address ranges occupied by NVDIMMs and
 * the types of the regions.
 */
struct nfit_spa {
    uint16_t type;
    uint16_t length;
    uint16_t spa_index;
    uint16_t flags;
    uint32_t reserved;
    uint32_t proximity_domain;
    uint8_t type_guid[16];
    uint64_t spa_base;
    uint64_t spa_length;
    uint64_t mem_attr;
} QEMU_PACKED;
typedef struct nfit_spa nfit_spa;

/*
 * Memory Device to System Physical Address Range Mapping Structure
 *
 * It enables identifying each NVDIMM region and the corresponding SPA
 * describing the memory interleave
 */
struct nfit_memdev {
    uint16_t type;
    uint16_t length;
    uint32_t nfit_handle;
    uint16_t phys_id;
    uint16_t region_id;
    uint16_t spa_index;
    uint16_t dcr_index;
    uint64_t region_len;
    uint64_t region_offset;
    uint64_t region_dpa;
    uint16_t interleave_index;
    uint16_t interleave_ways;
    uint16_t flags;
    uint16_t reserved;
} QEMU_PACKED;
typedef struct nfit_memdev nfit_memdev;

/*
 * NVDIMM Control Region Structure
 *
 * It describes the NVDIMM and if applicable, Block Control Window.
 */
struct nfit_dcr {
    uint16_t type;
    uint16_t length;
    uint16_t dcr_index;
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t revision_id;
    uint16_t sub_vendor_id;
    uint16_t sub_device_id;
    uint16_t sub_revision_id;
    uint8_t reserved[6];
    uint32_t serial_number;
    uint16_t fic;
    uint16_t num_bcw;
    uint64_t bcw_size;
    uint64_t cmd_offset;
    uint64_t cmd_size;
    uint64_t status_offset;
    uint64_t status_size;
    uint16_t flags;
    uint8_t reserved2[6];
} QEMU_PACKED;
typedef struct nfit_dcr nfit_dcr;

/*
 * calculate the size of structures which describe all NVDIMM devices.
 * Currently each device has three structures as only PMEM is supported
 * now.
 */
static uint64_t nvdimm_device_structure_size(uint64_t slots)
{
    return slots * (sizeof(nfit_spa) + sizeof(nfit_memdev) + sizeof(nfit_dcr));
}

/*
 * calculate the size of the memory used to implement NVDIMM ACPI operations
 * which include:
 * - __DSM method: it needs two pages to transfer control and data between
 *   Guest ACPI and QEMU.
 *
 * - _FIT method: it returns a buffer to Guest which contains the structures
 *   describing all the present NVDIMM devices in the system.
 */
static uint64_t nvdimm_acpi_memory_size(uint64_t slots)
{
    uint64_t size = nvdimm_device_structure_size(slots);

    return size + getpagesize() * 2;
}

void nvdimm_init_memory_state(NVDIMMState *state, MemoryRegion *system_memory,
                              MachineState *machine)
{
    QEMU_BUILD_BUG_ON(nvdimm_acpi_memory_size(ACPI_MAX_RAM_SLOTS)
                         >= NVDIMM_ACPI_MEM_SIZE);

    state->base = NVDIMM_ACPI_MEM_BASE;
    memory_region_init(&state->mr, OBJECT(machine), "nvdimm-acpi",
                       NVDIMM_ACPI_MEM_SIZE);
    memory_region_add_subregion(system_memory, state->base, &state->mr);
}
