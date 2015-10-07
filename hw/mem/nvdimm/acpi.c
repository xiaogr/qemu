/*
 * NVDIMM ACPI Implementation
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *  Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *
 * NFIT is defined in ACPI 6.0: 5.2.25 NVDIMM Firmware Interface Table (NFIT)
 * and the DSM specfication can be found at:
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
#include "internal.h"

static void nfit_spa_uuid_pm(uuid_le *uuid)
{
    uuid_le uuid_pm = UUID_LE(0x66f0d379, 0xb4f3, 0x4074, 0xac, 0x43, 0x0d,
                              0x33, 0x18, 0xb7, 0x8c, 0xdb);
    memcpy(uuid, &uuid_pm, sizeof(uuid_pm));
}

enum {
    NFIT_STRUCTURE_SPA = 0,
    NFIT_STRUCTURE_MEMDEV = 1,
    NFIT_STRUCTURE_IDT = 2,
    NFIT_STRUCTURE_SMBIOS = 3,
    NFIT_STRUCTURE_DCR = 4,
    NFIT_STRUCTURE_BDW = 5,
    NFIT_STRUCTURE_FLUSH = 6,
};

enum {
    EFI_MEMORY_UC = 0x1ULL,
    EFI_MEMORY_WC = 0x2ULL,
    EFI_MEMORY_WT = 0x4ULL,
    EFI_MEMORY_WB = 0x8ULL,
    EFI_MEMORY_UCE = 0x10ULL,
    EFI_MEMORY_WP = 0x1000ULL,
    EFI_MEMORY_RP = 0x2000ULL,
    EFI_MEMORY_XP = 0x4000ULL,
    EFI_MEMORY_NV = 0x8000ULL,
    EFI_MEMORY_MORE_RELIABLE = 0x10000ULL,
};

/*
 * NVDIMM Firmware Interface Table
 * @signature: "NFIT"
 */
struct nfit {
    ACPI_TABLE_HEADER_DEF
    uint32_t reserved;
} QEMU_PACKED;
typedef struct nfit nfit;

/* System Physical Address Range Structure */
struct nfit_spa {
    uint16_t type;
    uint16_t length;
    uint16_t spa_index;
    uint16_t flags;
    uint32_t reserved;
    uint32_t proximity_domain;
    uuid_le type_guid;
    uint64_t spa_base;
    uint64_t spa_length;
    uint64_t mem_attr;
} QEMU_PACKED;
typedef struct nfit_spa nfit_spa;

/*
 * Control region is strictly for management during hot add/online
 * operation.
 */
#define SPA_FLAGS_ADD_ONLINE_ONLY     (1)
/* Data in Proximity Domain field is valid. */
#define SPA_FLAGS_PROXIMITY_VALID     (1 << 1)

/* Memory Device to System Physical Address Range Mapping Structure */
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

/* NVDIMM Control Region Structure */
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

#define REVSISON_ID    1
#define NFIT_FIC1      0x201

static uint64_t nvdimm_device_structure_size(uint64_t slots)
{
    /* each nvdimm has three structures. */
    return slots * (sizeof(nfit_spa) + sizeof(nfit_memdev) + sizeof(nfit_dcr));
}

static uint64_t get_nfit_total_size(uint64_t slots)
{
    return sizeof(struct nfit) + nvdimm_device_structure_size(slots);
}

static uint64_t nvdimm_acpi_memory_size(uint64_t slots, uint64_t page_size)
{
    uint64_t size = nvdimm_device_structure_size(slots);

    /* two pages for nvdimm _DSM method. */
    return size + page_size * 2;
}

void nvdimm_init_memory_state(NVDIMMState *state, MemoryRegion*system_memory,
                              MachineState *machine , uint64_t page_size)
{
    QEMU_BUILD_BUG_ON(nvdimm_acpi_memory_size(ACPI_MAX_RAM_SLOTS,
                                   page_size) >= NVDIMM_ACPI_MEM_SIZE);

    state->base = NVDIMM_ACPI_MEM_BASE;
    state->page_size = page_size;

    memory_region_init(&state->mr, OBJECT(machine), "nvdimm-acpi",
                       NVDIMM_ACPI_MEM_SIZE);
    memory_region_add_subregion(system_memory, state->base, &state->mr);
}

static uint32_t nvdimm_slot_to_sn(int slot)
{
    return 0x123456 + slot;
}

static uint32_t nvdimm_slot_to_handle(int slot)
{
    return slot + 1;
}

static uint16_t nvdimm_slot_to_spa_index(int slot)
{
    return (slot + 1) << 1;
}

static uint32_t nvdimm_slot_to_dcr_index(int slot)
{
    return nvdimm_slot_to_spa_index(slot) + 1;
}

static int build_structure_spa(void *buf, NVDIMMDevice *nvdimm)
{
    nfit_spa *nfit_spa;
    uint64_t addr = object_property_get_int(OBJECT(nvdimm), DIMM_ADDR_PROP,
                                            NULL);
    uint64_t size = object_property_get_int(OBJECT(nvdimm), DIMM_SIZE_PROP,
                                            NULL);
    uint32_t node = object_property_get_int(OBJECT(nvdimm), DIMM_NODE_PROP,
                                            NULL);
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                            NULL);

    nfit_spa = buf;

    nfit_spa->type = cpu_to_le16(NFIT_STRUCTURE_SPA);
    nfit_spa->length = cpu_to_le16(sizeof(*nfit_spa));
    nfit_spa->spa_index = cpu_to_le16(nvdimm_slot_to_spa_index(slot));
    nfit_spa->flags = cpu_to_le16(SPA_FLAGS_PROXIMITY_VALID);
    nfit_spa->proximity_domain = cpu_to_le32(node);
    nfit_spa_uuid_pm(&nfit_spa->type_guid);
    nfit_spa->spa_base = cpu_to_le64(addr);
    nfit_spa->spa_length = cpu_to_le64(size);
    nfit_spa->mem_attr = cpu_to_le64(EFI_MEMORY_WB | EFI_MEMORY_NV);

    return sizeof(*nfit_spa);
}

static int build_structure_memdev(void *buf, NVDIMMDevice *nvdimm)
{
    nfit_memdev *nfit_memdev;
    uint64_t addr = object_property_get_int(OBJECT(nvdimm), DIMM_ADDR_PROP,
                                            NULL);
    uint64_t size = object_property_get_int(OBJECT(nvdimm), DIMM_SIZE_PROP,
                                            NULL);
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                            NULL);
    uint32_t handle = nvdimm_slot_to_handle(slot);

    nfit_memdev = buf;
    nfit_memdev->type = cpu_to_le16(NFIT_STRUCTURE_MEMDEV);
    nfit_memdev->length = cpu_to_le16(sizeof(*nfit_memdev));
    nfit_memdev->nfit_handle = cpu_to_le32(handle);
    /* point to nfit_spa. */
    nfit_memdev->spa_index = cpu_to_le16(nvdimm_slot_to_spa_index(slot));
    /* point to nfit_dcr. */
    nfit_memdev->dcr_index = cpu_to_le16(nvdimm_slot_to_dcr_index(slot));
    nfit_memdev->region_len = cpu_to_le64(size);
    nfit_memdev->region_dpa = cpu_to_le64(addr);
    /* Only one interleave for pmem. */
    nfit_memdev->interleave_ways = cpu_to_le16(1);

    return sizeof(*nfit_memdev);
}

static int build_structure_dcr(void *buf, NVDIMMDevice *nvdimm)
{
    nfit_dcr *nfit_dcr;
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                       NULL);
    uint32_t sn = nvdimm_slot_to_sn(slot);

    nfit_dcr = buf;
    nfit_dcr->type = cpu_to_le16(NFIT_STRUCTURE_DCR);
    nfit_dcr->length = cpu_to_le16(sizeof(*nfit_dcr));
    nfit_dcr->dcr_index = cpu_to_le16(nvdimm_slot_to_dcr_index(slot));
    nfit_dcr->vendor_id = cpu_to_le16(0x8086);
    nfit_dcr->device_id = cpu_to_le16(1);
    nfit_dcr->revision_id = cpu_to_le16(REVSISON_ID);
    nfit_dcr->serial_number = cpu_to_le32(sn);
    nfit_dcr->fic = cpu_to_le16(NFIT_FIC1);

    return sizeof(*nfit_dcr);
}

static void build_device_structure(GSList *device_list, char *buf)
{
    for (; device_list; device_list = device_list->next) {
        NVDIMMDevice *nvdimm = device_list->data;

        /* build System Physical Address Range Description Table. */
        buf += build_structure_spa(buf, nvdimm);

        /*
         * build Memory Device to System Physical Address Range Mapping
         * Table.
         */
        buf += build_structure_memdev(buf, nvdimm);

        /* build Control Region Descriptor Table. */
        buf += build_structure_dcr(buf, nvdimm);
    }
}

static void build_nfit(void *fit, GSList *device_list, GArray *table_offsets,
                       GArray *table_data, GArray *linker)
{
    size_t total;
    char *buf;
    int nfit_start, nr;

    nr = g_slist_length(device_list);
    total = get_nfit_total_size(nr);

    nfit_start = table_data->len;
    acpi_add_table(table_offsets, table_data);

    buf = acpi_data_push(table_data, total);
    memcpy(buf + sizeof(nfit), fit, total - sizeof(nfit));

    build_header(linker, table_data, (void *)(table_data->data + nfit_start),
                 "NFIT", table_data->len - nfit_start, 1);
}

static uint64_t dsm_read(void *opaque, hwaddr addr,
                         unsigned size)
{
    return 0;
}

static void dsm_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
}

static const MemoryRegionOps dsm_ops = {
    .read = dsm_read,
    .write = dsm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static MemoryRegion *build_dsm_memory(NVDIMMState *state)
{
    MemoryRegion *dsm_ram_mr, *dsm_mmio_mr, *dsm_fit_mr;
    uint64_t fit_size = memory_region_size(&state->mr) - state->page_size * 2;

    /* DSM memory has already been built. */
    dsm_fit_mr = memory_region_find(&state->mr, state->page_size * 2,
                                    fit_size).mr;
    if (dsm_fit_mr) {
        nvdebug("DSM FIT has already been built by %s.\n", dsm_fit_mr->name);
        memory_region_unref(dsm_fit_mr);
        return dsm_fit_mr;
    }

    /*
     * the first page is MMIO-based used to transfer control from guest
     * ACPI to QEMU.
     */
    dsm_mmio_mr = g_new(MemoryRegion, 1);
    memory_region_init_io(dsm_mmio_mr, NULL, &dsm_ops, state,
                          "nvdimm.dsm_mmio", state->page_size);

    /*
     * the second page is RAM-based used to transfer data between guest
     * ACPI and QEMU.
     */
    dsm_ram_mr = g_new(MemoryRegion, 1);
    memory_region_init_ram(dsm_ram_mr, NULL, "nvdimm.dsm_ram",
                           state->page_size, &error_abort);
    vmstate_register_ram_global(dsm_ram_mr);

    /*
     * the left is RAM-based which is _FIT buffer returned by _FIT
     * method.
     */
    dsm_fit_mr = g_new(MemoryRegion, 1);
    memory_region_init_ram(dsm_fit_mr, NULL, "nvdimm.fit", fit_size,
                           &error_abort);
    vmstate_register_ram_global(dsm_fit_mr);

    memory_region_add_subregion(&state->mr, 0, dsm_mmio_mr);
    memory_region_add_subregion(&state->mr, state->page_size, dsm_ram_mr);
    memory_region_add_subregion(&state->mr, state->page_size * 2, dsm_fit_mr);

    return dsm_fit_mr;
}

void nvdimm_build_acpi_table(NVDIMMState *state, GArray *table_offsets,
                             GArray *table_data, GArray *linker)
{
    GSList *device_list = nvdimm_get_built_list();

    if (!memory_region_size(&state->mr)) {
        assert(!device_list);
        return;
    }

    if (device_list) {
        void *fit = memory_region_get_ram_ptr(build_dsm_memory(state));

        build_device_structure(device_list, fit);
        build_nfit(fit, device_list, table_offsets, table_data, linker);
        g_slist_free(device_list);
    }
}
