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

#define NVDIMM_UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)             \
   { (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
     (b) & 0xff, ((b) >> 8) & 0xff, (c) & 0xff, ((c) >> 8) & 0xff,          \
     (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }

/*
 * This GUID defines a Byte Addressable Persistent Memory (PM) Region.
 * Please refer to ACPI 6.0: 5.2.25.1 System Physical Address Range
 * Structure.
 */
static const uint8_t nfit_spa_uuid_pm[] = NVDIMM_UUID_LE(0x66f0d379, 0xb4f3,
                0x4074, 0xac, 0x43, 0x0d, 0x33, 0x18, 0xb7, 0x8c, 0xdb);

/* NFIT Structure Types. */
enum {
    NFIT_STRUCTURE_SPA = 0,
    NFIT_STRUCTURE_MEMDEV = 1,
    NFIT_STRUCTURE_IDT = 2,
    NFIT_STRUCTURE_SMBIOS = 3,
    NFIT_STRUCTURE_DCR = 4,
    NFIT_STRUCTURE_BDW = 5,
    NFIT_STRUCTURE_FLUSH = 6,
};

/*
 * NVDIMM Firmware Interface Table
 * @signature: "NFIT"
 *
 * It provides information that allows OSPM to enumerate NVDIMM present in
 * the platform and associate system physical address ranges created by the
 * NVDIMMs.
 *
 * Detailed info please refer to ACPI 6.0: 5.2.25 NVDIMM Firmware Interface
 * Table (NFIT)
 */
struct nfit {
    ACPI_TABLE_HEADER_DEF
    uint32_t reserved;
} QEMU_PACKED;
typedef struct nfit nfit;

/*
 * Memory mapping attributes for the address range described in system
 * physical address range structure.
 */
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
 * Control region is strictly for management during hot add/online
 * operation.
 */
#define SPA_FLAGS_ADD_ONLINE_ONLY     (1)
/* Data in Proximity Domain field is valid. */
#define SPA_FLAGS_PROXIMITY_VALID     (1 << 1)

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
 * please refer to DSM specification, Chapter 2 NVDIMM Device Specific
 * Method (DSM).
 */
#define REVSISON_ID    1
/* the format interface code supported by DSM specification. */
#define NFIT_FIC1      0x201

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

/*
 * Module serial number is a unique number for each device. We use the
 * slot id of NVDIMM device to generate this number so that each device
 * associates with a different number.
 *
 * 0x123456 is a magic number we arbitrarily chose.
 */
static uint32_t nvdimm_slot_to_sn(int slot)
{
    return 0x123456 + slot;
}

/*
 * handle is used to uniquely associate nfit_memdev structure with NVDIMM
 * ACPI device - nfit_memdev.nfit_handle matches with the value returned
 * by ACPI device _ADR method.
 *
 * We generate the handle with the slot id of NVDIMM device and reserve
 * 0 for NVDIMM root device.
 */
static uint32_t nvdimm_slot_to_handle(int slot)
{
    return slot + 1;
}

/*
 * index uniquely identifies the structure, 0 is reserved which indicates
 * that the structure is not valid or the associated structure is not
 * present.
 *
 * Each NVDIMM device needs two indexes, one for nfit_spa and another for
 * nfit_dc which are generated by the slot id of NVDIMM device.
 */
static uint16_t nvdimm_slot_to_spa_index(int slot)
{
    return (slot + 1) << 1;
}

/* See the comment of nvdimm_slot_to_spa_index(). */
static uint32_t nvdimm_slot_to_dcr_index(int slot)
{
    return nvdimm_slot_to_spa_index(slot) + 1;
}

/*
 * Please refer to ACPI 6.0: 5.2.25.1 System Physical Address Range
 * Structure
 */
static void
nvdimm_build_structure_spa(GArray *structures, NVDIMMDevice *nvdimm)
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

    nfit_spa = acpi_data_push(structures, sizeof(*nfit_spa));

    /* System Physical Address Range Structure */
    nfit_spa->type = cpu_to_le16(NFIT_STRUCTURE_SPA);
    nfit_spa->length = cpu_to_le16(sizeof(*nfit_spa));
    nfit_spa->spa_index = cpu_to_le16(nvdimm_slot_to_spa_index(slot));

    /*
     * - Proximity Domain field is valid as NUMA node is valid.
     * - Control region is strictly during hot add as all the device
     *   info, such as SN, index, is associated with slot id.
     */
    nfit_spa->flags = cpu_to_le16(SPA_FLAGS_PROXIMITY_VALID |
                                  SPA_FLAGS_ADD_ONLINE_ONLY);

    /* NUMA node. */
    nfit_spa->proximity_domain = cpu_to_le32(node);
    /* the region reported as PMEM. */
    memcpy(nfit_spa->type_guid, nfit_spa_uuid_pm, sizeof(nfit_spa_uuid_pm));

    nfit_spa->spa_base = cpu_to_le64(addr);
    nfit_spa->spa_length = cpu_to_le64(size);

    /* It is the PMEM and can be cached as writeback. */
    nfit_spa->mem_attr = cpu_to_le64(EFI_MEMORY_WB | EFI_MEMORY_NV);
}

/*
 * Please refer to ACPI 6.0: 5.2.25.2 Memory Device to System Physical
 * Address Range Mapping Structure
 */
static void
nvdimm_build_structure_memdev(GArray *structures, NVDIMMDevice *nvdimm)
{
    nfit_memdev *nfit_memdev;
    uint64_t addr = object_property_get_int(OBJECT(nvdimm), DIMM_ADDR_PROP,
                                            NULL);
    uint64_t size = object_property_get_int(OBJECT(nvdimm), DIMM_SIZE_PROP,
                                            NULL);
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                            NULL);
    uint32_t handle = nvdimm_slot_to_handle(slot);

    nfit_memdev = acpi_data_push(structures, sizeof(*nfit_memdev));

    /* Memory Device to System Address Range Map Structure */
    nfit_memdev->type = cpu_to_le16(NFIT_STRUCTURE_MEMDEV);
    nfit_memdev->length = cpu_to_le16(sizeof(*nfit_memdev));
    nfit_memdev->nfit_handle = cpu_to_le32(handle);

    /*
     * associate memory device with System Physical Address Range
     * Structure.
     */
    nfit_memdev->spa_index = cpu_to_le16(nvdimm_slot_to_spa_index(slot));
    /* associate memory device with Control Region Structure. */
    nfit_memdev->dcr_index = cpu_to_le16(nvdimm_slot_to_dcr_index(slot));

    /* The memory region on the device. */
    nfit_memdev->region_len = cpu_to_le64(size);
    nfit_memdev->region_dpa = cpu_to_le64(addr);

    /* Only one interleave for PMEM. */
    nfit_memdev->interleave_ways = cpu_to_le16(1);
}

/* Please refer to ACPI 6.0: 5.2.25.5 NVDIMM Control Region Structure */
static void nvdimm_build_structure_dcr(GArray *structures, NVDIMMDevice *nvdimm)
{
    nfit_dcr *nfit_dcr;
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                       NULL);
    uint32_t sn = nvdimm_slot_to_sn(slot);

    nfit_dcr = acpi_data_push(structures, sizeof(*nfit_dcr));

    /* NVDIMM Control Region Structure */
    nfit_dcr->type = cpu_to_le16(NFIT_STRUCTURE_DCR);
    nfit_dcr->length = cpu_to_le16(sizeof(*nfit_dcr));
    nfit_dcr->dcr_index = cpu_to_le16(nvdimm_slot_to_dcr_index(slot));

    /* vendor: Intel. */
    nfit_dcr->vendor_id = cpu_to_le16(0x8086);
    nfit_dcr->device_id = cpu_to_le16(1);

    /* The _DSM method is following Intel's DSM specification. */
    nfit_dcr->revision_id = cpu_to_le16(REVSISON_ID);
    nfit_dcr->serial_number = cpu_to_le32(sn);
    nfit_dcr->fic = cpu_to_le16(NFIT_FIC1);
}

static GArray *nvdimm_build_device_structure(GSList *device_list)
{
    GArray *structures = g_array_new(false, true /* clear */, 1);

    for (; device_list; device_list = device_list->next) {
        NVDIMMDevice *nvdimm = device_list->data;

        /* build System Physical Address Range Structure. */
        nvdimm_build_structure_spa(structures, nvdimm);

        /*
         * build Memory Device to System Physical Address Range Mapping
         * Structure.
         */
        nvdimm_build_structure_memdev(structures, nvdimm);

        /* build NVDIMM Control Region Structure. */
        nvdimm_build_structure_dcr(structures, nvdimm);
    }

    return structures;
}

static void nvdimm_build_nfit(GArray *structures, GArray *table_offsets,
                              GArray *table_data, GArray *linker)
{
    void *header;

    acpi_add_table(table_offsets, table_data);

    /* NFIT header. */
    header = acpi_data_push(table_data, sizeof(nfit));

    /* NVDIMM device structures. */
    g_array_append_vals(table_data, structures->data, structures->len);

    build_header(linker, table_data, header, "NFIT",
                 sizeof(nfit) + structures->len, 1);
}

static uint64_t
nvdimm_dsm_read(void *opaque, hwaddr addr, unsigned size)
{
    return 0;
}

static void
nvdimm_dsm_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
}

static const MemoryRegionOps nvdimm_dsm_ops = {
    .read = nvdimm_dsm_read,
    .write = nvdimm_dsm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static MemoryRegion *nvdimm_build_dsm_memory(NVDIMMState *state)
{
    MemoryRegion *dsm_ram_mr, *dsm_mmio_mr, *dsm_fit_mr;
    uint64_t page_size = getpagesize();
    uint64_t fit_size = memory_region_size(&state->mr) - page_size * 2;

    /* DSM memory has already been built. */
    dsm_fit_mr = memory_region_find(&state->mr, page_size * 2,
                                    fit_size).mr;
    if (dsm_fit_mr) {
        nvdimm_debug("DSM FIT has already been built by %s.\n",
                     dsm_fit_mr->name);
        return dsm_fit_mr;
    }

    /*
     * the first page is MMIO-based used to transfer control from guest
     * ACPI to QEMU.
     */
    dsm_mmio_mr = g_new(MemoryRegion, 1);
    memory_region_init_io(dsm_mmio_mr, NULL, &nvdimm_dsm_ops, state,
                          "nvdimm.dsm_mmio", page_size);

    /*
     * the second page is RAM-based used to transfer data between guest
     * ACPI and QEMU.
     */
    dsm_ram_mr = g_new(MemoryRegion, 1);
    memory_region_init_ram(dsm_ram_mr, NULL, "nvdimm.dsm_ram",
                           page_size, &error_abort);
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
    memory_region_add_subregion(&state->mr, page_size, dsm_ram_mr);
    memory_region_add_subregion(&state->mr, page_size * 2, dsm_fit_mr);

    /* the caller will unref it. */
    memory_region_ref(dsm_fit_mr);
    return dsm_fit_mr;
}

void nvdimm_build_acpi(NVDIMMState *state, GArray *table_offsets,
                       GArray *table_data, GArray *linker)
{
    MemoryRegion *fit_mr;
    GArray *structures;
    GSList *device_list = nvdimm_get_plugged_device_list();

    if (!memory_region_size(&state->mr)) {
        assert(!device_list);
        return;
    }

    if (!device_list) {
        return;
    }

    fit_mr = nvdimm_build_dsm_memory(state);

    structures = nvdimm_build_device_structure(device_list);

    /* Build fit memory which is presented to guest via _FIT method. */
    assert(memory_region_size(fit_mr) >= structures->len);
    memcpy(memory_region_get_ram_ptr(fit_mr), structures->data,
           structures->len);

    nvdimm_build_nfit(structures, table_offsets, table_data, linker);

    memory_region_unref(fit_mr);
    g_slist_free(device_list);
    g_array_free(structures, true);
}
