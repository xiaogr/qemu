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

#include "hw/acpi/acpi.h"
#include "hw/acpi/aml-build.h"
#include "hw/mem/nvdimm.h"

static int nvdimm_plugged_device_list(Object *obj, void *opaque)
{
    GSList **list = opaque;

    if (object_dynamic_cast(obj, TYPE_NVDIMM)) {
        NVDIMMDevice *nvdimm = NVDIMM(obj);

        if (memory_region_is_mapped(&nvdimm->nvdimm_mr)) {
            *list = g_slist_append(*list, DEVICE(obj));
        }
    }

    object_child_foreach(obj, nvdimm_plugged_device_list, opaque);
    return 0;
}

/*
 * inquire plugged NVDIMM devices and link them into the list which is
 * returned to the caller.
 *
 * Note: it is the caller's responsibility to free the list to avoid
 * memory leak.
 */
static GSList *nvdimm_get_plugged_device_list(void)
{
    GSList *list = NULL;

    object_child_foreach(qdev_get_machine(), nvdimm_plugged_device_list,
                         &list);
    return list;
}

#define NVDIMM_UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)             \
   { (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
     (b) & 0xff, ((b) >> 8) & 0xff, (c) & 0xff, ((c) >> 8) & 0xff,          \
     (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }
/*
 * define Byte Addressable Persistent Memory (PM) Region according to
 * ACPI 6.0: 5.2.25.1 System Physical Address Range Structure.
 */
static const uint8_t nvdimm_nfit_spa_uuid[] =
      NVDIMM_UUID_LE(0x66f0d379, 0xb4f3, 0x4074, 0xac, 0x43, 0x0d, 0x33,
                     0x18, 0xb7, 0x8c, 0xdb);

/*
 * NVDIMM Firmware Interface Table
 * @signature: "NFIT"
 *
 * It provides information that allows OSPM to enumerate NVDIMM present in
 * the platform and associate system physical address ranges created by the
 * NVDIMMs.
 *
 * It is defined in ACPI 6.0: 5.2.25 NVDIMM Firmware Interface Table (NFIT)
 */
struct NvdimmNfitHeader {
    ACPI_TABLE_HEADER_DEF
    uint32_t reserved;
} QEMU_PACKED;
typedef struct NvdimmNfitHeader NvdimmNfitHeader;

/*
 * define NFIT structures according to ACPI 6.0: 5.2.25 NVDIMM Firmware
 * Interface Table (NFIT).
 */

/*
 * System Physical Address Range Structure
 *
 * It describes the system physical address ranges occupied by NVDIMMs and
 * the types of the regions.
 */
struct NvdimmNfitSpa {
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
typedef struct NvdimmNfitSpa NvdimmNfitSpa;

/*
 * Memory Device to System Physical Address Range Mapping Structure
 *
 * It enables identifying each NVDIMM region and the corresponding SPA
 * describing the memory interleave
 */
struct NvdimmNfitMemDev {
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
typedef struct NvdimmNfitMemDev NvdimmNfitMemDev;

/*
 * NVDIMM Control Region Structure
 *
 * It describes the NVDIMM and if applicable, Block Control Window.
 */
struct NvdimmNfitControlRegion {
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
typedef struct NvdimmNfitControlRegion NvdimmNfitControlRegion;

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

/* See the comments of nvdimm_slot_to_spa_index(). */
static uint32_t nvdimm_slot_to_dcr_index(int slot)
{
    return nvdimm_slot_to_spa_index(slot) + 1;
}

/* ACPI 6.0: 5.2.25.1 System Physical Address Range Structure */
static void
nvdimm_build_structure_spa(GArray *structures, NVDIMMDevice *nvdimm)
{
    NvdimmNfitSpa *nfit_spa;
    uint64_t addr = object_property_get_int(OBJECT(nvdimm), DIMM_ADDR_PROP,
                                            NULL);
    uint64_t size = object_property_get_int(OBJECT(nvdimm), DIMM_SIZE_PROP,
                                            NULL);
    uint32_t node = object_property_get_int(OBJECT(nvdimm), DIMM_NODE_PROP,
                                            NULL);
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                            NULL);

    nfit_spa = acpi_data_push(structures, sizeof(*nfit_spa));

    nfit_spa->type = cpu_to_le16(0 /* System Physical Address Range
                                      Structure */);
    nfit_spa->length = cpu_to_le16(sizeof(*nfit_spa));
    nfit_spa->spa_index = cpu_to_le16(nvdimm_slot_to_spa_index(slot));

    /*
     * Control region is strict as all the device info, such as SN, index,
     * is associated with slot id.
     */
    nfit_spa->flags = cpu_to_le16(1 /* Control region is strictly for
                                       management during hot add/online
                                       operation */ |
                                  2 /* Data in Proximity Domain field is
                                       valid*/);

    /* NUMA node. */
    nfit_spa->proximity_domain = cpu_to_le32(node);
    /* the region reported as PMEM. */
    memcpy(nfit_spa->type_guid, nvdimm_nfit_spa_uuid,
           sizeof(nvdimm_nfit_spa_uuid));

    nfit_spa->spa_base = cpu_to_le64(addr);
    nfit_spa->spa_length = cpu_to_le64(size);

    /* It is the PMEM and can be cached as writeback. */
    nfit_spa->mem_attr = cpu_to_le64(0x8ULL /* EFI_MEMORY_WB */ |
                                     0x8000ULL /* EFI_MEMORY_NV */);
}

/*
 * ACPI 6.0: 5.2.25.2 Memory Device to System Physical Address Range Mapping
 * Structure
 */
static void
nvdimm_build_structure_memdev(GArray *structures, NVDIMMDevice *nvdimm)
{
    NvdimmNfitMemDev *nfit_memdev;
    uint64_t addr = object_property_get_int(OBJECT(nvdimm), DIMM_ADDR_PROP,
                                            NULL);
    uint64_t size = object_property_get_int(OBJECT(nvdimm), DIMM_SIZE_PROP,
                                            NULL);
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                            NULL);
    uint32_t handle = nvdimm_slot_to_handle(slot);

    nfit_memdev = acpi_data_push(structures, sizeof(*nfit_memdev));

    nfit_memdev->type = cpu_to_le16(1 /* Memory Device to System Address
                                         Range Map Structure*/);
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

/*
 * ACPI 6.0: 5.2.25.5 NVDIMM Control Region Structure.
 */
static void nvdimm_build_structure_dcr(GArray *structures,
                                       NVDIMMDevice *nvdimm)
{
    NvdimmNfitControlRegion *nfit_dcr;
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                       NULL);
    uint32_t sn = nvdimm_slot_to_sn(slot);

    nfit_dcr = acpi_data_push(structures, sizeof(*nfit_dcr));

    nfit_dcr->type = cpu_to_le16(4 /* NVDIMM Control Region Structure */);
    nfit_dcr->length = cpu_to_le16(sizeof(*nfit_dcr));
    nfit_dcr->dcr_index = cpu_to_le16(nvdimm_slot_to_dcr_index(slot));

    /* vendor: Intel. */
    nfit_dcr->vendor_id = cpu_to_le16(0x8086);
    nfit_dcr->device_id = cpu_to_le16(1);

    /* The _DSM method is following Intel's DSM specification. */
    nfit_dcr->revision_id = cpu_to_le16(1 /* Current Revision supported
                                             in ACPI 6.0 is 1. */);
    nfit_dcr->serial_number = cpu_to_le32(sn);
    nfit_dcr->fic = cpu_to_le16(0x201 /* Format Interface Code. See Chapter
                                         2: NVDIMM Device Specific Method
                                         (DSM) in DSM Spec Rev1.*/);
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

static void nvdimm_build_nfit(GSList *device_list, GArray *table_offsets,
                              GArray *table_data, GArray *linker)
{
    GArray *structures = nvdimm_build_device_structure(device_list);
    void *header;

    acpi_add_table(table_offsets, table_data);

    /* NFIT header. */
    header = acpi_data_push(table_data, sizeof(NvdimmNfitHeader));

    /* NVDIMM device structures. */
    g_array_append_vals(table_data, structures->data, structures->len);

    build_header(linker, table_data, header, "NFIT",
                 sizeof(NvdimmNfitHeader) + structures->len, 1);
    g_array_free(structures, true);
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
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

void nvdimm_init_acpi_state(MemoryRegion *memory, MemoryRegion *io,
                            Object *owner, AcpiNVDIMMState *state)
{
    memory_region_init_ram(&state->ram_mr, owner, "nvdimm-acpi-ram",
                           TARGET_PAGE_SIZE, &error_abort);
    vmstate_register_ram_global(&state->ram_mr);
    memory_region_add_subregion(memory, NVDIMM_ACPI_MEM_BASE, &state->ram_mr);

    memory_region_init_io(&state->io_mr, owner, &nvdimm_dsm_ops, state,
                          "nvdimm-acpi-io", NVDIMM_ACPI_IO_LEN);
    memory_region_add_subregion(io, NVDIMM_ACPI_IO_BASE, &state->io_mr);
}

void nvdimm_build_acpi(GArray *table_offsets, GArray *table_data,
                       GArray *linker)
{
    GSList *device_list;

    /* no NVDIMM device is plugged. */
    device_list = nvdimm_get_plugged_device_list();
    if (!device_list) {
        return;
    }

    nvdimm_build_nfit(device_list, table_offsets, table_data, linker);
    g_slist_free(device_list);
}
