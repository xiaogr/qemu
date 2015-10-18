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

static NVDIMMDevice
*nvdimm_get_device_by_handle(GSList *list, uint32_t handle)
{
    for (; list; list = list->next) {
        NVDIMMDevice *nvdimm = list->data;
        int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                           NULL);

        if (nvdimm_slot_to_handle(slot) == handle) {
            return nvdimm;
        }
    }

    return NULL;
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

/* detailed _DSM design please refer to docs/specs/acpi_nvdimm.txt */
#define NOTIFY_VALUE      0x99

enum {
    DSM_FUN_IMPLEMENTED = 0,

    /* NVDIMM Root Device Functions */
    DSM_ROOT_DEV_FUN_ARS_CAP = 1,
    DSM_ROOT_DEV_FUN_ARS_START = 2,
    DSM_ROOT_DEV_FUN_ARS_QUERY = 3,

    /* NVDIMM Device (non-root) Functions */
    DSM_DEV_FUN_SMART = 1,
    DSM_DEV_FUN_SMART_THRESHOLD = 2,
    DSM_DEV_FUN_BLOCK_NVDIMM_FLAGS = 3,
    DSM_DEV_FUN_NAMESPACE_LABEL_SIZE = 4,
    DSM_DEV_FUN_GET_NAMESPACE_LABEL_DATA = 5,
    DSM_DEV_FUN_SET_NAMESPACE_LABEL_DATA = 6,
    DSM_DEV_FUN_VENDOR_EFFECT_LOG_SIZE = 7,
    DSM_DEV_FUN_GET_VENDOR_EFFECT_LOG = 8,
    DSM_DEV_FUN_VENDOR_SPECIFIC = 9,
};

enum {
    /* Common return status codes. */
    DSM_STATUS_SUCCESS = 0,                   /* Success */
    DSM_STATUS_NOT_SUPPORTED = 1,             /* Not Supported */

    /* NVDIMM Root Device _DSM function return status codes*/
    DSM_ROOT_DEV_STATUS_INVALID_PARAS = 2,    /* Invalid Input Parameters */
    DSM_ROOT_DEV_STATUS_FUNCTION_SPECIFIC_ERROR = 3, /* Function-Specific
                                                        Error */

    /* NVDIMM Device (non-root) _DSM function return status codes*/
    DSM_DEV_STATUS_NON_EXISTING_MEM_DEV = 2,  /* Non-Existing Memory Device */
    DSM_DEV_STATUS_INVALID_PARAS = 3,         /* Invalid Input Parameters */
    DSM_DEV_STATUS_VENDOR_SPECIFIC_ERROR = 4, /* Vendor Specific Error */
};

/* Current revision supported by DSM specification is 1. */
#define DSM_REVISION        (1)

/*
 * please refer to ACPI 6.0: 9.14.1 _DSM (Device Specific Method): Return
 * Value Information:
 *   if set to zero, no functions are supported (other than function zero)
 *   for the specified UUID and Revision ID. If set to one, at least one
 *   additional function is supported.
 */

/* do not support any function on root. */
#define ROOT_SUPPORT_FUN     (0ULL)
#define DIMM_SUPPORT_FUN    ((1 << DSM_FUN_IMPLEMENTED)                   \
                           | (1 << DSM_DEV_FUN_NAMESPACE_LABEL_SIZE)      \
                           | (1 << DSM_DEV_FUN_GET_NAMESPACE_LABEL_DATA)  \
                           | (1 << DSM_DEV_FUN_SET_NAMESPACE_LABEL_DATA))

struct dsm_in {
    uint32_t handle;
    uint32_t revision;
    uint32_t function;
   /* the remaining size in the page is used by arg3. */
    uint8_t arg3[0];
} QEMU_PACKED;
typedef struct dsm_in dsm_in;

struct cmd_out_implemented {
    uint64_t cmd_list;
};
typedef struct cmd_out_implemented cmd_out_implemented;

struct dsm_out {
    /* the size of buffer filled by QEMU. */
    uint32_t len;
    uint8_t data[0];
} QEMU_PACKED;
typedef struct dsm_out dsm_out;

static uint64_t
nvdimm_dsm_read(void *opaque, hwaddr addr, unsigned size)
{
    fprintf(stderr, "BUG: we never read DSM notification MMIO.\n");
    return 0;
}

static void nvdimm_dsm_write_status(GArray *out, uint32_t status)
{
    /* status locates in the first 4 bytes in the dsm memory. */
    assert(!out->len);

    status = cpu_to_le32(status);
    g_array_append_vals(out, &status, sizeof(status));
}

static void nvdimm_dsm_write_root(dsm_in *in, GArray *out)
{
    uint32_t status = DSM_STATUS_NOT_SUPPORTED;

    /* please refer to ACPI 6.0: 9.14.1 _DSM (Device Specific Method) */
    if (in->function == DSM_FUN_IMPLEMENTED) {
        uint64_t cmd_list = cpu_to_le64(ROOT_SUPPORT_FUN);

        g_array_append_vals(out, &cmd_list, sizeof(cmd_list));
        return;
    }

    nvdimm_debug("Return status %#x.\n", status);
    nvdimm_dsm_write_status(out, status);
}

static void nvdimm_dsm_write_nvdimm(dsm_in *in, GArray *out)
{
    GSList *list = nvdimm_get_plugged_device_list();
    NVDIMMDevice *nvdimm = nvdimm_get_device_by_handle(list, in->handle);
    uint32_t status = DSM_DEV_STATUS_NON_EXISTING_MEM_DEV;
    uint64_t cmd_list;

    if (!nvdimm) {
        goto set_status_free;
    }

    switch (in->function) {
    /* please refer to ACPI 6.0: 9.14.1 _DSM (Device Specific Method) */
    case DSM_FUN_IMPLEMENTED:
        cmd_list = cpu_to_le64(DIMM_SUPPORT_FUN);
        g_array_append_vals(out, &cmd_list, sizeof(cmd_list));
        goto free;
    default:
        status = DSM_STATUS_NOT_SUPPORTED;
    };

set_status_free:
    nvdimm_debug("Return status %#x.\n", status);
    nvdimm_dsm_write_status(out, status);
free:
    g_slist_free(list);
}

static void
nvdimm_dsm_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    NVDIMMState *state = opaque;
    MemoryRegion *dsm_ram_mr;
    dsm_in *in;
    GArray *out;
    void *dsm_ram_addr;

    if (val != NOTIFY_VALUE) {
        fprintf(stderr, "BUG: unexepected notify value 0x%" PRIx64, val);
    }

    dsm_ram_mr = memory_region_find(&state->mr, getpagesize(),
                                    getpagesize()).mr;
    dsm_ram_addr = memory_region_get_ram_ptr(dsm_ram_mr);

    /*
     * copy all input data to our local memory to avoid potential issue
     * as the dsm memory is visible to guest.
     */
    in = g_malloc(memory_region_size(dsm_ram_mr));
    memcpy(in, dsm_ram_addr, memory_region_size(dsm_ram_mr));

    le32_to_cpus(&in->revision);
    le32_to_cpus(&in->function);
    le32_to_cpus(&in->handle);

    nvdimm_debug("Revision %#x Handler %#x Function %#x.\n", in->revision,
                 in->handle, in->function);

    out = g_array_new(false, true /* clear */, 1);

    if (in->revision != DSM_REVISION) {
        nvdimm_debug("Revision %#x is not supported, expect %#x.\n",
                      in->revision, DSM_REVISION);
        nvdimm_dsm_write_status(out, DSM_STATUS_NOT_SUPPORTED);
        goto exit;
    }

    /* Handle 0 is reserved for NVDIMM Root Device. */
    if (!in->handle) {
        nvdimm_dsm_write_root(in, out);
        goto exit;
    }

    nvdimm_dsm_write_nvdimm(in, out);

exit:
    /* Write our output result to dsm memory. */
    ((dsm_out *)dsm_ram_addr)->len = out->len;
    memcpy(((dsm_out *)dsm_ram_addr)->data, out->data, out->len);

    g_free(in);
    g_array_free(out, true);
    memory_region_unref(dsm_ram_mr);
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

#define BUILD_STA_METHOD(_dev_, _method_)                                  \
    do {                                                                   \
        _method_ = aml_method("_STA", 0);                                  \
        aml_append(_method_, aml_return(aml_int(0x0f)));                   \
        aml_append(_dev_, _method_);                                       \
    } while (0)

#define BUILD_DSM_METHOD(_dev_, _method_, _handle_, _errcode_, _uuid_)     \
    do {                                                                   \
        Aml *ifctx, *uuid;                                                 \
        _method_ = aml_method("_DSM", 4);                                  \
        /* check UUID if it is we expect, return the errorcode if not.*/   \
        uuid = aml_touuid(_uuid_);                                         \
        ifctx = aml_if(aml_lnot(aml_equal(aml_arg(0), uuid)));             \
        aml_append(ifctx, aml_return(aml_int(_errcode_)));                 \
        aml_append(method, ifctx);                                         \
        aml_append(method, aml_return(aml_call4("NCAL", aml_int(_handle_), \
                   aml_arg(1), aml_arg(2), aml_arg(3))));                  \
        aml_append(_dev_, _method_);                                       \
    } while (0)

#define BUILD_FIELD_UNIT_STRUCT(_field_, _s_, _f_, _name_)                 \
    aml_append(_field_, aml_named_field(_name_,                            \
               sizeof(typeof_field(_s_, _f_)) * BITS_PER_BYTE))

#define BUILD_FIELD_UNIT_SIZE(_field_, _byte_, _name_)                     \
    aml_append(_field_, aml_named_field(_name_, (_byte_) * BITS_PER_BYTE))

static void build_nvdimm_devices(NVDIMMState *state, GSList *device_list,
                                 Aml *root_dev)
{
    for (; device_list; device_list = device_list->next) {
        NVDIMMDevice *nvdimm = device_list->data;
        int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP,
                                           NULL);
        uint32_t handle = nvdimm_slot_to_handle(slot);
        Aml *dev, *method;

        dev = aml_device("NV%02X", slot);
        aml_append(dev, aml_name_decl("_ADR", aml_int(handle)));

        BUILD_STA_METHOD(dev, method);

        /*
         * Please refer to DSM specification Chapter 4 _DSM Interface
         * for NVDIMM Device (non-root) - Example
         */
        BUILD_DSM_METHOD(dev, method,
                         handle /* NVDIMM Device Handle */,
                         DSM_DEV_STATUS_INVALID_PARAS, /* error code if UUID
                                                         is not matched. */
                         "4309AC30-0D11-11E4-9191-0800200C9A66"
                         /* UUID for NVDIMM Devices. */);

        aml_append(root_dev, dev);
    }
}

static void nvdimm_build_acpi_devices(NVDIMMState *state, GSList *device_list,
                                      Aml *sb_scope)
{
    Aml *dev, *method, *field;
    uint64_t page_size = getpagesize();
    int fit_size = nvdimm_device_structure_size(g_slist_length(device_list));

    dev = aml_device("NVDR");
    aml_append(dev, aml_name_decl("_HID", aml_string("ACPI0012")));

    /* map DSM memory into ACPI namespace. */
    aml_append(dev, aml_operation_region("NMIO", AML_SYSTEM_MEMORY,
               state->base, page_size));
    aml_append(dev, aml_operation_region("NRAM", AML_SYSTEM_MEMORY,
               state->base + page_size, page_size));
    aml_append(dev, aml_operation_region("NFIT", AML_SYSTEM_MEMORY,
               state->base + page_size * 2,
               memory_region_size(&state->mr) - page_size * 2));

    /*
     * DSM notifier:
     * @NOTI: write value to it will notify QEMU that _DSM method is being
     *        called and the parameters can be found in dsm_in.
     *
     * It is MMIO mapping on host so that it will cause VM-exit then QEMU
     * gets control.
     */
    field = aml_field("NMIO", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_SIZE(field, sizeof(uint32_t), "NOTI");
    aml_append(dev, field);

    /*
     * DSM input:
     * @HDLE: store device's handle, it's zero if the _DSM call happens
     *        on ROOT.
     * @ARG0 ~ @ARG3: store the parameters of _DSM call.
     *
     * They are ram mapping on host so that these accesses never cause
     * VM-EXIT.
     */
    field = aml_field("NRAM", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_STRUCT(field, dsm_in, handle, "HDLE");
    BUILD_FIELD_UNIT_STRUCT(field, dsm_in, revision, "REVS");
    BUILD_FIELD_UNIT_STRUCT(field, dsm_in, function, "FUNC");
    BUILD_FIELD_UNIT_SIZE(field, page_size - offsetof(dsm_in, arg3),
                          "ARG3");
    aml_append(dev, field);

    /*
     * DSM output:
     * @RLEN: the size of buffer filled by QEMU
     * @ODAT: the buffer QEMU uses to store the result
     *
     * Since the page is reused by both input and out, the input data
     * will be lost after storing new result into @RLEN and @ODAT
    */
    field = aml_field("NRAM", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_STRUCT(field, dsm_out, len, "RLEN");
    BUILD_FIELD_UNIT_SIZE(field, page_size - offsetof(dsm_out, data),
                          "ODAT");
    aml_append(dev, field);

    /* @RFIT, returned by _FIT method. */
    field = aml_field("NFIT", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_SIZE(field, fit_size, "RFIT");
    aml_append(dev, field);

    method = aml_method_serialized("NCAL", 4);
    {
        Aml *ifctx;

        aml_append(method, aml_store(aml_arg(0), aml_name("HDLE")));
        aml_append(method, aml_store(aml_arg(1), aml_name("REVS")));
        aml_append(method, aml_store(aml_arg(2), aml_name("FUNC")));

        /* Arg3 is passed as Package and it has one element? */
        ifctx = aml_if(aml_and(aml_equal(aml_object_type(aml_arg(3)),
                                         aml_int(4)),
                               aml_equal(aml_sizeof(aml_arg(3)),
                                         aml_int(1))));
        {
            /* Local0 = Index(Arg3, 0) */
            aml_append(ifctx, aml_store(aml_index(aml_arg(3), aml_int(0)),
                                        aml_local(0)));
            /* Local3 = DeRefOf(Local0) */
            aml_append(ifctx, aml_store(aml_derefof(aml_local(0)),
                                        aml_local(3)));
            /* ARG3 = Local3 */
            aml_append(ifctx, aml_store(aml_local(3), aml_name("ARG3")));
        }
        aml_append(method, ifctx);

        aml_append(method, aml_store(aml_int(NOTIFY_VALUE), aml_name("NOTI")));

        aml_append(method, aml_store(aml_name("RLEN"), aml_local(6)));
        aml_append(method, aml_store(aml_shiftleft(aml_local(6),
                                       aml_int(3)), aml_local(6)));
        aml_append(method, aml_create_field(aml_name("ODAT"), aml_int(0),
                                            aml_local(6) , "OBUF"));
        aml_append(method, aml_name_decl("ZBUF", aml_buffer(0, NULL)));
        aml_append(method, aml_concatenate(aml_name("ZBUF"),
                                           aml_name("OBUF"), aml_arg(6)));
        aml_append(method, aml_return(aml_arg(6)));
    }
    aml_append(dev, method);

    BUILD_STA_METHOD(dev, method);

    /*
     * please refer to DSM specification Chapter 3 _DSM Interface for
     * NVDIMM Root Device - Example
     */
    BUILD_DSM_METHOD(dev, method,
                     0 /* 0 is reserved for NVDIMM Root Device*/,
                     DSM_ROOT_DEV_STATUS_INVALID_PARAS, /* error code if
                                                     UUID is not matched. */
                     "2F10E7A4-9E91-11E4-89D3-123B93F75CBA"
                     /* UUID for NVDIMM Root Devices. */);

    method = aml_method("_FIT", 0);
    {
        aml_append(method, aml_return(aml_name("RFIT")));
    }
    aml_append(dev, method);

    build_nvdimm_devices(state, device_list, dev);

    aml_append(sb_scope, dev);
}

static void nvdimm_build_ssdt(NVDIMMState *state, GSList *device_list,
                              GArray *table_offsets, GArray *table_data,
                              GArray *linker)
{
    Aml *ssdt, *sb_scope;

    acpi_add_table(table_offsets, table_data);

    ssdt = init_aml_allocator();
    acpi_data_push(ssdt->buf, sizeof(AcpiTableHeader));

    sb_scope = aml_scope("\\_SB");
    nvdimm_build_acpi_devices(state, device_list, sb_scope);

    aml_append(ssdt, sb_scope);
    /* copy AML table into ACPI tables blob and patch header there */
    g_array_append_vals(table_data, ssdt->buf->data, ssdt->buf->len);
    build_header(linker, table_data,
        (void *)(table_data->data + table_data->len - ssdt->buf->len),
        "SSDT", ssdt->buf->len, 1);
    free_aml_allocator();
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

    nvdimm_build_ssdt(state, device_list, table_offsets, table_data,
                      linker);

    memory_region_unref(fit_mr);
    g_slist_free(device_list);
    g_array_free(structures, true);
}
