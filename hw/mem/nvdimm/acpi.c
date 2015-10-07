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

static bool dsm_is_root_uuid(uint8_t *uuid)
{
    uuid_le uuid_root = UUID_LE(0x2f10e7a4, 0x9e91, 0x11e4, 0x89,
                                0xd3, 0x12, 0x3b, 0x93, 0xf7, 0x5c, 0xba);

    return !memcmp(uuid, &uuid_root, sizeof(uuid_root));
}

static bool dsm_is_dimm_uuid(uint8_t *uuid)
{
    uuid_le uuid_dimm = UUID_LE(0x4309ac30, 0x0d11, 0x11e4, 0x91,
                                0x91, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66);

    return !memcmp(uuid, &uuid_dimm, sizeof(uuid_dimm));
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

static NVDIMMDevice
*get_nvdimm_device_by_handle(GSList *list, uint32_t handle)
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

#define NOTIFY_VALUE      0x99

enum {
    DSM_CMD_IMPLEMENTED = 0,

    /* root device commands */
    DSM_CMD_ARS_CAP = 1,
    DSM_CMD_ARS_START = 2,
    DSM_CMD_ARS_QUERY = 3,

    /* per-nvdimm device commands */
    DSM_CMD_SMART = 1,
    DSM_CMD_SMART_THRESHOLD = 2,
    DSM_CMD_BLOCK_NVDIMM_FLAGS = 3,
    DSM_CMD_NAMESPACE_LABEL_SIZE = 4,
    DSM_CMD_GET_NAMESPACE_LABEL_DATA = 5,
    DSM_CMD_SET_NAMESPACE_LABEL_DATA = 6,
    DSM_CMD_VENDOR_EFFECT_LOG_SIZE = 7,
    DSM_CMD_GET_VENDOR_EFFECT_LOG = 8,
    DSM_CMD_VENDOR_SPECIFIC = 9,
};

enum {
    DSM_STATUS_SUCCESS = 0,
    DSM_STATUS_NOT_SUPPORTED = 1,
    DSM_STATUS_NON_EXISTING_MEM_DEV = 2,
    DSM_STATUS_INVALID_PARAS = 3,
    DSM_STATUS_VENDOR_SPECIFIC_ERROR = 4,
};

#define DSM_REVISION        (1)

/* do not support any command except NFIT_CMD_IMPLEMENTED on root. */
#define ROOT_SUPPORT_CMD    (1 << DSM_CMD_IMPLEMENTED)
#define DIMM_SUPPORT_CMD    ((1 << DSM_CMD_IMPLEMENTED)               \
                           | (1 << DSM_CMD_NAMESPACE_LABEL_SIZE)      \
                           | (1 << DSM_CMD_GET_NAMESPACE_LABEL_DATA)  \
                           | (1 << DSM_CMD_SET_NAMESPACE_LABEL_DATA))

struct cmd_in_get_label_data {
    uint32_t offset;
    uint32_t length;
} QEMU_PACKED;
typedef struct cmd_in_get_label_data cmd_in_get_label_data;

struct cmd_in_set_label_data {
    uint32_t offset;
    uint32_t length;
    uint8_t in_buf[0];
} QEMU_PACKED;
typedef struct cmd_in_set_label_data cmd_in_set_label_data;

struct dsm_in {
    uint32_t handle;
    uint8_t arg0[16];
    uint32_t arg1;
    uint32_t arg2;
   /* the remaining size in the page is used by arg3. */
    union {
        uint8_t arg3[0];
        cmd_in_set_label_data cmd_set_label_data;
        cmd_in_get_label_data cmd_get_label_data;
    };
} QEMU_PACKED;
typedef struct dsm_in dsm_in;

struct cmd_out_implemented {
    uint64_t cmd_list;
};
typedef struct cmd_out_implemented cmd_out_implemented;

struct cmd_out_label_size {
    uint32_t status;
    uint32_t label_size;
    uint32_t max_xfer;
} QEMU_PACKED;
typedef struct cmd_out_label_size cmd_out_label_size;

struct cmd_out_get_label_data {
    uint32_t status;
    uint8_t out_buf[0];
} QEMU_PACKED;
typedef struct cmd_out_get_label_data cmd_out_get_label_data;

struct cmd_out_set_label_data {
    uint32_t status;
};
typedef struct cmd_out_set_label_data cmd_out_set_label_data;

struct dsm_out {
    /* the size of buffer filled by QEMU. */
    uint16_t len;
    union {
        uint8_t data[0];
        uint32_t status;
        cmd_out_implemented cmd_implemented;
        cmd_out_label_size cmd_label_size;
        cmd_out_get_label_data cmd_get_label_data;
        cmd_out_set_label_data cmd_set_label_data;
    };
} QEMU_PACKED;
typedef struct dsm_out dsm_out;

static uint64_t dsm_read(void *opaque, hwaddr addr,
                         unsigned size)
{
    fprintf(stderr, "BUG: we never read DSM notification MMIO.\n");
    return 0;
}

static void dsm_write_root(uint32_t function, dsm_in *in, dsm_out *out)
{
    if (function == DSM_CMD_IMPLEMENTED) {
        out->len = sizeof(out->cmd_implemented);
        out->cmd_implemented.cmd_list = cpu_to_le64(ROOT_SUPPORT_CMD);
        return;
    }

    out->len = sizeof(out->status);
    out->status = cpu_to_le32(DSM_STATUS_NOT_SUPPORTED);
    nvdebug("Return status %#x.\n", out->status);
}

/*
 * the max transfer size is the max size transfered by both a
 * DSM_CMD_GET_NAMESPACE_LABEL_DATA and a DSM_CMD_SET_NAMESPACE_LABEL_DATA
 * command.
 */
static uint32_t max_xfer_label_size(MemoryRegion *dsm_ram_mr)
{
    dsm_in *in;
    dsm_out *out;
    uint32_t mr_size, max_get_size, max_set_size;

    mr_size = memory_region_size(dsm_ram_mr);

    /*
     * the max data ACPI can read one time which is transfered by
     * the response of DSM_CMD_GET_NAMESPACE_LABEL_DATA.
     */
    max_get_size = mr_size - offsetof(dsm_out, data) -
                   sizeof(out->cmd_get_label_data);

    /*
     * the max data ACPI can write one time which is transfered by
     * DSM_CMD_SET_NAMESPACE_LABEL_DATA
     */
    max_set_size = mr_size - offsetof(dsm_in, arg3) -
                   sizeof(in->cmd_set_label_data);

    return MIN(max_get_size, max_set_size);
}

static uint32_t
dsm_cmd_label_size(MemoryRegion *dsm_ram_mr, NVDIMMDevice *nvdimm,
                    dsm_out *out)
{
    uint32_t label_size, mxfer;

    label_size = nvdimm->label_size;
    mxfer = max_xfer_label_size(dsm_ram_mr);

    out->cmd_label_size.label_size = cpu_to_le32(label_size);
    out->cmd_label_size.max_xfer = cpu_to_le32(mxfer);
    out->len = sizeof(out->cmd_label_size);

    nvdebug("%s label_size %#x, max_xfer %#x.\n", __func__, label_size, mxfer);

    return DSM_STATUS_SUCCESS;
}

static uint32_t dsm_cmd_get_label_data(NVDIMMDevice *nvdimm, dsm_in *in,
                                       dsm_out *out)
{
    cmd_in_get_label_data *cmd_in = &in->cmd_get_label_data;
    uint32_t length, offset, status;

    length = cmd_in->length;
    offset = cmd_in->offset;
    le32_to_cpus(&length);
    le32_to_cpus(&offset);

    nvdebug("Read Label Data: offset %#x length %#x.\n", offset, length);

    if (nvdimm->label_size < length + offset) {
        nvdebug("position %#x is beyond label data (len = %#lx).\n",
                length + offset, nvdimm->label_size);
        out->len = sizeof(out->status);
        status = DSM_STATUS_INVALID_PARAS;
        goto exit;
    }

    status = DSM_STATUS_SUCCESS;
    memcpy(out->cmd_get_label_data.out_buf, nvdimm->label_data +
           offset, length);
    out->len = sizeof(out->cmd_get_label_data) + length;
exit:
    return status;
}

static uint32_t
dsm_cmd_set_label_data(NVDIMMDevice *nvdimm, dsm_in *in, dsm_out *out)
{
    cmd_in_set_label_data *cmd_in = &in->cmd_set_label_data;
    uint32_t length, offset, status;

    length = cmd_in->length;
    offset = cmd_in->offset;
    le32_to_cpus(&length);
    le32_to_cpus(&offset);

    nvdebug("Write Label Data: offset %#x length %#x.\n", offset, length);
    if (nvdimm->label_size < length + offset) {
        nvdebug("position %#x is beyond config data (len = %#lx).\n",
                length + offset, nvdimm->label_size);
        out->len = sizeof(out->status);
        status = DSM_STATUS_INVALID_PARAS;
        goto exit;
    }

    status = DSM_STATUS_SUCCESS;
    memcpy(nvdimm->label_data + offset, cmd_in->in_buf, length);
    out->len = sizeof(status);
exit:
    return status;
}

static void dsm_write_nvdimm(MemoryRegion *dsm_ram_mr, uint32_t handle,
                             uint32_t function, dsm_in *in, dsm_out *out)
{
    GSList *list = nvdimm_get_built_list();
    NVDIMMDevice *nvdimm = get_nvdimm_device_by_handle(list, handle);
    uint32_t status = DSM_STATUS_NON_EXISTING_MEM_DEV;
    uint64_t cmd_list;

    if (!nvdimm) {
        out->len = sizeof(out->status);
        goto set_status_free;
    }

    switch (function) {
    case DSM_CMD_IMPLEMENTED:
        cmd_list = DIMM_SUPPORT_CMD;
        out->len = sizeof(out->cmd_implemented);
        out->cmd_implemented.cmd_list = cpu_to_le64(cmd_list);
        goto free;
    case DSM_CMD_NAMESPACE_LABEL_SIZE:
        status = dsm_cmd_label_size(dsm_ram_mr, nvdimm, out);
        break;
    case DSM_CMD_GET_NAMESPACE_LABEL_DATA:
        status = dsm_cmd_get_label_data(nvdimm, in, out);
        break;
    case DSM_CMD_SET_NAMESPACE_LABEL_DATA:
        status = dsm_cmd_set_label_data(nvdimm, in, out);
        break;
    default:
        out->len = sizeof(out->status);
        status = DSM_STATUS_NOT_SUPPORTED;
    };

    nvdebug("Return status %#x.\n", status);

set_status_free:
    out->status = cpu_to_le32(status);
free:
    g_slist_free(list);
}

static void dsm_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    NVDIMMState *state = opaque;
    MemoryRegion *dsm_ram_mr;
    dsm_in *in;
    dsm_out *out;
    uint32_t revision, function, handle;

    if (val != NOTIFY_VALUE) {
        fprintf(stderr, "BUG: unexepected notify value 0x%" PRIx64, val);
    }

    dsm_ram_mr = memory_region_find(&state->mr, state->page_size,
                                    state->page_size).mr;
    memory_region_unref(dsm_ram_mr);
    in = memory_region_get_ram_ptr(dsm_ram_mr);
    out = (dsm_out *)in;

    revision = in->arg1;
    function = in->arg2;
    handle = in->handle;
    le32_to_cpus(&revision);
    le32_to_cpus(&function);
    le32_to_cpus(&handle);

    nvdebug("UUID " UUID_FMT ".\n", in->arg0[0], in->arg0[1], in->arg0[2],
            in->arg0[3], in->arg0[4], in->arg0[5], in->arg0[6],
            in->arg0[7], in->arg0[8], in->arg0[9], in->arg0[10],
            in->arg0[11], in->arg0[12], in->arg0[13], in->arg0[14],
            in->arg0[15]);
    nvdebug("Revision %#x Function %#x Handler %#x.\n", revision, function,
            handle);

    if (revision != DSM_REVISION) {
        nvdebug("Revision %#x is not supported, expect %#x.\n",
                revision, DSM_REVISION);
        goto exit;
    }

    if (!handle) {
        if (!dsm_is_root_uuid(in->arg0)) {
            nvdebug("Root UUID does not match.\n");
            goto exit;
        }

        return dsm_write_root(function, in, out);
    }

    if (!dsm_is_dimm_uuid(in->arg0)) {
        nvdebug("DIMM UUID does not match.\n");
        goto exit;
    }

    return dsm_write_nvdimm(dsm_ram_mr, handle, function, in, out);

exit:
    out->len = sizeof(out->status);
    out->status = cpu_to_le32(DSM_STATUS_NOT_SUPPORTED);
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

#define BUILD_STA_METHOD(_dev_, _method_)                                  \
    do {                                                                   \
        _method_ = aml_method("_STA", 0);                                  \
        aml_append(_method_, aml_return(aml_int(0x0f)));                   \
        aml_append(_dev_, _method_);                                       \
    } while (0)

#define SAVE_ARG012_HANDLE_LOCK(_method_, _handle_)                        \
    do {                                                                   \
        aml_append(_method_, aml_acquire(aml_name("NLCK"), 0xFFFF));       \
        aml_append(_method_, aml_store(_handle_, aml_name("HDLE")));       \
        aml_append(_method_, aml_store(aml_arg(0), aml_name("ARG0")));     \
        aml_append(_method_, aml_store(aml_arg(1), aml_name("ARG1")));     \
        aml_append(_method_, aml_store(aml_arg(2), aml_name("ARG2")));     \
    } while (0)

#define NOTIFY_AND_RETURN_UNLOCK(_method_)                           \
    do {                                                                   \
        aml_append(_method_, aml_store(aml_int(NOTIFY_VALUE),              \
                   aml_name("NOTI")));                                     \
        aml_append(_method_, aml_store(aml_name("RLEN"), aml_local(6)));   \
        aml_append(_method_, aml_store(aml_shiftleft(aml_local(6),         \
                      aml_int(3)), aml_local(6)));                         \
        aml_append(_method_, aml_create_field(aml_name("ODAT"), aml_int(0),\
                                              aml_local(6) , "OBUF"));     \
        aml_append(_method_, aml_name_decl("ZBUF", aml_buffer(0, NULL)));  \
        aml_append(_method_, aml_concatenate(aml_name("ZBUF"),             \
                                          aml_name("OBUF"), aml_arg(6)));  \
        aml_append(_method_, aml_release(aml_name("NLCK")));               \
        aml_append(_method_, aml_return(aml_arg(6)));                      \
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
        Aml *dev, *method, *ifctx;

        dev = aml_device("NV%02X", slot);
        aml_append(dev, aml_name_decl("_ADR", aml_int(handle)));

        BUILD_STA_METHOD(dev, method);

        method = aml_method("_DSM", 4);
        {
            SAVE_ARG012_HANDLE_LOCK(method, aml_int(handle));

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

            NOTIFY_AND_RETURN_UNLOCK(method);
        }
        aml_append(dev, method);

        aml_append(root_dev, dev);
    }
}

static void nvdimm_build_acpi_devices(NVDIMMState *state, GSList *device_list,
                                      Aml *sb_scope)
{
    Aml *dev, *method, *field;
    int fit_size = nvdimm_device_structure_size(g_slist_length(device_list));

    dev = aml_device("NVDR");
    aml_append(dev, aml_name_decl("_HID", aml_string("ACPI0012")));

    /* map DSM memory into ACPI namespace. */
    aml_append(dev, aml_operation_region("NMIO", AML_SYSTEM_MEMORY,
               state->base, state->page_size));
    aml_append(dev, aml_operation_region("NRAM", AML_SYSTEM_MEMORY,
               state->base + state->page_size, state->page_size));
    aml_append(dev, aml_operation_region("NFIT", AML_SYSTEM_MEMORY,
               state->base + state->page_size * 2,
               memory_region_size(&state->mr) - state->page_size * 2));

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
    BUILD_FIELD_UNIT_STRUCT(field, dsm_in, arg0, "ARG0");
    BUILD_FIELD_UNIT_STRUCT(field, dsm_in, arg1, "ARG1");
    BUILD_FIELD_UNIT_STRUCT(field, dsm_in, arg2, "ARG2");
    BUILD_FIELD_UNIT_SIZE(field, state->page_size - offsetof(dsm_in, arg3),
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
    BUILD_FIELD_UNIT_SIZE(field, state->page_size - offsetof(dsm_out, data),
                          "ODAT");
    aml_append(dev, field);

    /* @RFIT, returned by _FIT method. */
    field = aml_field("NFIT", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_SIZE(field, fit_size, "RFIT");
    aml_append(dev, field);

    aml_append(dev, aml_mutex("NLCK", 0));

    BUILD_STA_METHOD(dev, method);

    method = aml_method("_DSM", 4);
    {
        SAVE_ARG012_HANDLE_LOCK(method, aml_int(0));
        /* no command we support on ROOT device has Arg3. */
        NOTIFY_AND_RETURN_UNLOCK(method);
    }
    aml_append(dev, method);

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

        nvdimm_build_ssdt(state, device_list, table_offsets, table_data,
                          linker);
        g_slist_free(device_list);
    }
}
