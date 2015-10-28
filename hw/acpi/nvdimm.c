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
static const uint8_t nvdimm_nfit_spa_uuid_pm[] =
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
struct nvdimm_nfit {
    ACPI_TABLE_HEADER_DEF
    uint32_t reserved;
} QEMU_PACKED;
typedef struct nvdimm_nfit nvdimm_nfit;

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
struct nvdimm_nfit_spa {
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
typedef struct nvdimm_nfit_spa nvdimm_nfit_spa;

/*
 * Memory Device to System Physical Address Range Mapping Structure
 *
 * It enables identifying each NVDIMM region and the corresponding SPA
 * describing the memory interleave
 */
struct nvdimm_nfit_memdev {
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
typedef struct nvdimm_nfit_memdev nvdimm_nfit_memdev;

/*
 * NVDIMM Control Region Structure
 *
 * It describes the NVDIMM and if applicable, Block Control Window.
 */
struct nvdimm_nfit_dcr {
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
typedef struct nvdimm_nfit_dcr nvdimm_nfit_dcr;

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

/* ACPI 6.0: 5.2.25.1 System Physical Address Range Structure */
static void
nvdimm_build_structure_spa(GArray *structures, NVDIMMDevice *nvdimm)
{
    nvdimm_nfit_spa *nfit_spa;
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
    memcpy(nfit_spa->type_guid, nvdimm_nfit_spa_uuid_pm,
           sizeof(nvdimm_nfit_spa_uuid_pm));

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
    nvdimm_nfit_memdev *nfit_memdev;
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
    nvdimm_nfit_dcr *nfit_dcr;
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
    header = acpi_data_push(table_data, sizeof(nvdimm_nfit));

    /* NVDIMM device structures. */
    g_array_append_vals(table_data, structures->data, structures->len);

    build_header(linker, table_data, header, "NFIT",
                 sizeof(nvdimm_nfit) + structures->len, 1);
    g_array_free(structures, true);
}

/* define NVDIMM DSM return status codes according to DSM Spec Rev1. */
enum {
    /* Common return status codes. */
    /* Success */
    NVDIMM_DSM_STATUS_SUCCESS = 0,
    /* Not Supported */
    NVDIMM_DSM_STATUS_NOT_SUPPORTED = 1,

    /* NVDIMM Root Device _DSM function return status codes*/
    /* Invalid Input Parameters */
    NVDIMM_DSM_ROOT_DEV_STATUS_INVALID_PARAS = 2,
    /* Function-Specific Error */
    NVDIMM_DSM_ROOT_DEV_STATUS_FUNCTION_SPECIFIC_ERROR = 3,

    /* NVDIMM Device (non-root) _DSM function return status codes*/
    /* Non-Existing Memory Device */
    NVDIMM_DSM_DEV_STATUS_NON_EXISTING_MEM_DEV = 2,
    /* Invalid Input Parameters */
    NVDIMM_DSM_DEV_STATUS_INVALID_PARAS = 3,
    /* Vendor Specific Error */
    NVDIMM_DSM_DEV_STATUS_VENDOR_SPECIFIC_ERROR = 4,
};

struct nvdimm_dsm_in {
    uint32_t handle;
    uint32_t revision;
    uint32_t function;
   /* the remaining size in the page is used by arg3. */
    uint8_t arg3[0];
} QEMU_PACKED;
typedef struct nvdimm_dsm_in nvdimm_dsm_in;

static void nvdimm_dsm_write_status(GArray *out, uint32_t status)
{
    status = cpu_to_le32(status);
    build_append_int_noprefix(out, status, sizeof(status));
}

static void nvdimm_dsm_root(nvdimm_dsm_in *in, GArray *out)
{
    uint32_t status = NVDIMM_DSM_STATUS_NOT_SUPPORTED;

    /*
     * Query command implemented per ACPI Specification, it is defined in
     * ACPI 6.0: 9.14.1 _DSM (Device Specific Method).
     */
    if (in->function == 0x0) {
        /*
         * Set it to zero to indicate no function is supported for NVDIMM
         * root.
         */
        uint64_t cmd_list = cpu_to_le64(0);

        build_append_int_noprefix(out, cmd_list, sizeof(cmd_list));
        return;
    }

    nvdimm_debug("Return status %#x.\n", status);
    nvdimm_dsm_write_status(out, status);
}

static void nvdimm_dsm_device(nvdimm_dsm_in *in, GArray *out)
{
    GSList *list = nvdimm_get_plugged_device_list();
    NVDIMMDevice *nvdimm = nvdimm_get_device_by_handle(list, in->handle);
    uint32_t status = NVDIMM_DSM_DEV_STATUS_NON_EXISTING_MEM_DEV;
    uint64_t cmd_list;

    if (!nvdimm) {
        goto set_status_free;
    }

    /* Encode DSM function according to DSM Spec Rev1. */
    switch (in->function) {
    /* see comments in nvdimm_dsm_root(). */
    case 0x0:
        cmd_list = cpu_to_le64(0x1 /* Bit 0 indicates whether there is
                                      support for any functions other
                                      than function 0.
                                    */                               |
                               1 << 4 /* Get Namespace Label Size */ |
                               1 << 5 /* Get Namespace Label Data */ |
                               1 << 6 /* Set Namespace Label Data */);
        build_append_int_noprefix(out, cmd_list, sizeof(cmd_list));
        goto free;
    default:
        status = NVDIMM_DSM_STATUS_NOT_SUPPORTED;
    };

set_status_free:
    nvdimm_debug("Return status %#x.\n", status);
    nvdimm_dsm_write_status(out, status);
free:
    g_slist_free(list);
}

static uint64_t
nvdimm_dsm_read(void *opaque, hwaddr addr, unsigned size)
{
    AcpiNVDIMMState *state = opaque;
    MemoryRegion *dsm_ram_mr = &state->ram_mr;
    nvdimm_dsm_in *in;
    GArray *out;
    void *dsm_ram_addr;
    uint32_t buf_size;

    assert(memory_region_size(dsm_ram_mr) >= sizeof(nvdimm_dsm_in));
    dsm_ram_addr = memory_region_get_ram_ptr(dsm_ram_mr);

    /*
     * The DSM memory is mapped to guest address space so an evil guest
     * can change its content while we are doing DSM emulation. Avoid
     * this by copying DSM memory to QEMU local memory.
     */
    in = g_malloc(memory_region_size(dsm_ram_mr));
    memcpy(in, dsm_ram_addr, memory_region_size(dsm_ram_mr));

    le32_to_cpus(&in->revision);
    le32_to_cpus(&in->function);
    le32_to_cpus(&in->handle);

    nvdimm_debug("Revision %#x Handler %#x Function %#x.\n", in->revision,
                 in->handle, in->function);

    out = g_array_new(false, true /* clear */, 1);

    if (in->revision != 0x1 /* Current we support DSM Spec Rev1. */) {
        nvdimm_debug("Revision %#x is not supported, expect %#x.\n",
                      in->revision, 0x1);
        nvdimm_dsm_write_status(out, NVDIMM_DSM_STATUS_NOT_SUPPORTED);
        goto exit;
    }

    /* Handle 0 is reserved for NVDIMM Root Device. */
    if (!in->handle) {
        nvdimm_dsm_root(in, out);
        goto exit;
    }

    nvdimm_dsm_device(in, out);

exit:
    /* Write output result to dsm memory. */
    memcpy(dsm_ram_addr, out->data, out->len);
    memory_region_set_dirty(dsm_ram_mr, 0, out->len);

    buf_size = cpu_to_le32(out->len);

    g_free(in);
    g_array_free(out, true);
    return buf_size;
}

static void
nvdimm_dsm_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    fprintf(stderr, "BUG: we never write DSM notification IO Port.\n");
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
                           getpagesize(), &error_abort);
    vmstate_register_ram_global(&state->ram_mr);
    memory_region_add_subregion(memory, NVDIMM_ACPI_MEM_BASE, &state->ram_mr);

    memory_region_init_io(&state->io_mr, owner, &nvdimm_dsm_ops, state,
                          "nvdimm-acpi-io", NVDIMM_ACPI_IO_LEN);
    memory_region_add_subregion(io, NVDIMM_ACPI_IO_BASE, &state->io_mr);
}

#define BUILD_STA_METHOD(_dev_, _method_)                                  \
    do {                                                                   \
        _method_ = aml_method("_STA", 0);                                  \
        aml_append(_method_, aml_return(aml_int(0x0f)));                   \
        aml_append(_dev_, _method_);                                       \
    } while (0)

#define BUILD_DSM_METHOD(_dev_, _method_, _handle_, _uuid_)                \
    do {                                                                   \
        Aml *ifctx, *uuid;                                                 \
        _method_ = aml_method("_DSM", 4);                                  \
        /* check UUID if it is we expect, return the errorcode if not.*/   \
        uuid = aml_touuid(_uuid_);                                         \
        ifctx = aml_if(aml_lnot(aml_equal(aml_arg(0), uuid)));             \
        aml_append(ifctx, aml_return(aml_int(1 /* Not Supported */)));     \
        aml_append(method, ifctx);                                         \
        aml_append(method, aml_return(aml_call4("NCAL", aml_int(_handle_), \
                   aml_arg(1), aml_arg(2), aml_arg(3))));                  \
        aml_append(_dev_, _method_);                                       \
    } while (0)

#define BUILD_FIELD_UNIT_SIZE(_field_, _byte_, _name_)                     \
    aml_append(_field_, aml_named_field(_name_, (_byte_) * BITS_PER_BYTE))

#define BUILD_FIELD_UNIT_STRUCT(_field_, _s_, _f_, _name_)                 \
    BUILD_FIELD_UNIT_SIZE(_field_, sizeof(typeof_field(_s_, _f_)), _name_)

static void build_nvdimm_devices(GSList *device_list, Aml *root_dev)
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
         * Chapter 4: _DSM Interface for NVDIMM Device (non-root) - Example
         * in DSM Spec Rev1.
         */
        BUILD_DSM_METHOD(dev, method,
                         handle /* NVDIMM Device Handle */,
                         "4309AC30-0D11-11E4-9191-0800200C9A66"
                         /* UUID for NVDIMM Devices. */);

        aml_append(root_dev, dev);
    }
}

static void nvdimm_build_acpi_devices(GSList *device_list, Aml *sb_scope)
{
    Aml *dev, *method, *field;
    uint64_t page_size = getpagesize();

    dev = aml_device("NVDR");
    aml_append(dev, aml_name_decl("_HID", aml_string("ACPI0012")));

    /* map DSM memory and IO into ACPI namespace. */
    aml_append(dev, aml_operation_region("NPIO", AML_SYSTEM_IO,
               NVDIMM_ACPI_IO_BASE, NVDIMM_ACPI_IO_LEN));
    aml_append(dev, aml_operation_region("NRAM", AML_SYSTEM_MEMORY,
               NVDIMM_ACPI_MEM_BASE, page_size));

    /*
     * DSM notifier:
     * @NOTI: Read it will notify QEMU that _DSM method is being
     *        called and the parameters can be found in nvdimm_dsm_in.
     *        The value read from it is the buffer size of DSM output
     *        filled by QEMU.
     */
    field = aml_field("NPIO", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_SIZE(field, sizeof(uint32_t), "NOTI");
    aml_append(dev, field);

    /*
     * DSM input:
     * @HDLE: store device's handle, it's zero if the _DSM call happens
     *        on NVDIMM Root Device.
     * @REVS: store the Arg1 of _DSM call.
     * @FUNC: store the Arg2 of _DSM call.
     * @ARG3: store the Arg3 of _DSM call.
     *
     * They are RAM mapping on host so that these accesses never cause
     * VM-EXIT.
     */
    field = aml_field("NRAM", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_STRUCT(field, nvdimm_dsm_in, handle, "HDLE");
    BUILD_FIELD_UNIT_STRUCT(field, nvdimm_dsm_in, revision, "REVS");
    BUILD_FIELD_UNIT_STRUCT(field, nvdimm_dsm_in, function, "FUNC");
    BUILD_FIELD_UNIT_SIZE(field, page_size - offsetof(nvdimm_dsm_in, arg3),
                          "ARG3");
    aml_append(dev, field);

    /*
     * DSM output:
     * @ODAT: the buffer QEMU uses to store the result, the actual size
     *        filled by QEMU is the value read from NOT1.
     *
     * Since the page is reused by both input and out, the input data
     * will be lost after storing new result into @ODAT.
    */
    field = aml_field("NRAM", AML_DWORD_ACC, AML_PRESERVE);
    BUILD_FIELD_UNIT_SIZE(field, page_size, "ODAT");
    aml_append(dev, field);

    method = aml_method_serialized("NCAL", 4);
    {
        Aml *ifctx, *pckg, *buffer_size = aml_local(0);

        aml_append(method, aml_store(aml_arg(0), aml_name("HDLE")));
        aml_append(method, aml_store(aml_arg(1), aml_name("REVS")));
        aml_append(method, aml_store(aml_arg(2), aml_name("FUNC")));

        /*
         * The fourth parameter (Arg3) of _DSM is a package which contains
         * a buffer, the layout of the buffer is specified by UUID (Arg0),
         * Revision ID (Arg1) and Function Index (Arg2) which are documented
         * in the DSM Spec.
         */
        pckg = aml_arg(3);
        ifctx = aml_if(aml_and(aml_equal(aml_object_type(pckg),
                                         aml_int(4 /* Package */)),
                               aml_equal(aml_sizeof(pckg),
                                         aml_int(1))));
        {
            Aml *pckg_index, *pckg_buf;

            pckg_index = aml_local(2);
            pckg_buf = aml_local(3);

            aml_append(ifctx, aml_store(aml_index(pckg, aml_int(0)),
                                        pckg_index));
            aml_append(ifctx, aml_store(aml_derefof(pckg_index),
                                        pckg_buf));
            aml_append(ifctx, aml_store(pckg_buf, aml_name("ARG3")));
        }
        aml_append(method, ifctx);

        /*
         * transfer control to QEMU and the buffer size filled by
         * QEMU is returned.
         */
        aml_append(method, aml_store(aml_name("NOTI"), buffer_size));

        aml_append(method, aml_store(aml_shiftleft(buffer_size,
                                       aml_int(3)), buffer_size));

        aml_append(method, aml_create_field(aml_name("ODAT"), aml_int(0),
                                            buffer_size , "OBUF"));
        aml_append(method, aml_concatenate(aml_buffer(0, NULL),
                                           aml_name("OBUF"), aml_local(1)));
        aml_append(method, aml_return(aml_local(1)));
    }
    aml_append(dev, method);

    BUILD_STA_METHOD(dev, method);

    /*
     * Chapter 3: _DSM Interface for NVDIMM Root Device - Example in DSM
     * Spec Rev1.
     */
    BUILD_DSM_METHOD(dev, method,
                     0 /* 0 is reserved for NVDIMM Root Device*/,
                     "2F10E7A4-9E91-11E4-89D3-123B93F75CBA"
                     /* UUID for NVDIMM Root Devices. */);

    build_nvdimm_devices(device_list, dev);

    aml_append(sb_scope, dev);
}

static void nvdimm_build_ssdt(GSList *device_list, GArray *table_offsets,
                              GArray *table_data, GArray *linker)
{
    Aml *ssdt, *sb_scope;

    acpi_add_table(table_offsets, table_data);

    ssdt = init_aml_allocator();
    acpi_data_push(ssdt->buf, sizeof(AcpiTableHeader));

    sb_scope = aml_scope("\\_SB");
    nvdimm_build_acpi_devices(device_list, sb_scope);

    aml_append(ssdt, sb_scope);
    /* copy AML table into ACPI tables blob and patch header there */
    g_array_append_vals(table_data, ssdt->buf->data, ssdt->buf->len);
    build_header(linker, table_data,
        (void *)(table_data->data + table_data->len - ssdt->buf->len),
        "SSDT", ssdt->buf->len, 1);
    free_aml_allocator();
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
    nvdimm_build_ssdt(device_list, table_offsets, table_data, linker);
    g_slist_free(device_list);
}
