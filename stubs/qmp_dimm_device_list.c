#include "qom/object.h"
#include "hw/mem/dimm.h"

int qmp_dimm_device_list(Object *obj, void *opaque)
{
   return 0;
}

ram_addr_t get_current_ram_size(void)
{
    return ram_size;
}
