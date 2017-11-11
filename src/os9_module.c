
#include "os9_module.h"

const ut8 os9_module_sync[] = { 0x4a, 0xfc };

ut64 os9_header_size(ut8 module_type)
{
	switch(module_type)
	{
		case OS9_MODULE_TYPE_FLMGR:
		case OS9_MODULE_TYPE_SYSTM:
			return 0x38;
		case OS9_MODULE_TYPE_DRIVR:
			return 0x3c;
		case OS9_MODULE_TYPE_PROGRAM:
			return 0x48;
		case OS9_MODULE_TYPE_TRAPLIB:
			return 0x50;
		default:
			return OS9_BASE_HEADER_SIZE;
	}
}


bool os9_read_header(const ut8 *buf, ut64 size, os9_module_header_t *header)
{
	if(size < OS9_BASE_HEADER_SIZE)
		return false;

	header->id = r_read_be16(buf);
	header->sys_ref = r_read_be16(buf + 0x02);
	header->size = r_read_be32(buf + 0x04);
	header->owner = r_read_be32(buf + 0x08);
	header->name_offset = r_read_be32(buf + 0x0c);
	header->accs = r_read_be16(buf + 0x10);
	header->type = r_read_be8(buf  + 0x12);
	header->lang = r_read_be8(buf  + 0x13);
	header->attr = r_read_be8(buf  + 0x14);
	header->revs = r_read_be8(buf  + 0x15);
	header->edit = r_read_be16(buf + 0x16);
	header->usage = r_read_be32(buf + 0x18);
	header->symbol = r_read_be32(buf + 0x1c);
	// 16 bit parity at buf + 0x2e

	return true;
}

bool os9_read_ext_header(const ut8 *buf, ut64 size, ut8 module_type, os9_module_ext_header_t *header)
{
	ut64 header_size = os9_header_size(module_type);

	if(size < header_size)
		return false;

	memset(header, 0, sizeof(os9_module_ext_header_t));


	// file manager / system

	if(header_size < 0x38)
		return true;

	header->exec_offset = r_read_be32(buf + 0x30);
	header->excpt = r_read_be32(buf + 0x34);


	// device driver

	if(header_size < 0x3c)
		return true;

	header->mem_size = r_read_be32(buf + 0x38);


	// program

	if(header_size < 0x48)
		return true;

	header->stack_size = r_read_be32(buf + 0x3c);
	header->idata_offset = r_read_be32(buf + 0x40);
	header->irefs_offset = r_read_be32(buf + 0x44);


	// trap handlers

	if(header_size < 0x50)
		return true;

	header->exec_offset = r_read_be32(buf + 0x48);
	header->term_offset = r_read_be32(buf + 0x4c);


	return true;
}