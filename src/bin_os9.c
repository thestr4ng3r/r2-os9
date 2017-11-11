/*
 * r2-os9
 * Copyright (C) 2017 Florian Maerkl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>

#include "os9_module.h"


typedef struct os9_module_info
{
	os9_module_header_t header;
	os9_module_ext_header_t ext_header;
} os9_module_info_t;



static ut64 p2v(ut64 offset)
{
	return offset;
}


static bool check_bytes(const ut8 *buf, ut64 length)
{
	return buf && length >= 2 &&
		memcmp(buf, &os9_module_sync, 2) == 0;
}


static void header(RBinFile *bf)
{
	os9_module_info_t *info = bf->o->bin_obj;

	if(!info)
		return;

	const ut8 *buf = r_buf_get_at(bf->buf, 0, NULL);

#define p bf->rbin->cb_printf
	p("0x00000000  M$ID        0x%04x\n", info->header.id);
	p("0x00000002  M$SysRev    0x%04x\n", info->header.sys_ref);
	p("0x00000004  M$Size      0x%08x\n", info->header.size);
	p("0x00000008  M$Owner     0x%08x\n", info->header.owner);
	p("0x0000000c  M$Name      0x%08x\n", info->header.name_offset);
	p("0x00000010  M$Accs      0x%04x\n", info->header.accs);
	p("0x00000012  M$Type      0x%02x\n", info->header.type);
	p("0x00000013  M$Lang      0x%02x\n", info->header.lang);
	p("0x00000014  M$Attr      0x%02x\n", info->header.attr);
	p("0x00000015  M$Revs      0x%02x\n", info->header.revs);
	p("0x00000016  M$Edit      0x%04x\n", info->header.edit);
	p("0x00000018  M$Usage     0x%08x\n", info->header.usage);
	p("0x0000001c  M$Symbol    0x%08x\n", info->header.symbol);
	p("0x0000002e  M$Parity    0x%04x\n", r_read_be16(buf + 0x2e));

	p("\nadditional values:\n");
	p("0x00000000  M$Exec      0x%08x\n", info->ext_header.exec_offset);
	p("0x00000002  M$Excpt     0x%08x\n", info->ext_header.excpt);
	p("0x00000004  M$Mem       0x%08x\n", info->ext_header.mem_size);
	p("0x00000008  M$Stack     0x%08x\n", info->ext_header.stack_size);
	p("0x0000000c  M$IData     0x%08x\n", info->ext_header.idata_offset);
	p("0x00000010  M$IRefs     0x%08x\n", info->ext_header.irefs_offset);
	p("0x00000012  M$Init      0x%08x\n", info->ext_header.init_offset);
	p("0x00000012  M$Term      0x%08x\n", info->ext_header.term_offset);
#undef p
}



static void *load_bytes(RBinFile *bf, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb)
{
	if(!buf || !sz || sz == UT64_MAX)
		return NULL;

	os9_module_info_t *info = malloc(sizeof(os9_module_info_t));

	if(!os9_read_header(buf, sz, &info->header))
	{
		free(info);
		return NULL;
	}

	if(!os9_read_ext_header(buf, sz, info->header.type, &info->ext_header))
	{
		free(info);
		return NULL;
	}

	return info;
}



static bool load(RBinFile *bf)
{
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	ut64 sz = bf ? r_buf_size (bf->buf) : 0;

	if(!bf || !bf->o)
		return false;

	bf->o->bin_obj = load_bytes (bf, bytes, sz, bf->o->loadaddr, bf->sdb);
	return bf->o->bin_obj != NULL;
}

static int destroy(RBinFile *bf)
{
	free(bf->o->bin_obj);
	return true;
}

static RBinInfo *info(RBinFile *bf)
{
	os9_module_info_t *info = bf->o->bin_obj;

	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret)
		return NULL;

	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->bits = 32;
	ret->big_endian = true;

	if (info->header.lang == OS9_LANG_68K)
	{
		ret->arch = strdup("m68k");
	}

	return ret;
}

static ut64 baddr(RBinFile *bf)
{
	return 0LL;
}

static RList *sections(RBinFile *bf)
{
	os9_module_info_t *info = bf->o->bin_obj;
	if(!info)
		return NULL;

	RList *ret = NULL;
	if(!(ret = r_list_new ()))
		return NULL;


	ut64 header_size = os9_header_size(info->header.type);

	RBinSection *header_section = R_NEW0 (RBinSection);
	if(!header_section)
		return ret;
	strcpy (header_section->name, "header");
	header_section->paddr = 0;
	header_section->size = header_size;
	header_section->vaddr = p2v(0);
	header_section->vsize = header_section->size;
	header_section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
	header_section->add = true;
	r_list_append (ret, header_section);


	ut64 sz = r_buf_size (bf->buf);
	ut64 body_size = sz - header_size - OS9_CRC_SIZE;

	RBinSection *body_section = R_NEW0 (RBinSection);
	if(!body_section)
		return ret;
	strcpy (body_section->name, "body");
	body_section->paddr = header_size;
	body_section->size = body_size;
	body_section->vaddr = p2v(body_section->paddr);
	body_section->vsize = body_section->size;
	body_section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	body_section->add = true;
	r_list_append (ret, body_section);


	RBinSection *crc_section = R_NEW0 (RBinSection);
	if(!crc_section)
		return ret;
	strcpy (crc_section->name, "crc");
	crc_section->paddr = header_size + body_size;
	crc_section->size = OS9_CRC_SIZE;
	crc_section->vaddr = p2v(crc_section->paddr);
	crc_section->vsize = crc_section->size;
	crc_section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
	crc_section->add = true;
	r_list_append (ret, crc_section);

	return ret;
}


static RList *entries(RBinFile *bf)
{
	os9_module_info_t *info = bf->o->bin_obj;
	if(!info)
		return NULL;

	RList *ret;
	if(!(ret = r_list_new ()))
		return NULL;

	if(info->header.type == OS9_MODULE_TYPE_PROGRAM
	   || info->header.type == OS9_MODULE_TYPE_TRAPLIB
	   || info->header.type == OS9_MODULE_TYPE_DRIVR
	   || info->header.type == OS9_MODULE_TYPE_FLMGR
	   || info->header.type == OS9_MODULE_TYPE_SYSTM)
	{
		RBinAddr *entry;
		if(!(entry = R_NEW0(RBinAddr)))
			return ret;
		r_list_append(ret, entry);

		entry->bits = 32;
		entry->paddr = info->ext_header.exec_offset;
		entry->vaddr = p2v(entry->paddr);
		entry->haddr = 0x30;
	}

	return ret;
}



RBinPlugin r_bin_plugin_os9 = {
	.name = "os9",
	.desc = "OS-9 module format",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.load = &load,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.header = &header,
	.baddr = &baddr,
	.info = &info,
	.sections = &sections,
	.entries = &entries
};



#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_os9,
	.version = R2_VERSION
};
#endif
