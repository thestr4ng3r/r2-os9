
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

	RBinSection *header_section = R_NEW0 (RBinSection);
	if(!header_section)
		return ret;
	strcpy (header_section->name, "header");
	header_section->paddr = 0;
	header_section->size = OS9_BASE_HEADER_SIZE;
	header_section->vaddr = 0;
	header_section->vsize = header_section->size;
	header_section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
	header_section->add = true;
	r_list_append (ret, header_section);

	return ret;
}


static RList *entries(RBinFile *bf)
{
	const ut8 *buf = r_buf_buffer (bf->buf);
	ut64 sz = r_buf_size (bf->buf);

	RList *ret;
	if(!(ret = r_list_new ()))
		return NULL;

	RBinAddr *ptr;
	if(!(ptr = R_NEW0(RBinAddr)))
		return ret;

	// TODO

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
