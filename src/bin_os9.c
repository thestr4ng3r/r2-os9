
#include <stdio.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>

#define OS9_HEADER_SIZE			0x30

static ut8 os9_module_sync[] = { 0x4a, 0xfc };

#define OS9_LANG_UNSPECIFIED	0
#define OS9_LANG_68K			1
#define OS9_LANG_BASIC_ICODE	2
#define OS9_LANG_PASCAL_PCODE	3
#define OS9_LANG_C_ICODE		4
#define OS9_LANG_COBOL_ICODE	5
#define OS9_LANG_FORTRAN		6


typedef struct os9_module_header
{
	ut16 id;
	ut16 sys_ref;
	ut32 size;
	ut32 owner;
	ut32 name_offset;
	ut16 accs;
	ut8 type;
	ut8 lang;
	ut8 attr;
	ut8 revs;
	ut16 edit;
	ut32 usage;
	ut32 symbol;
} os9_module_header_t;


static bool os9_read_header(const ut8 *buf, ut64 size, os9_module_header_t *header)
{
	if(size < OS9_HEADER_SIZE)
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
	// p("0x0000002e  M$Parity    0x%04x\n", r_read_be16(buf + 0x2e));

	return true;
}




typedef struct os9_module_info
{
	os9_module_header_t header;
} os9_module_info_t;






static bool check_bytes(const ut8 *buf, ut64 length)
{
	return buf && length >= 2 &&
		memcmp(buf, &os9_module_sync, 2) == 0;
}


static void header(RBinFile *bf)
{
#define p bf->rbin->cb_printf
	const ut8 *buf = r_buf_get_at (bf->buf, 0, NULL);
	p("0x00000000  M$ID        0x%04x\n", r_read_be16(buf));
	p("0x00000002  M$SysRev    0x%04x\n", r_read_be16(buf + 0x02));
	p("0x00000004  M$Size      0x%08x\n", r_read_be32(buf + 0x04));
	p("0x00000008  M$Owner     0x%08x\n", r_read_be32(buf + 0x08));
	p("0x0000000c  M$Name      0x%08x\n", r_read_be32(buf + 0x0c));
	p("0x00000010  M$Accs      0x%04x\n", r_read_be16(buf + 0x10));
	p("0x00000012  M$Type      0x%02x\n", r_read_be8(buf  + 0x12));
	p("0x00000013  M$Lang      0x%02x\n", r_read_be8(buf  + 0x13));
	p("0x00000014  M$Attr      0x%02x\n", r_read_be8(buf  + 0x14));
	p("0x00000015  M$Revs      0x%02x\n", r_read_be8(buf  + 0x15));
	p("0x00000016  M$Edit      0x%04x\n", r_read_be16(buf + 0x16));
	p("0x00000018  M$Usage     0x%08x\n", r_read_be32(buf + 0x18));
	p("0x0000001c  M$Symbol    0x%08x\n", r_read_be32(buf + 0x1c));
	p("0x0000002e  M$Parity    0x%04x\n", r_read_be16(buf + 0x2e));
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
	ut64 sz = r_buf_size (bf->buf);

	if(sz == 0)
		return NULL;

	RList *ret = NULL;
	if(!(ret = r_list_new ()))
		return NULL;

	RBinSection *header_section = R_NEW0 (RBinSection);
	if(!header_section)
		return ret;
	strcpy (header_section->name, "header");
	header_section->paddr = 0;
	header_section->size = 0x30;
	header_section->vaddr = 0;
	header_section->vsize = header_section->size;
	header_section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
	header_section->add = true;
	r_list_append (ret, header_section);

	return ret;
}


static RList* entries(RBinFile *bf)
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
