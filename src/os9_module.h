
#ifndef OS9_MODULE_H
#define OS9_MODULE_H

#include <r_types.h>


#define OS9_BASE_HEADER_SIZE		0x30


extern const ut8 os9_module_sync[];


// values for M$type

#define OS9_MODULE_TYPE_PROGRAM		1
#define OS9_MODULE_TYPE_SUBROUTINE	2
#define OS9_MODULE_TYPE_MULTI		3
#define OS9_MODULE_TYPE_DATA		4
#define OS9_MODULE_TYPE_CSDDATA		5
#define OS9_MODULE_TYPE_TRAPLIB		11
#define OS9_MODULE_TYPE_SYSTM		12
#define OS9_MODULE_TYPE_FLMGR		13
#define OS9_MODULE_TYPE_DRIVR		14
#define OS9_MODULE_TYPE_DEVIC		15


// values for M$Lang

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


typedef struct os9_module_ext_header
{
	ut32 exec_offset;
	ut32 excpt;
	ut32 mem_size;
	ut32 stack_size;
	ut32 idata_offset;
	ut32 irefs_offset;
	ut32 init_offset;
	ut32 term_offset;
} os9_module_ext_header_t;


ut64 os9_header_size(ut8 module_type);

bool os9_read_header(const ut8 *buf, ut64 size, os9_module_header_t *header);
bool os9_read_ext_header(const ut8 *buf, ut64 size, ut8 module_type, os9_module_ext_header_t *header);


#endif