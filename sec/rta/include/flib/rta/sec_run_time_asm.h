/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __RTA_SEC_RUN_TIME_ASM_H__
#define __RTA_SEC_RUN_TIME_ASM_H__

#include "flib/desc.h"

/* flib/compat.h is not delivered in kernel */
#ifndef __KERNEL__
#include "flib/compat.h"
#endif

/**
 * enum rta_sec_era - SEC HW block revisions supported by the RTA library
 * @RTA_SEC_ERA_1: SEC Era 1
 * @RTA_SEC_ERA_2: SEC Era 2
 * @RTA_SEC_ERA_3: SEC Era 3
 * @RTA_SEC_ERA_4: SEC Era 4
 * @RTA_SEC_ERA_5: SEC Era 5
 * @RTA_SEC_ERA_6: SEC Era 6
 * @RTA_SEC_ERA_7: SEC Era 7
 * @RTA_SEC_ERA_8: SEC Era 8
 * @MAX_SEC_ERA: maximum SEC HW block revision supported by RTA library
 */
enum rta_sec_era {
	RTA_SEC_ERA_1,
	RTA_SEC_ERA_2,
	RTA_SEC_ERA_3,
	RTA_SEC_ERA_4,
	RTA_SEC_ERA_5,
	RTA_SEC_ERA_6,
	RTA_SEC_ERA_7,
	RTA_SEC_ERA_8,
	MAX_SEC_ERA = RTA_SEC_ERA_8
};

/**
 * DEFAULT_SEC_ERA - the default value for the SEC era in case the user provides
 * an unsupported value.
 */
#define DEFAULT_SEC_ERA	MAX_SEC_ERA

/**
 * USER_SEC_ERA - translates the SEC Era from internal to user representation.
 * @sec_era: SEC Era in internal (library) representation
 */
#define USER_SEC_ERA(sec_era)	(sec_era + 1)

/**
 * INTL_SEC_ERA - translates the SEC Era from user representation to internal.
 * @sec_era: SEC Era in user representation
 */
#define INTL_SEC_ERA(sec_era)	(sec_era - 1)

/**
 * enum rta_jump_type - Types of action taken by JUMP command
 * @LOCAL_JUMP: conditional jump to an offset within the descriptor buffer
 * @FAR_JUMP: conditional jump to a location outside the descriptor buffer,
 *            indicated by the POINTER field after the JUMP command.
 * @HALT: conditional halt - stop the execution of the current descriptor and
 *        writes PKHA / Math condition bits as status / error code.
 * @HALT_STATUS: conditional halt with user-specified status - stop the
 *               execution of the current descriptor and writes the value of
 *               "LOCAL OFFSET" JUMP field as status / error code.
 * @GOSUB: conditional subroutine call - similar to @LOCAL_JUMP, but also saves
 *         return address in the Return Address register; subroutine calls
 *         cannot be nested.
 * @RETURN: conditional subroutine return - similar to @LOCAL_JUMP, but the
 *          offset is taken from the Return Address register.
 * @LOCAL_JUMP_INC: similar to @LOCAL_JUMP, but increment the register specified
 *                  in "SRC_DST" JUMP field before evaluating the jump
 *                  condition.
 * @LOCAL_JUMP_DEC: similar to @LOCAL_JUMP, but decrement the register specified
 *                  in "SRC_DST" JUMP field before evaluating the jump
 *                  condition.
 */
enum rta_jump_type {
	LOCAL_JUMP,
	FAR_JUMP,
	HALT,
	HALT_STATUS,
	GOSUB,
	RETURN,
	LOCAL_JUMP_INC,
	LOCAL_JUMP_DEC
};

/**
 * enum rta_jump_cond - How test conditions are evaluated by JUMP command
 * @ALL_TRUE: perform action if ALL selected conditions are true
 * @ALL_FALSE: perform action if ALL selected conditions are false
 * @ANY_TRUE: perform action if ANY of the selected conditions is true
 * @ANY_FALSE: perform action if ANY of the selected conditions is false
 */
enum rta_jump_cond {
	ALL_TRUE,
	ALL_FALSE,
	ANY_TRUE,
	ANY_FALSE
};

/**
 * enum rta_share_type - Types of sharing for JOB_HDR and SHR_HDR commands
 * @SHR_NEVER: nothing is shared; descriptors can execute in parallel (i.e. no
 *             dependencies are allowed between them).
 * @SHR_WAIT: shared descriptor and keys are shared once the descriptor sets
 *            "OK to share" in DECO Control Register (DCTRL).
 * @SHR_SERIAL: shared descriptor and keys are shared once the descriptor has
 *              completed.
 * @SHR_ALWAYS: shared descriptor is shared anytime after the descriptor is
 *              loaded.
 * @SHR_DEFER: valid only for JOB_HDR; sharing type is the one specified
 *             in the shared descriptor associated with the job descriptor.
 */
enum rta_share_type {
	SHR_NEVER,
	SHR_WAIT,
	SHR_SERIAL,
	SHR_ALWAYS,
	SHR_DEFER
};

/* Registers definitions */
enum rta_regs {
	/* CCB Registers */
	CONTEXT1 = 1,
	CONTEXT2,
	KEY1,
	KEY2,
	KEY1SZ,
	KEY2SZ,
	ICV1SZ,
	ICV2SZ,
	DATA1SZ,
	DATA2SZ,
	ALTDS1,
	IV1SZ,
	AAD1SZ,
	MODE1,
	MODE2,
	CCTRL,
	DCTRL,
	ICTRL,
	CLRW,
	CSTAT,
	IFIFO,
	NFIFO,
	OFIFO,
	PKASZ,
	PKBSZ,
	PKNSZ,
	PKESZ,
	/* DECO Registers */
	MATH0,
	MATH1,
	MATH2,
	MATH3,
	DESCBUF,
	JOBDESCBUF,
	SHAREDESCBUF,
	DPOVRD,
	DJQDA,
	DSTAT,
	DPID,
	DJQCTRL,
	ALTSOURCE,
	SEQINSZ,
	SEQOUTSZ,
	VSEQINSZ,
	VSEQOUTSZ,
	/* PKHA Registers */
	PKA,
	PKN,
	PKA0,
	PKA1,
	PKA2,
	PKA3,
	PKB,
	PKB0,
	PKB1,
	PKB2,
	PKB3,
	PKE,
	/* Pseudo registers */
	AB1,
	AB2,
	ABD,
	IFIFOABD,
	IFIFOAB1,
	IFIFOAB2,
	AFHA_SBOX,
	MDHA_SPLIT_KEY,
	JOBSRC,
	ZERO,
	ONE,
	AAD1,
	IV1,
	IV2,
	MSG1,
	MSG2,
	MSG,
	MSGOUTSNOOP,
	MSGINSNOOP,
	ICV1,
	ICV2,
	SKIP,
	NONE,
	RNGOFIFO,
	RNG,
	IDFNS,
	ODFNS,
	NFIFOSZ,
	SZ,
	PAD,
	SAD1,
	AAD2,
	BIT_DATA,
	NFIFO_SZL,
	NFIFO_SZM,
	NFIFO_L,
	NFIFO_M,
	SZL,
	SZM,
	JOBDESCBUF_EFF,
	SHAREDESCBUF_EFF,
	METADATA,
	GTR,
	STR,
	OFIFO_SYNC,
	MSGOUTSNOOP_ALT
};

/* Command flags */
#define FLUSH1          BIT(0)
#define LAST1           BIT(1)
#define LAST2           BIT(2)
#define IMMED           BIT(3)
#define SGF             BIT(4)
#define VLF             BIT(5)
#define EXT             BIT(6)
#define CONT            BIT(7)
#define SEQ             BIT(8)
#define AIDF		BIT(9)
#define FLUSH2          BIT(10)
#define CLASS1          BIT(11)
#define CLASS2          BIT(12)
#define BOTH            BIT(13)

/**
 * DCOPY - (AIOP only) command param is pointer to external memory
 *
 * CDMA must be used to transfer the key via DMA into Workspace Area.
 * Valid only in combination with IMMED flag.
 */
#define DCOPY		BIT(30)

#define COPY		BIT(31) /*command param is pointer (not immediate)
				  valid only in combination when IMMED */

#define __COPY_MASK	(COPY | DCOPY)

/* SEQ IN/OUT PTR Command specific flags */
#define RBS             BIT(16)
#define INL             BIT(17)
#define PRE             BIT(18)
#define RTO             BIT(19)
#define RJD             BIT(20)
#define SOP		BIT(21)
#define RST		BIT(22)
#define EWS		BIT(23)

#define ENC             BIT(14)	/* Encrypted Key */
#define EKT             BIT(15)	/* AES CCM Encryption (default is
				 * AES ECB Encryption) */
#define TK              BIT(16)	/* Trusted Descriptor Key (default is
				 * Job Descriptor Key) */
#define NWB             BIT(17)	/* No Write Back Key */
#define PTS             BIT(18)	/* Plaintext Store */

/* HEADER Command specific flags */
#define RIF             BIT(16)
#define DNR             BIT(17)
#define CIF             BIT(18)
#define PD              BIT(19)
#define RSMS            BIT(20)
#define TD              BIT(21)
#define MTD             BIT(22)
#define REO             BIT(23)
#define SHR             BIT(24)
#define SC		BIT(25)
/* Extended HEADER specific flags */
#define DSV		BIT(7)
#define DSEL_MASK	0x00000007	/* DECO Select */
#define FTD		BIT(8)

/* JUMP Command specific flags */
#define NIFP            BIT(20)
#define NIP             BIT(21)
#define NOP             BIT(22)
#define NCP             BIT(23)
#define CALM            BIT(24)

#define MATH_Z          BIT(25)
#define MATH_N          BIT(26)
#define MATH_NV         BIT(27)
#define MATH_C          BIT(28)
#define PK_0            BIT(29)
#define PK_GCD_1        BIT(30)
#define PK_PRIME        BIT(31)
#define SELF            BIT(0)
#define SHRD            BIT(1)
#define JQP             BIT(2)

/* NFIFOADD specific flags */
#define PAD_ZERO        BIT(16)
#define PAD_NONZERO     BIT(17)
#define PAD_INCREMENT   BIT(18)
#define PAD_RANDOM      BIT(19)
#define PAD_ZERO_N1     BIT(20)
#define PAD_NONZERO_0   BIT(21)
#define PAD_N1          BIT(23)
#define PAD_NONZERO_N   BIT(24)
#define OC              BIT(25)
#define BM              BIT(26)
#define PR              BIT(27)
#define PS              BIT(28)
#define BP              BIT(29)

/* MOVE Command specific flags */
#define WAITCOMP        BIT(16)
#define SIZE_WORD	BIT(17)
#define SIZE_BYTE	BIT(18)
#define SIZE_DWORD	BIT(19)

/* MATH command specific flags */
#define IFB         MATH_IFB
#define NFU         MATH_NFU
#define STL         MATH_STL
#define SSEL        MATH_SSEL
#define SWP         MATH_SWP
#define IMMED2      BIT(31)

/**
 * struct program - descriptor buffer management structure
 * @current_pc:	current offset in descriptor
 * @current_instruction: current instruction in descriptor
 * @first_error_pc: offset of the first error in descriptor
 * @start_pc: start offset in descriptor buffer
 * @buffer: buffer carrying descriptor
 * @shrhdr: shared descriptor header
 * @jobhdr: job descriptor header
 * @ps: pointer fields size; if ps is true, pointers will be 36bits in
 *      length; if ps is false, pointers will be 32bits in length
 * @bswap: if true, perform byte swap on a 4-byte boundary
 */
struct program {
	unsigned current_pc;
	unsigned current_instruction;
	unsigned first_error_pc;
	unsigned start_pc;
	uint32_t *buffer;
	uint32_t *shrhdr;
	uint32_t *jobhdr;
	bool ps;
	bool bswap;
};

static inline void rta_program_cntxt_init(struct program *program,
					 uint32_t *buffer, unsigned offset)
{
	program->current_pc = 0;
	program->current_instruction = 0;
	program->first_error_pc = 0;
	program->start_pc = offset;
	program->buffer = buffer;
	program->shrhdr = NULL;
	program->jobhdr = NULL;
	program->ps = false;
	program->bswap = false;
}

static inline void __rta__desc_bswap(uint32_t *buff, unsigned buff_len)
{
	unsigned i;

	for (i = 0; i < buff_len; i++)
		buff[i] = swab32(buff[i]);
}

static inline int rta_program_finalize(struct program *program)
{
	/* Descriptor is usually not allowed to go beyond 64 words size */
	if (program->current_pc > MAX_CAAM_DESCSIZE)
		pr_warn("Descriptor Size exceeded max limit of 64 words\n");

	/* Descriptor is erroneous */
	if (program->first_error_pc) {
		pr_err("Descriptor creation error\n");
		return -EINVAL;
	}

	/* Update descriptor length in shared and job descriptor headers */
	if (program->shrhdr != NULL) {
		*program->shrhdr |= program->current_pc;
		if (program->bswap)
			__rta__desc_bswap(program->shrhdr, program->current_pc);
	} else if (program->jobhdr != NULL) {
		*program->jobhdr |= program->current_pc;
		if (program->bswap)
			__rta__desc_bswap(program->jobhdr, program->current_pc);
	}

	return (int)program->current_pc;
}

static inline unsigned rta_program_set_36bit_addr(struct program *program)
{
	program->ps = true;
	return program->current_pc;
}

static inline unsigned rta_program_set_bswap(struct program *program)
{
	program->bswap = true;
	return program->current_pc;
}

static inline void __rta_out32(struct program *program, uint32_t val)
{
	program->buffer[program->current_pc] = val;
	program->current_pc++;
}

static inline void __rta_out64(struct program *program, bool is_ext,
			       uint64_t val)
{
	if (is_ext)
		__rta_out32(program, upper_32_bits(val));

	__rta_out32(program, lower_32_bits(val));
}

static inline unsigned rta_word(struct program *program, uint32_t val)
{
	unsigned start_pc = program->current_pc;

	__rta_out32(program, val);

	return start_pc;
}

static inline unsigned rta_dword(struct program *program, uint64_t val)
{
	unsigned start_pc = program->current_pc;

	__rta_out64(program, true, val);

	return start_pc;
}

static inline unsigned rta_copy_data(struct program *program, uint8_t *data,
				     unsigned length)
{
	unsigned i;
	unsigned start_pc = program->current_pc;
	uint8_t *tmp = (uint8_t *)&program->buffer[program->current_pc];

	for (i = 0; i < length; i++)
		*tmp++ = data[i];
	program->current_pc += (length + 3) / 4;

	return start_pc;
}

#if defined(__EWL__) && defined(AIOP)
static inline void __rta_dma_data(void *ws_dst, uint64_t ext_address,
				  uint16_t size)
{ cdma_read(ws_dst, ext_address, size); }
#else
static inline void __rta_dma_data(void *ws_dst, uint64_t ext_address,
				  uint16_t size)
{ pr_warn("RTA: DCOPY not supported, DMA will be skipped\n"); }
#endif /* defined(__EWL__) && defined(AIOP) */

static inline void __rta_inline_data(struct program *program, uint64_t data,
				     uint32_t copy_data, uint32_t length)
{
	if (!copy_data) {
		__rta_out64(program, length > 4, data);
	} else if (copy_data & COPY) {
		uint8_t *tmp = (uint8_t *)&program->buffer[program->current_pc];
		uint32_t i;

		for (i = 0; i < length; i++)
			*tmp++ = ((uint8_t *)(uintptr_t)data)[i];
		program->current_pc += ((length + 3) / 4);
	} else if (copy_data & DCOPY) {
		__rta_dma_data(&program->buffer[program->current_pc], data,
			       (uint16_t)length);
		program->current_pc += ((length + 3) / 4);
	}
}

static inline unsigned rta_desc_len(uint32_t *buffer)
{
	if ((*buffer & CMD_MASK) == CMD_DESC_HDR)
		return *buffer & HDR_DESCLEN_MASK;
	else
		return *buffer & HDR_DESCLEN_SHR_MASK;
}

static inline unsigned rta_desc_bytes(uint32_t *buffer)
{
	return (unsigned)(rta_desc_len(buffer) * CAAM_CMD_SZ);
}

static inline unsigned rta_set_label(struct program *program)
{
	return program->current_pc + program->start_pc;
}

static inline int rta_patch_move(struct program *program, int line,
				 unsigned new_ref, bool check_swap)
{
	uint32_t opcode;
	bool bswap = check_swap && program->bswap;

	if (line < 0)
		return -EINVAL;

	opcode = bswap ? swab32(program->buffer[line]) : program->buffer[line];

	opcode &= (uint32_t)~MOVE_OFFSET_MASK;
	opcode |= (new_ref << (MOVE_OFFSET_SHIFT + 2)) & MOVE_OFFSET_MASK;
	program->buffer[line] = bswap ? swab32(opcode) : opcode;

	return 0;
}

static inline int rta_patch_jmp(struct program *program, int line,
				unsigned new_ref, bool check_swap)
{
	uint32_t opcode;
	bool bswap = check_swap && program->bswap;

	if (line < 0)
		return -EINVAL;

	opcode = bswap ? swab32(program->buffer[line]) : program->buffer[line];

	opcode &= (uint32_t)~JUMP_OFFSET_MASK;
	opcode |= (new_ref - (line + program->start_pc)) & JUMP_OFFSET_MASK;
	program->buffer[line] = bswap ? swab32(opcode) : opcode;

	return 0;
}

static inline int rta_patch_header(struct program *program, int line,
				   unsigned new_ref, bool check_swap)
{
	uint32_t opcode;
	bool bswap = check_swap && program->bswap;

	if (line < 0)
		return -EINVAL;

	opcode = bswap ? swab32(program->buffer[line]) : program->buffer[line];

	opcode &= (uint32_t)~HDR_START_IDX_MASK;
	opcode |= (new_ref << HDR_START_IDX_SHIFT) & HDR_START_IDX_MASK;
	program->buffer[line] = bswap ? swab32(opcode) : opcode;

	return 0;
}

static inline int rta_patch_load(struct program *program, int line,
				 unsigned new_ref)
{
	uint32_t opcode;

	if (line < 0)
		return -EINVAL;

	opcode = program->buffer[line] & (uint32_t)~LDST_OFFSET_MASK;

	if (opcode & (LDST_SRCDST_WORD_DESCBUF | LDST_CLASS_DECO))
		opcode |= (new_ref << LDST_OFFSET_SHIFT) & LDST_OFFSET_MASK;
	else
		opcode |= (new_ref << (LDST_OFFSET_SHIFT + 2)) &
			  LDST_OFFSET_MASK;

	program->buffer[line] = opcode;

	return 0;
}

static inline int rta_patch_store(struct program *program, int line,
				  unsigned new_ref, bool check_swap)
{
	uint32_t opcode;
	bool bswap = check_swap && program->bswap;

	if (line < 0)
		return -EINVAL;

	opcode = bswap ? swab32(program->buffer[line]) : program->buffer[line];

	opcode &= (uint32_t)~LDST_OFFSET_MASK;

	switch (opcode & LDST_SRCDST_MASK) {
	case LDST_SRCDST_WORD_DESCBUF:
	case LDST_SRCDST_WORD_DESCBUF_JOB:
	case LDST_SRCDST_WORD_DESCBUF_SHARED:
	case LDST_SRCDST_WORD_DESCBUF_JOB_WE:
	case LDST_SRCDST_WORD_DESCBUF_SHARED_WE:
		opcode |= ((new_ref) << LDST_OFFSET_SHIFT) & LDST_OFFSET_MASK;
		break;
	default:
		opcode |= (new_ref << (LDST_OFFSET_SHIFT + 2)) &
			  LDST_OFFSET_MASK;
	}

	program->buffer[line] = bswap ? swab32(opcode) : opcode;

	return 0;
}

static inline int rta_patch_raw(struct program *program, int line,
				unsigned mask, unsigned new_val,
				bool check_swap)
{
	uint32_t opcode;
	bool bswap = check_swap && program->bswap;

	if (line < 0)
		return -EINVAL;

	opcode = bswap ? swab32(program->buffer[line]) : program->buffer[line];

	opcode &= (uint32_t)~mask;
	opcode |= new_val & mask;
	program->buffer[line] = bswap ? swab32(opcode) : opcode;

	return 0;
}

static inline int __rta_map_opcode(uint32_t name,
				  const uint32_t (*map_table)[2],
				  unsigned num_of_entries, uint32_t *val)
{
	unsigned i;

	for (i = 0; i < num_of_entries; i++)
		if (map_table[i][0] == name) {
			*val = map_table[i][1];
			return 0;
		}

	return -EINVAL;
}

static inline void __rta_map_flags(uint32_t flags,
				   const uint32_t (*flags_table)[2],
				   unsigned num_of_entries, uint32_t *opcode)
{
	unsigned i;

	for (i = 0; i < num_of_entries; i++) {
		if (flags_table[i][0] & flags)
			*opcode |= flags_table[i][1];
	}
}

#endif /* __RTA_SEC_RUN_TIME_ASM_H__ */
