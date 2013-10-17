/* Copyright 2008-2013 Freescale Semiconductor, Inc. */

#ifndef __RTA_FIFO_LOAD_STORE_CMD_H__
#define __RTA_FIFO_LOAD_STORE_CMD_H__

extern enum rta_sec_era rta_sec_era;

static const uint32_t fifo_load_table[][2] = {
/*1*/	{ _PKA0,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 },
	{ _PKA1,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 },
	{ _PKA2,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2 },
	{ _PKA3,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 },
	{ _PKB0,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 },
	{ _PKB1,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1 },
	{ _PKB2,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2 },
	{ _PKB3,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3 },
	{ _PKA,         FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A },
	{ _PKB,         FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B },
	{ _PKN,         FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N },
	{ _SKIP,        FIFOLD_CLASS_SKIP },
	{ _MSG1,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_MSG },
	{ _MSG2,        FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG },
	{ _MSGOUTSNOOP, FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG1OUT2 },
	{ _MSGINSNOOP,  FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG },
	{ _IV1,         FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_IV },
	{ _IV2,         FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_IV },
	{ _AAD1,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_AAD },
	{ _ICV1,        FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_ICV },
	{ _ICV2,        FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_ICV },
	{ _BIT_DATA,    FIFOLD_TYPE_BITDATA },
/*23*/	{ _IFIFO,       FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_DFIFO }
};

/*
 * Allowed FIFO_LOAD input data types for each SEC Era.
 * Values represent the number of entries from fifo_load_table[] that are
 * supported.
 */
static const uint32_t fifo_load_table_sz[] = {22, 22, 23, 23, 23};

static inline unsigned rta_fifo_load(struct program *program, uint32_t src,
				     uint32_t type_src, uint64_t loc,
				     uint32_t type_loc, uint32_t length,
				     uint32_t flags)
{
	uint32_t opcode = 0;
	uint32_t is_seq_cmd = 0, ext_length = 0, val = 0;
	int8_t ret = 0, i;
	unsigned start_pc = program->current_pc;

	/* write command type field */
	if (flags & SEQ) {
		opcode = CMD_SEQ_FIFO_LOAD;
		is_seq_cmd = 1;
	} else
		opcode = CMD_FIFO_LOAD;

	if (type_loc == IMM_DATA)
		flags |= IMMED;

	/* Parameters checking */
	if (is_seq_cmd) {
		if (flags & IMMED) {
			pr_debug("SEQ FIFO LOAD: Invalid command\n");
			goto err;
		}
		if ((flags & VLF) && ((flags & EXT) || (length >> 16))) {
			pr_debug("SEQ FIFO LOAD: Invalid usage of VLF\n");
			goto err;
		}
	} else {
		if (src == _SKIP) {
			pr_debug("FIFO LOAD: Invalid src\n");
			goto err;
		}
		if ((flags & IMMED) && (flags & SGF)) {
			pr_debug("FIFO LOAD: Invalid usage of SGF and IMM\n");
			goto err;
		}
		if ((flags & IMMED) && ((flags & EXT) || (length >> 16))) {
			pr_debug("FIFO LOAD: Invalid usage of EXT and IMM\n");
			goto err;
		}
	}

	/* write input data type field */
	ret = __rta_map_opcode(src, fifo_load_table,
			       fifo_load_table_sz[rta_sec_era], &val);
	if (ret == -1) {
		pr_debug("FIFO LOAD: Source value is not supported. "
				"SEC Program Line: %d\n", program->current_pc);
		goto err;
	}
	opcode |= val;

	if (flags & CLASS1)
		opcode |= FIFOLD_CLASS_CLASS1;
	if (flags & CLASS2)
		opcode |= FIFOLD_CLASS_CLASS2;
	if (flags & BOTH)
		opcode |= FIFOLD_CLASS_BOTH;

	/* write fields: SGF|VLF, IMM, [LC1, LC2, F1] */
	if (flags & FLUSH1)
		opcode |= FIFOLD_TYPE_FLUSH1;
	if (flags & LAST1)
		opcode |= FIFOLD_TYPE_LAST1;
	if (flags & LAST2)
		opcode |= FIFOLD_TYPE_LAST2;
	if (flags & SGF)
		opcode |= FIFOLDST_SGF;
	if (flags & VLF)
		opcode |= FIFOLDST_VLF;
	if (flags & IMMED)
		opcode |= FIFOLD_IMM;

	/*
	 * Verify if extended length is required. In case of BITDATA, calculate
	 * number of full bytes and additional valid bits.
	 */
	if ((flags & EXT) || (length >> 16)) {
		opcode |= FIFOLDST_EXT;
		if (src == _BIT_DATA) {
			ext_length = (length / 8);
			length = (length % 8);
		} else {
			ext_length = length;
			length = 0;
		}
	}
	opcode |= (uint16_t) length;

	program->buffer[program->current_pc] = opcode;
	program->current_pc++;
	program->current_instruction++;

	/* write pointer or immediate data field */
	if (flags & IMMED) {
		if (type_loc == IMM_DATA) {
			if (length > BYTES_4) {
				program->buffer[program->current_pc] =
					high_32b(loc);
				program->current_pc++;
			}

			program->buffer[program->current_pc] = low_32b(loc);
			program->current_pc++;
		} else {
			uint8_t *tmp = (uint8_t *) &program->buffer[program->current_pc];

			for (i = 0; i < length; i++)
				*tmp++ = ((uint8_t *)(uintptr_t)loc)[i];
			program->current_pc += ((length + 3) / 4);
		}
	} else if (!is_seq_cmd) {
		if (program->ps == 1) {
			program->buffer[program->current_pc] = high_32b(loc);
			program->current_pc++;
		}

		program->buffer[program->current_pc] = low_32b(loc);
		program->current_pc++;
	}

	/* write extended length field */
	if (opcode & FIFOLDST_EXT) {
		program->buffer[program->current_pc] = ext_length;
		program->current_pc++;
	}

	return start_pc;

 err:
	program->first_error_pc = start_pc;
	program->current_instruction++;
	return start_pc;
}

static const uint32_t fifo_store_table[][2] = {
/*1*/	{ _PKA0,      FIFOST_TYPE_PKHA_A0 },
	{ _PKA1,      FIFOST_TYPE_PKHA_A1 },
	{ _PKA2,      FIFOST_TYPE_PKHA_A2 },
	{ _PKA3,      FIFOST_TYPE_PKHA_A3 },
	{ _PKB0,      FIFOST_TYPE_PKHA_B0 },
	{ _PKB1,      FIFOST_TYPE_PKHA_B1 },
	{ _PKB2,      FIFOST_TYPE_PKHA_B2 },
	{ _PKB3,      FIFOST_TYPE_PKHA_B3 },
	{ _PKA,       FIFOST_TYPE_PKHA_A },
	{ _PKB,       FIFOST_TYPE_PKHA_B },
	{ _PKN,       FIFOST_TYPE_PKHA_N },
	{ _PKE,       FIFOST_TYPE_PKHA_E_JKEK },
	{ _RNG,       FIFOST_TYPE_RNGSTORE },
	{ _RNGOFIFO,  FIFOST_TYPE_RNGFIFO },
	{ _AFHA_SBOX, FIFOST_TYPE_AF_SBOX_JKEK },
	{ _MDHA_SPLIT_KEY, FIFOST_CLASS_CLASS2KEY | FIFOST_TYPE_SPLIT_KEK },
	{ _MSG,       FIFOST_TYPE_MESSAGE_DATA },
	{ _KEY1,      FIFOST_CLASS_CLASS1KEY | FIFOST_TYPE_KEY_KEK },
	{ _KEY2,      FIFOST_CLASS_CLASS2KEY | FIFOST_TYPE_KEY_KEK },
	{ _OFIFO,     FIFOST_TYPE_OUTFIFO_KEK},
	{ _SKIP,      FIFOST_TYPE_SKIP },
/*22*/	{ _METADATA,  FIFOST_TYPE_METADATA}
};

/*
 * Allowed FIFO_STORE output data types for each SEC Era.
 * Values represent the number of entries from fifo_store_table[] that are
 * supported.
 */
static const uint32_t fifo_store_table_sz[] = {21, 21, 21, 21, 22};

static inline unsigned rta_fifo_store(struct program *program, uint32_t src,
				      uint32_t type_src, uint32_t encrypt_flags,
				      uint64_t dst, uint32_t length,
				      uint32_t flags)
{
	uint32_t opcode = 0;
	uint32_t is_seq_cmd = 0, val = 0;
	int8_t ret = 0;
	unsigned start_pc = program->current_pc;

	/* write command type field */
	if (flags & SEQ) {
		opcode = CMD_SEQ_FIFO_STORE;
		is_seq_cmd = 1;
	} else
		opcode = CMD_FIFO_STORE;

	/* Parameter checking */
	if (is_seq_cmd) {
		if ((flags & VLF) && ((length >> 16) || (flags & EXT))) {
			pr_debug("SEQ FIFO STORE: Invalid usage of VLF\n");
			goto err;
		}
		if (dst) {
			pr_debug("SEQ FIFO STORE: Invalid command\n");
			goto err;
		}
		if ((src == _METADATA) && (flags & (CONT | EXT))) {
			pr_debug("SEQ FIFO STORE: Invalid flags\n");
			goto err;
		}
	} else {
		if (((src == _RNGOFIFO) && ((dst) || (flags & EXT))) ||
		    (src == _METADATA)) {
			pr_debug("FIFO STORE: Invalid destination\n");
			goto err;
		}
	}

	/* write output data type field */
	ret = __rta_map_opcode(src, fifo_store_table,
			       fifo_store_table_sz[rta_sec_era], &val);
	if (ret == -1) {
		pr_debug("FIFO STORE: Source type not supported. "
				"SEC Program Line: %d\n", program->current_pc);
		goto err;
	}
	opcode |= val;

	if (encrypt_flags & TK)
		opcode |= (0x1 << FIFOST_TYPE_SHIFT);
	if (encrypt_flags & EKT) {
		if (rta_sec_era == RTA_SEC_ERA_1) {
			pr_debug("FIFO STORE: AES-CCM source types not "
				 "supported\n");
			goto err;
		}
		opcode |= (0x10 << FIFOST_TYPE_SHIFT);
		opcode &= ~(0x20 << FIFOST_TYPE_SHIFT);
	}

	/* write flags fields */
	if (flags & CONT)
		opcode |= FIFOST_CONT;
	if ((flags & VLF) && (is_seq_cmd))
		opcode |= FIFOLDST_VLF;
	if ((flags & SGF) && (!is_seq_cmd))
		opcode |= FIFOLDST_SGF;
	if (flags & CLASS1)
		opcode |= FIFOST_CLASS_CLASS1KEY;
	if (flags & CLASS2)
		opcode |= FIFOST_CLASS_CLASS2KEY;
	if (flags & BOTH)
		opcode |= FIFOST_CLASS_BOTH;

	/* Verify if extended length is required */
	if ((length >> 16) || (flags & EXT))
		opcode |= FIFOLDST_EXT;
	else
		opcode |= (uint16_t) length;

	program->buffer[program->current_pc] = opcode;
	program->current_pc++;
	program->current_instruction++;

	/* write pointer field */
	if ((!is_seq_cmd) && (dst)) {
		if (program->ps == 1) {
			program->buffer[program->current_pc] = high_32b(dst);
			program->current_pc++;
		}

		program->buffer[program->current_pc] = low_32b(dst);
		program->current_pc++;
	}

	/* write extended length field */
	if (opcode & FIFOLDST_EXT) {
		program->buffer[program->current_pc] = length;
		program->current_pc++;
	}

	return start_pc;

 err:
	program->first_error_pc = start_pc;
	program->current_instruction++;
	return start_pc;
}

#endif /* __RTA_FIFO_LOAD_STORE_CMD_H__ */
