/* Copyright 2008-2013 Freescale Semiconductor, Inc. */

#ifndef __RTA_MOVE_CMD_H__
#define __RTA_MOVE_CMD_H__

#define MOVE_SET_AUX_SRC  1
#define MOVE_SET_AUX_DST  2
#define MOVE_SET_AUX_LS   3
#define MOVE_SET_LEN_16b  4

#define MASK_16b  0xFF

extern enum rta_sec_era rta_sec_era;

static const uint32_t move_src_table[][2] = {
/*1*/	{ _CONTEXT1, MOVE_SRC_CLASS1CTX },
	{ _CONTEXT2, MOVE_SRC_CLASS2CTX },
	{ _OFIFO,    MOVE_SRC_OUTFIFO },
	{ _DESCBUF,  MOVE_SRC_DESCBUF },
	{ _MATH0,    MOVE_SRC_MATH0 },
	{ _MATH1,    MOVE_SRC_MATH1 },
	{ _MATH2,    MOVE_SRC_MATH2 },
	{ _MATH3,    MOVE_SRC_MATH3 },
/*9*/	{ _IFIFOABD, MOVE_SRC_INFIFO },
	{ _IFIFOAB1, MOVE_SRC_INFIFO_CL | MOVE_AUX_LS },
	{ _IFIFOAB2, MOVE_SRC_INFIFO_CL },
/*12*/	{ _ABD,      MOVE_SRC_INFIFO_NO_NFIFO },
	{ _AB1,      MOVE_SRC_INFIFO_NO_NFIFO | MOVE_AUX_LS },
	{ _AB2,      MOVE_SRC_INFIFO_NO_NFIFO | MOVE_AUX_MS }
};

/* Allowed MOVE / MOVE_LEN sources for each SEC Era.
 * Values represent the number of entries from move_src_table[] that are
 * supported.
 */
static const uint32_t move_src_table_sz[] = {9, 11, 14, 14, 14};

static const uint32_t move_dst_table[][2] = {
/*1*/	{ _CONTEXT1,  MOVE_DEST_CLASS1CTX },
	{ _CONTEXT2,  MOVE_DEST_CLASS2CTX },
	{ _OFIFO,     MOVE_DEST_OUTFIFO },
	{ _DESCBUF,   MOVE_DEST_DESCBUF },
	{ _MATH0,     MOVE_DEST_MATH0 },
	{ _MATH1,     MOVE_DEST_MATH1 },
	{ _MATH2,     MOVE_DEST_MATH2 },
	{ _MATH3,     MOVE_DEST_MATH3 },
	{ _IFIFOAB1,  MOVE_DEST_CLASS1INFIFO },
	{ _IFIFOAB2,  MOVE_DEST_CLASS2INFIFO },
	{ _PKA,       MOVE_DEST_PK_A },
	{ _KEY1,      MOVE_DEST_CLASS1KEY },
	{ _KEY2,      MOVE_DEST_CLASS2KEY },
/*14*/	{ _IFIFO,     MOVE_DEST_INFIFO },
/*15*/	{_ALTSOURCE,  MOVE_DEST_ALTSOURCE}
};

/* Allowed MOVE / MOVE_LEN destinations for each SEC Era.
 * Values represent the number of entries from move_dst_table[] that are
 * supported.
 */
static const uint32_t move_dst_table_sz[] = {13, 14, 14, 15, 15};

static inline int set_move_offset(struct program *program, uint64_t src,
				  uint16_t src_offset, uint64_t dst,
				  uint16_t dst_offset, uint16_t *offset,
				  uint16_t *opt);


static inline unsigned rta_move(struct program *program, uint64_t src,
				int type_src, uint16_t src_offset, uint64_t dst,
				int type_dst, uint16_t dst_offset,
				uint32_t length, int type_length,
				uint32_t flags)
{
	uint32_t opcode = 0, is_move_len_cmd = 0;
	uint16_t offset = 0, opt = 0;
	uint32_t val = 0;
	int ret = 0;
	unsigned start_pc = program->current_pc;

	/* write command type */
	if (type_length == REG_TYPE) {
		if (rta_sec_era < RTA_SEC_ERA_3) {
			pr_debug("MOVE: MOVE_LEN not supported by SEC Era %d. "
				 "SEC PC: %d; Instr: %d\n",
				 USER_SEC_ERA(rta_sec_era), program->current_pc,
				 program->current_instruction);
			goto err;
		}

		if ((length != _MATH0) && (length != _MATH1) &&
		    (length != _MATH2) && (length != _MATH3)) {
			pr_debug("MOVE: MOVE_LEN length must be MATH[0-3]. "
				 "SEC PC: %d; Instr: %d\n", program->current_pc,
				 program->current_instruction);
			goto err;
		}

		opcode = CMD_MOVE_LEN;
		is_move_len_cmd = 1;
	} else
		opcode = CMD_MOVE;

	/* write offset first, to check for invalid combinations or incorrect
	 * offset values sooner; decide which offset should be here
	 * (src or dst)
	 */
	ret = set_move_offset(program, src, (uint16_t) src_offset, dst,
			(uint16_t) dst_offset, &offset, &opt);
	if (ret)
		goto err;

	opcode |= (offset << MOVE_OFFSET_SHIFT) & MOVE_OFFSET_MASK;

	/* set AUX field if required */
	if (opt == MOVE_SET_AUX_SRC)
		opcode |= ((src_offset / 16) << MOVE_AUX_SHIFT) & MOVE_AUX_MASK;
	else if (opt == MOVE_SET_AUX_DST)
		opcode |= ((dst_offset / 16) << MOVE_AUX_SHIFT) & MOVE_AUX_MASK;
	else if (opt == MOVE_SET_AUX_LS)
		opcode |= MOVE_AUX_LS;

	/* write source field */
	ret = __rta_map_opcode(src, move_src_table,
			       move_src_table_sz[rta_sec_era], &val);
	if (ret == -1) {
		pr_debug("MOVE: Invalid SRC. SEC PC: %d; Instr: %d\n",
				program->current_pc,
				program->current_instruction);
		goto err;
	}
	opcode |= val;

	/* write destination field */
	ret = __rta_map_opcode(dst, move_dst_table,
			       move_dst_table_sz[rta_sec_era], &val);
	if (ret == -1) {
		pr_debug("MOVE: Invalid DST. SEC PC: %d; Instr: %d\n",
				program->current_pc,
				program->current_instruction);
		goto err;
	}
	opcode |= val;

	/* write flags */
	if (flags & (FLUSH1 | FLUSH2))
		opcode |= MOVE_AUX_MS;
	if (flags & (LAST2 | LAST1))
		opcode |= MOVE_AUX_LS;
	if (flags & WAITCOMP)
		opcode |= MOVE_WAITCOMP;

	if (!is_move_len_cmd) {
		/* write length */
		if (opt == MOVE_SET_LEN_16b)
			opcode |= (length & (MOVE_OFFSET_MASK | MOVE_LEN_MASK));
		else
			opcode |= (length & MOVE_LEN_MASK);
	} else {
		/* write mrsel */
		switch (length) {
		case (_MATH0):
			opcode |= MOVELEN_MRSEL_MATH0;
			break;
		case (_MATH1):
			opcode |= MOVELEN_MRSEL_MATH1;
			break;
		case (_MATH2):
			opcode |= MOVELEN_MRSEL_MATH2;
			break;
		case (_MATH3):
			opcode |= MOVELEN_MRSEL_MATH3;
			break;
		}
	}
	program->buffer[program->current_pc] = opcode;
	program->current_pc++;
	program->current_instruction++;

	return start_pc;

 err:
	program->first_error_pc = start_pc;
	program->current_instruction++;
	return start_pc;
}

static inline int set_move_offset(struct program *program, uint64_t src,
				  uint16_t src_offset, uint64_t dst,
				  uint16_t dst_offset, uint16_t *offset,
				  uint16_t *opt)
{
	switch (src) {
	case (_CONTEXT1):
	case (_CONTEXT2):
		if (dst == _DESCBUF) {
			*opt = MOVE_SET_AUX_SRC;
			*offset = dst_offset;
		} else if ((dst == _KEY1) || (dst == _KEY2)) {
			if ((src_offset) && (dst_offset)) {
				pr_debug("MOVE: Bad offset. SEC PC: %d; "
						"Instr: %d\n",
						program->current_pc,
						program->current_instruction);
				goto err;
			}
			if (dst_offset) {
				*opt = MOVE_SET_AUX_LS;
				*offset = dst_offset;
			} else
				*offset = src_offset;
		} else {
			if (((dst == _OFIFO) || (dst == _ALTSOURCE))
			    && (src_offset % 4)) {
				pr_debug("MOVE: Bad offset alignment. "
					"SEC PC: %d; Instr: %d\n",
					program->current_pc,
					program->current_instruction);
				goto err;
			}
			*offset = src_offset;
		}
		break;

	case (_OFIFO):
		if (dst == _OFIFO) {
			pr_debug("MOVE: Invalid DST. SEC PC: %d; Instr: %d\n",
					program->current_pc,
					program->current_instruction);
			goto err;
		}
		if (((dst == _IFIFOAB1) || (dst == _IFIFOAB2) || (dst == _IFIFO)
		     || (dst == _PKA))
		    && (src_offset || dst_offset)) {
			pr_debug("MOVE: Offset should be zero. SEC PC: %d; "
					"Instr: %d\n", program->current_pc,
					program->current_instruction);
			goto err;
		}
		*offset = dst_offset;
		break;

	case (_DESCBUF):
		if ((dst == _CONTEXT1) || (dst == _CONTEXT2)) {
			*opt = MOVE_SET_AUX_DST;
			*offset = src_offset;
		}
		if (dst == _DESCBUF) {
			pr_debug("MOVE: Invalid DST. SEC PC: %d; Instr: %d\n",
					program->current_pc,
					program->current_instruction);
			goto err;
		}
		if (((dst == _OFIFO) || (dst == _ALTSOURCE))
		    && (src_offset % 4)) {
			pr_debug("MOVE: Invalid offset alignment. SEC PC: %d; "
					"Instr %d\n", program->current_pc,
					program->current_instruction);
			goto err;
		}
		*offset = src_offset;
		break;

	case (_MATH0):
	case (_MATH1):
	case (_MATH2):
	case (_MATH3):
		if ((dst == _OFIFO) || (dst == _ALTSOURCE)) {
			if (src_offset % 4) {
				pr_debug("MOVE: Bad offset alignment. "
						"SEC PC: %d; Instr: %d\n",
						program->current_pc,
						program->current_instruction);
				goto err;
			}
			*offset = src_offset;
		} else if ((dst == _IFIFOAB1) || (dst == _IFIFOAB2)
			   || (dst == _IFIFO) || (dst == _PKA))
			*offset = src_offset;
		else
			*offset = dst_offset;
		break;

	case (_IFIFOABD):
	case (_IFIFOAB1):
	case (_IFIFOAB2):
	case (_ABD):
	case (_AB1):
	case (_AB2):
		if ((dst == _IFIFOAB1) || (dst == _IFIFOAB2) || (dst == _IFIFO)
		    || (dst == _PKA) || (dst == _ALTSOURCE)) {
			pr_debug("MOVE: Bad DST. SEC PC: %d; Instr: %d\n",
					program->current_pc,
					program->current_instruction);
			goto err;
		} else if (dst == _OFIFO)
			*opt = MOVE_SET_LEN_16b;
		else {
			if (dst_offset % 4) {
				pr_debug("MOVE: Bad offset alignment. "
						"SEC PC: %d; Instr: %d\n",
						program->current_pc,
						program->current_instruction);
				goto err;
			}
			*offset = dst_offset;
		}
		break;
	default:
		break;
	}

	return 0;
 err:
	return -1;
}

#endif /* __RTA_MOVE_CMD_H__ */
