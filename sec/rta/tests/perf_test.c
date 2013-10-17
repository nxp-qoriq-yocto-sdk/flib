/* Copyright 2008-2013 Freescale Semiconductor, Inc. */

#include <stdio.h>
#include "flib/rta.h"
#include "test_common.h"

enum rta_sec_era rta_sec_era;

int test_perf(uint32_t *buff)
{
	struct program prg;
	struct program *program = &prg;
	int size;
	int seqnum = 1;

	PROGRAM_CNTXT_INIT(buff, 0);
	LABEL(test1);
	LABEL(test2);
	LABEL(encap_iv);
	LABEL(seqoutptr);
	LABEL(new_seqinptr);

	{
		SHR_HDR(SHR_ALWAYS, 0, 0);
		WORD(0x17feff00);	/* type 0x17 / protocol version */
		WORD(0x00010000);	/* Epoch / upper bits of SeqNum */
		WORD(seqnum);	/* Lower bits of SeqNum */

		JUMP(IMM(test1), LOCAL_JUMP, ALL_TRUE, 0);
		MATHB(MATH0, ADD, IMM(0x0840010008880000), MATH3, SIZE(8), 0);
		MATHB(IMM(0x08400100009990), XOR, MATH1, MATH3, SIZE(8), 0);
		SET_LABEL(test1);
		MATHB(IMM(0x0840010000aaa0), XOR, MATH1, MATH3, SIZE(8), 0);
		SET_LABEL(test2);
		MATHB(MATH2, XOR, MATH1, MATH3, 4, 0);
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));
		JUMP(IMM(test2), LOCAL_JUMP, ALL_TRUE, 0);
		MATHU(MATH0, BSWAP, MATH1, 8, 0);
		/* SYNC (NO_PEND_INPUT); */

		LOAD(IMM(4), ICV1SZ, 0, 4, 0);
		LOAD(IMM(4), ICV2SZ, 0, 4, 0);
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));
		MATHB(IMM(0x0840010000aaa0), XOR, MATH1, MATH3, SIZE(8), 0);
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));
		WORD(0x17feff00);	/* type 0x17 / protocol version */
		WORD(0x00010000);	/* Epoch / upper bits of SeqNum */
		WORD(seqnum);	/* Lower bits of SeqNum */
		JUMP(IMM(test1), LOCAL_JUMP, ALL_TRUE, 0);
		MATHB(MATH0, XOR, IMM(0x0840010008880000), MATH3, SIZE(8), 0);
		MATHB(IMM(0x08400100009990), XOR, MATH1, MATH3, SIZE(8), 0);
		MATHB(IMM(0x0840010000aaa0), XOR, MATH1, MATH3, SIZE(8), 0);
		MATHB(MATH2, XOR, MATH1, MATH3, 4, 0);
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));
		JUMP(IMM(test2), LOCAL_JUMP, ALL_TRUE, 0);
		MATHU(MATH0, BSWAP, MATH1, 8, 0);
		/* SYNC (NO_PEND_INPUT); */
		LOAD(IMM(4), ICV2SZ, 0, 4, 0);
		LOAD(IMM(4), ICV1SZ, 0, 4, 0);
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));
		MATHB(IMM(0x0840010000aaa0), XOR, MATH1, MATH3, SIZE(8), 0);
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));

		SET_LABEL(encap_iv);
		/* All of the IV, both next and previous */
		ENDIAN_DATA(((uint8_t[]) { 00, 00}), 2);

		MOVE(DESCBUF, seqoutptr, MATH0, 0, IMM(16), WITH(WAITCOMP));
		MATHB(MATH0, XOR, IMM(0x0840010000000000), MATH0, 8, 0);
		MOVE(MATH0, 0, DESCBUF, new_seqinptr, IMM(8), 0);
		SET_LABEL(new_seqinptr);
		WORD(0x0);
		WORD(0x0);
		/* NOP(); */
		SEQLOAD(MATH2, 0, 8, 0);
		/* JUMP_COND(all[calm], ADD1); */
		MATHB(MATH0, XOR, MATH2, NONE, 8, 0);
		MATHB(MATH1, XOR, MATH3, NONE, 8, 0);
		/* HALT_COND(all[z], 255); */
		MOVE(MATH0, 0, DESCBUF, encap_iv, IMM(32), 0);
		seqoutptr = 8;

		size = PROGRAM_FINALIZE();
	}
	return size;
}

int prg_buff[1000];

int main(int argc, char **argv)
{
	int size;

	pr_debug("Perf example program\n");
	rta_set_sec_era(RTA_SEC_ERA_4);
	size = test_perf((uint32_t *) prg_buff);
	pr_debug("size = %d\n", size);
	print_prog((uint32_t *) prg_buff, size);

	return 0;
}
