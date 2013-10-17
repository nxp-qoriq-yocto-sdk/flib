/* Copyright 2008-2013 Freescale Semiconductor, Inc. */

#include <stdio.h>
#include "flib/rta.h"
#include "test_common.h"

enum rta_sec_era rta_sec_era;

int test_jump(uint32_t *buff)
{
	struct program prg;
	struct program *program = &prg;
	int size;
	char test_data_char[13] = "My Imm Data\n";
	uint32_t test_data = (uint32_t) &test_data_char;

	LABEL(test1);
	REFERENCE(ptest1);
	LABEL(test2);
	REFERENCE(ptest2);

	PROGRAM_CNTXT_INIT(buff, 0);
	{
		SHR_HDR(SHR_ALWAYS, 0, 0);
		ptest1 = JUMP(IMM(test1), LOCAL_JUMP, ALL_TRUE, 0);
		MATHB(MATH0, XOR, IMM(0x0840010008880000), MATH3, SIZE(8), 0);
		MATHB(IMM(0x08400100009990), XOR, MATH1, MATH3, SIZE(8), 0);
		SET_LABEL(test1);
		MATHB(IMM(0x0840010000aaa0), XOR, MATH1, MATH3, SIZE(8), 0);
		SET_LABEL(test2);
		MATHB(MATH2, XOR, MATH1, MATH3, 4, 0);
		MATHU(MATH2, BSWAP, MATH3, 2, WITH(NFU));
		ptest2 = JUMP(IMM(test2), LOCAL_JUMP, ALL_TRUE, 0);
		MATHU(MATH0, BSWAP, MATH1, 8, 0);
		LOAD(IMM(test_data), CONTEXT2, 0, 8, 0);

		PATCH_JUMP(ptest1, test1);
		PATCH_JUMP(ptest2, test2);

		size = PROGRAM_FINALIZE();
	}
	return size;
}

int prg_buff[1000];

int main(int argc, char **argv)
{
	int size;

	pr_debug("JUMP program\n");
	rta_set_sec_era(RTA_SEC_ERA_4);
	size = test_jump((uint32_t *) prg_buff);
	pr_debug("size = %d\n", size);
	print_prog((uint32_t *) prg_buff, size);

	return 0;
}
