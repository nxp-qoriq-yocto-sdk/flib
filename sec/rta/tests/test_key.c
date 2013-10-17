/* Copyright 2008-2013 Freescale Semiconductor, Inc. */

#include <stdio.h>
#include "flib/rta.h"
#include "test_common.h"

enum rta_sec_era rta_sec_era;

int test_key_op(uint32_t *buff)
{
	struct program prg;
	struct program *program = &prg;
	int size;
	uint8_t key_imm[] = { 0x12, 0x13, 0x14, 0x15 };
	uintptr_t addr = (uintptr_t) &key_imm;

	PROGRAM_CNTXT_INIT(buff, 0);
	KEY(MDHA_SPLIT_KEY, WITH(ENC), IMM(addr), 4, 0);
	KEY(MDHA_SPLIT_KEY, WITH(ENC), PTR(addr), 4, 0);
	KEY(KEY1, WITH(EKT), IMM(addr), 4, 0);

	size = PROGRAM_FINALIZE();
	return size;
}

int prg_buff[1000];

int main(int argc, char **argv)
{
	int size;

	pr_debug("KEY program\n");
	rta_set_sec_era(RTA_SEC_ERA_2);
	size = test_key_op((uint32_t *) prg_buff);
	pr_debug("size = %d\n", size);
	print_prog((uint32_t *) prg_buff, size);

	return 0;
}
