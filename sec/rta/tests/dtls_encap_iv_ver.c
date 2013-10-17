/* Copyright 2008-2013 Freescale Semiconductor, Inc. */

#include <stdio.h>
#include "flib/rta.h"
#include "test_common.h"

enum rta_sec_era rta_sec_era;

const uint8_t key1[16] = {
	0x1d, 0xc9, 0xef, 0x2f, 0x7d, 0xa3, 0x3b, 0xd6,
	0x42, 0xa4, 0x61, 0xef, 0x5b, 0x10, 0x48, 0x73
};

const uint8_t key2[48] = {
	0x5c, 0x9b, 0x69, 0xe0, 0x6f, 0x07, 0xa9, 0xcc,
	0xa4, 0xc0, 0xd3, 0x16, 0xce, 0x46, 0x06, 0x96,
	0x2a, 0xf7, 0x77, 0xfd, 0x43, 0x82, 0x68, 0x4f,
	0xaa, 0x1f, 0xf7, 0x53, 0xba, 0x1c, 0xcc, 0x74,
	0x75, 0xa0, 0x71, 0xf3, 0x99, 0x41, 0x28, 0xe7,
	0x98, 0x46, 0x25, 0x52, 0x2b, 0x9e, 0xd6, 0xd9
};


/*
 * Function to generate a Shared Descriptor for DTLS encap, with metadata and
 * verification that IV is not used twice in a rwo.
 */
int build_dtls_sharedesc(uint32_t *buff, uint32_t seqnum,
			 const uint8_t *aes_key, const uint8_t *hmac_key,
			 uint32_t mdatalen, uint32_t cipher_alg)
{
	struct program prg;
	struct program *program = &prg;
	int size;
	int word_size = sizeof(uint32_t);

	LABEL(encap_iv);
	LABEL(previous_iv);
	LABEL(seqoutptr);
	REFERENCE(pmove1);
	REFERENCE(pmove2);
	REFERENCE(pmove3);
	REFERENCE(pmove4);
	LABEL(new_seqinptr);
	REFERENCE(pjump1);
	LABEL(skip_keyloading);
	REFERENCE(pjump2);
	LABEL(new_IV_OK);

	PROGRAM_CNTXT_INIT(buff, 0);
	SHR_HDR(SHR_SERIAL, 12, 0);
	{
		{	/* Custom DTLS Encap AES-CBC */
			WORD(0x017feff00); /* type 0x17 / protocol version */
			WORD(0x00010000); /* Epoch / upper bits of SeqNum */
			WORD(seqnum); /* Lower bits of SeqNum */

			SET_LABEL(encap_iv);
			SET_LABEL(previous_iv);
			/* Location of the extra, custom part of PDB */
			previous_iv += 4;
			/* All of the IV, both next and previous */
			DWORD(0x0000000000000000);
			DWORD(0x0000000000000000);
			DWORD(0x0000000000000000);
			DWORD(0x0000000000000000);
		}
		/*
		 * s1: Copy SEQ-OUT-PTR cmd from Job Descriptor
		 *     mask to turn the SEQ-OUT-PTR cmd into a SEQ-IN-PTR cmd
		 *     put new SEQ-IN-PTR command in-line in shared descriptor
		 */
		pmove1 = MOVE(DESCBUF, seqoutptr, MATH0, 0, IMM(16),
			      WITH(WAITCOMP));
		MATHB(MATH0, XOR, IMM(0x0840010000000000), MATH0, 8, 0);
		/*(8 needs to be 12 if 64-bit pointers are being used */
		pmove2 = MOVE(MATH0, 0, DESCBUF, new_seqinptr, IMM(8), 0);
		/*
		 * s2: Customer has defined that every packet has 46 bytes of
		 *     what we call metadata -- data that we are to pass
		 *     unadulterated from input frame to output frame
		 */
		SEQFIFOLOAD(IFIFO, mdatalen, 0);
		MOVE(IFIFOABD, 0, OFIFO, 0, IMM(mdatalen), 0);
		SEQFIFOSTORE(MSG, 0, mdatalen, 0);
		/* s3: Skip key commands when sharing permits */
		pjump1 = JUMP(IMM(skip_keyloading), LOCAL_JUMP, ALL_TRUE,
			      WITH(SHRD));
		KEY(MDHA_SPLIT_KEY, ENC, PTR((intptr_t) hmac_key), 40,
		    WITH(IMMED));

		/* load DTLS HMAC authentication key */
		KEY(KEY1, 0, PTR((intptr_t) aes_key), 16, WITH(IMMED));
		/* load DTLS AES confidentiality key */
		SET_LABEL(skip_keyloading);
		/* s4: Execute DTLS protocol thread */
		PROTOCOL(OP_TYPE_ENCAP_PROTOCOL, OP_PCLID_DTLS10,
			 WITH(cipher_alg));
		SET_LABEL(new_seqinptr);
		/* s5: These 3 words reserved for a new SEQ-IN-PTR cmd to
		 * set up to */
		WORD(0x00000000);
		WORD(0x00000000);
		/* Reread the IV that was written out by the DTLS protocol
		 * thread */
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, 0);

		/*
		 * s6: Skip the "metadata" and the DTLS header material
		 *     set input ptr to IV
		 *     Load IV from output frame into math2/math3 */
		SEQFIFOLOAD(SKIP, 59, 0);
		SEQLOAD(MATH2, 0, 16, 0);
		/* Load last frame's output IV into math0/math1 */
		pmove3 = MOVE(DESCBUF, previous_iv, MATH0, 0, IMM(16),
			      WITH(WAITCOMP));
		/* Wait for loads to complete */
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
		/* Compare upper half of two IVs */
		MATHB(MATH0, XOR, MATH2, NONE, 8, 0);
		/* If two upper halves are different, then zero is not set and
		 * jump to */
		pjump2 = JUMP(IMM(new_IV_OK), LOCAL_JUMP, ANY_FALSE,
			      WITH(MATH_Z));
		/* Compare lower half of two IVs */
		MATHB(MATH1, XOR, MATH3, NONE, 8, 0);
		/*
		 * If we got here with zero set, then both halves were
		 * identical --this is an ERROR
		 */
		JUMP(IMM(255), HALT_STATUS, ALL_TRUE, WITH(MATH_Z));
		SET_LABEL(new_IV_OK);
		/*
		 * s7: Store back both IVs; math2/3 for next compare; math0/1
		 * for software to check if need be
		 */
		pmove4 = MOVE(MATH0, 0, DESCBUF, encap_iv, IMM(32), 0);
		/* Store back both IVs to the shared descriptor in system
		 * memory */
		STORE(SHAREDESCBUF, 4 * word_size, NONE, 8 * word_size, 0);
		/*
		 * Get past JOB HEADER and init ptr (needs to be 12 for 64-bit
		 * pointers). (There could be 'magic labels' for use by Shared
		 * Descriptors that are going to be used in QI, so that they
		 * can reference various parts of the Job Descriptor: Header,
		 * seq out ptr, the ptr, the ext length, same series for the
		 * seq in ptr, etc.)
		 */
		SET_LABEL(seqoutptr);
		seqoutptr += 2;
	}
	PATCH_MOVE(pmove1, seqoutptr);
	PATCH_MOVE(pmove2, new_seqinptr);
	PATCH_MOVE(pmove4, encap_iv);
	PATCH_JUMP(pjump1, skip_keyloading);
	PATCH_MOVE(pmove3, previous_iv);
	PATCH_JUMP(pjump2, new_IV_OK);

	size = PROGRAM_FINALIZE();
	return size;
}

int prg_buff[1000];

int main(int argc, char **argv)
{
	uint32_t seqnum = 0x179;
	int size;

	pr_debug("DTLS example program\n");
	rta_set_sec_era(RTA_SEC_ERA_3);
	size = build_dtls_sharedesc((uint32_t *) prg_buff, seqnum, key1, key2,
				    46, 0xff80);
	pr_debug("size = %d\n", size);
	print_prog((uint32_t *) prg_buff, size);

	return 0;
}
