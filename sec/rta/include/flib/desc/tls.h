/*
 * Copyright 2008-2013 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause or GPL-2.0+
 */

#ifndef __DESC_TLS_H__
#define __DESC_TLS_H__

#include "flib/rta.h"
#include "common.h"

/**
 * DOC: SSL/TLS/DTLS Shared Descriptor Constructors
 *
 * Shared descriptors for SSL / TLS and DTLS protocols.
 */

/*
 * Lengths of shared descriptors - bytes consumed by the commands, excluding
 * the data items to be inlined (or corresponding pointer if an item is not
 * inlined). These descriptor lengths can be used with rta_inline_query() to
 * provide indications on which data items can be inlined and which shall be
 * referenced in a shared descriptor.
 */
#define DESC_TLS_BASE			(4 * CAAM_CMD_SZ)
/* TLS decapsulation descriptor does not have enough space for inlined keys */
#define DESC_TLS10_ENC_LEN		(DESC_TLS_BASE + 29 * CAAM_CMD_SZ)

/*
 * TLS family encapsulation/decapsulation PDB definitions.
 */

#define DTLS_PDBOPTS_ARS32	0x40	/* DTLS only */
#define DTLS_PDBOPTS_ARS64	0xc0	/* DTLS only */
#define TLS_PDBOPTS_OUTFMT	0x08
#define TLS_PDBOPTS_IV_WRTBK	0x02	/* TLS1.1/TLS1.2/DTLS only */
#define TLS_PDBOPTS_EXP_RND_IV	0x01	/* TLS1.1/TLS1.2/DTLS only */
#define TLS_PDBOPTS_TR_ICV	0x10	/* Available starting with SEC ERA 5 */

/**
 * struct tls_block_enc - SSL3.0/TLS1.0/TLS1.1/TLS1.2 block encapsulation PDB
 *                        part.
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls_block_enc {
	uint8_t type;
	uint8_t version[2];
	uint8_t options;
	uint32_t seq_num[2];
};

/**
 * struct dtls_block_enc - DTLS1.0 block encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
struct dtls_block_enc {
	uint8_t type;
	uint8_t version[2];
	uint8_t options;
	uint16_t epoch;
	uint16_t seq_num[3];
};

/**
 * struct tls_block_dec - SSL3.0/TLS1.0/TLS1.1/TLS1.2 block decapsulation PDB
 *                        part.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls_block_dec {
	uint8_t rsvd[3];
	uint8_t options;
	uint32_t seq_num[2];
};

/**
 * struct dtls_block_dec - DTLS1.0 block decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
struct dtls_block_dec {
	uint8_t rsvd[3];
	uint8_t options;
	uint16_t epoch;
	uint16_t seq_num[3];
};

/**
 * struct tls_block_pdb - SSL3.0/TLS1.0/TLS1.1/TLS1.2/DTLS1.0 block
 *                        encapsulation / decapsulation PDB.
 * @iv: initialization vector
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options byte.
 *             If SEC ERA is equal or greater than SEC ERA 5 and
 *             TLS_PDBOPTS_TR_ICV is set in the PDB Options Byte, it expands for
 *             ICVLen.
 */
struct tls_block_pdb {
	union {
		struct tls_block_enc tls_enc;
		struct dtls_block_enc dtls_enc;
		struct tls_block_dec tls_dec;
		struct dtls_block_dec dtls_dec;
	};
	uint32_t iv[4];
	uint32_t end_index[0];
};

/**
 * struct tls_stream_enc - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream encapsulation PDB
 *                         part.
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 */
struct tls_stream_enc {
	uint8_t type;
	uint8_t version[2];
	uint8_t options;
};

/**
 * struct tls_stream_dec - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream decapsulation PDB
 *                         part.
 * @rsvd: reserved, do not use
 * @options: PDB options
 */
struct tls_stream_dec {
	uint8_t rsvd[3];
	uint8_t options;
};

/**
 * struct tls_stream_pdb - SSL3.0/TLS1.0/TLS1.1/TLS1.2 stream
 *                         encapsulation / decapsulation PDB.
 * @seq_num: protocol sequence number
 * @end_index: the zero-length array expands for ICVLen if SEC ERA is equal or
 *             greater than SEC ERA 5 and TLS_PDBOPTS_TR_ICV is set in the PDB
 *             Options Byte.
 */
struct tls_stream_pdb {
	union {
		struct tls_stream_enc enc;
		struct tls_stream_dec dec;
	};
	uint32_t seq_num[2];
	uint32_t end_index[0];
};

/**
 * struct tls_ctr_enc - TLS1.1/TLS1.2 AES CTR encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls_ctr_enc {
	uint8_t type;
	uint8_t version[2];
	uint8_t options;
	uint32_t seq_num[2];
};

/**
 * struct tls_ctr - PDB part for TLS1.1/TLS1.2 AES CTR decapsulation and
 *                  DTLS1.0 AES CTR encapsulation/decapsulation.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
struct tls_ctr {
	uint8_t rsvd[3];
	uint8_t options;
	uint16_t epoch;
	uint16_t seq_num[3];
};

/**
 * struct tls_ctr_pdb - TLS1.1/TLS1.2/DTLS1.0 AES CTR
 *                      encapsulation / decapsulation PDB.
 * @write_iv: server write IV / client write IV
 * @constant: constant equal to 0x0000
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options Byte.
 *             If TLS_PDBOPTS_TR_ICV is set in the PDB Option Byte, it expands
 *             for ICVLen.
 *
 * TLS1.1/TLS1.2/DTLS1.0 AES CTR encryption processing is supported starting
 * with SEC ERA 5.
 */
struct tls_ctr_pdb {
	union {
		struct tls_ctr_enc tls_enc;
		struct tls_ctr ctr;
	};
	uint16_t write_iv[3];
	uint16_t constant;
	uint32_t end_index[0];
};

/**
 * struct tls12_gcm_encap - TLS1.2 AES GCM encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls12_gcm_encap {
	uint8_t type;
	uint8_t version[2];
	uint8_t options;
	uint32_t seq_num[2];
};

/**
 * struct tls12_gcm_decap - TLS1.2 AES GCM decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls12_gcm_decap {
	uint8_t rsvd[3];
	uint8_t options;
	uint32_t seq_num[2];
};

/**
 * struct dtls_gcm - DTLS1.0 AES GCM encapsulation / decapsulation PDB part
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
struct dtls_gcm {
	uint8_t rsvd[3];
	uint8_t options;
	uint16_t epoch;
	uint16_t seq_num[3];
};

/**
 * struct tls_gcm_pdb - TLS1.2/DTLS1.0 AES GCM encapsulation / decapsulation PDB
 * @salt: 4-byte salt
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options byte.
 *             If SEC ERA is equal or greater than SEC ERA 5 and
 *             TLS_PDBOPTS_TR_ICV is set in the PDB Option Byte, it expands for
 *             ICVLen.
 */
struct tls_gcm_pdb {
	union {
		struct tls12_gcm_encap tls12_enc;
		struct tls12_gcm_decap tls12_dec;
		struct dtls_gcm dtls;
	};
	uint32_t salt;
	uint32_t end_index[0];
};

/**
 * struct tls12_ccm_encap - TLS1.2 AES CCM encapsulation PDB part
 * @type: protocol content type
 * @version: protocol version
 * @options: PDB options
 * @seq_num: protocol sequence number
 */
struct tls12_ccm_encap {
	uint8_t type;
	uint8_t version[2];
	uint8_t options;
	uint32_t seq_num[2];
};

/**
 * struct tls_ccm - PDB part for TLS12 AES CCM decapsulation PDB and
 *                  DTLS1.0 AES CCM encapsulation / decapsulation.
 * @rsvd: reserved, do not use
 * @options: PDB options
 * @epoch: protocol epoch
 * @seq_num: protocol sequence number
 */
struct tls_ccm {
	uint8_t rsvd[3];
	uint8_t options;
	uint16_t epoch;
	uint16_t seq_num[3];
};

/**
 * struct tls_ccm_pdb - TLS1.2/DTLS1.0 AES CCM encapsulation / decapsulation PDB
 * @write_iv: server write IV / client write IV
 * @b0_flags: use 0x5A for 8-byte ICV, 0x7A for 16-byte ICV
 * @ctr0_flags: equal to 0x2
 * @rsvd: reserved, do not use
 * @ctr0: CR0 lower 3 bytes, set to 0
 * @end_index: the zero-length array expands with one/two words for the
 *             Anti-Replay Scorecard if DTLS_PDBOPTS_ARS32/64 is set in the
 *             DTLS1.0 decapsulation PDB Options byte.
 *             If SEC ERA is equal or greater than SEC ERA 5 and
 *             TLS_PDBOPTS_TR_ICV is set in the PDB Option Byte, it expands for
 *             ICVLen.
 */
struct tls_ccm_pdb {
	union {
		struct tls12_ccm_encap tls12;
		struct tls_ccm ccm;
	};
	uint32_t write_iv;
	uint8_t b0_flags;
	uint8_t ctr0_flags;
	uint8_t rsvd[3];
	uint8_t ctr0[3];
	uint32_t end_index[0];
};

/**
 * cnstr_shdsc_tls - TLS family block cipher encapsulation / decapsulation
 *                   shared descriptor.
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @pdb: pointer to the PDB to be used in this descriptor
 *       This structure will be copied inline to the descriptor under
 *       construction. No error checking will be made. Refer to the block guide
 *       for details of the PDB.
 * @pdb_len: the length of the Protocol Data Block in bytes
 * @protcmd: pointer to Protocol Operation Command definitions
 * @cipherdata: pointer to block cipher transform definitions
 * @authdata: pointer to authentication transform definitions
 *
 * Return: size of descriptor written in words or negative number on error
 *
 * The following built-in protocols are supported:
 * SSL3.0 / TLS1.0 / TLS1.1 / TLS1.2 / DTLS10
 */
static inline int cnstr_shdsc_tls(uint32_t *descbuf, bool ps, uint8_t *pdb,
				  unsigned pdb_len, struct protcmd *protcmd,
				  struct alginfo *cipherdata,
				  struct alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;
	unsigned startidx;

	LABEL(keyjmp);
	REFERENCE(pkeyjmp);

	startidx = pdb_len >> 2;
	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	SHR_HDR(p, SHR_SERIAL, ++startidx, 0);
	COPY_DATA(p, pdb, pdb_len);
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, BOTH|SHRD|SELF);
	/*
	 * SSL3.0 uses SSL-MAC (SMAC) instead of HMAC, thus MDHA Split Key
	 * does not apply.
	 */
	if (protcmd->protid == OP_PCLID_SSL30)
		KEY(p, KEY2, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, INLINE_KEY(authdata));
	else
		KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, INLINE_KEY(authdata));
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjmp);
	PROTOCOL(p, protcmd->optype, protcmd->protid, protcmd->protinfo);

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_tls10_enc - stateless tls10 encapsulation shared descriptor
 * This descriptor is valid on platforms with 36/40-bit address pointers.
 * Supported cipher suites: AES_128_CBC_SHA, AES_256_CBC_SHA, 3DES_EDE_CBC_SHA.
 *
 * Encapsulation input frame format:
 * +-------+------+-------+--------------+---+-------+
 * |SeqNum | Type |Version|Len (pre ICV) |IV |Payload|
 * |8 bytes|1 byte|2 bytes|   2 bytes    |   |       |
 * +-------+------+-------+--------------+---+-------+
 *
 * Authentication processing:
 * +-------+------+-------+--------------+---+-------+
 * |SeqNum | Type |Version|Len (pre ICV) |IV |Payload|
 * |8 bytes|1 byte|2 bytes|   2 bytes    |   |       |
 * +-------+------+-------+--------------+---+-------+
 * |                  Authenticate       | * |       |
 * +-------------------------------------+---+-------+
 * (*IV) is not authenticated.
 *
 * Encryption processing for block cipher suites:
 *                                           +------ +----+----------+--------+
 *                                           |Payload|ICV |Padding   |Pad Len |
 *                                           |       |    |0-15 bytes| 1 byte |
 *                                           +-------+----+----------+--------+
 *                                           |             Encrypt            |
 *                                           +--------------------------------+
 *
 * Encapsulation output frame format:
 *                                           +--------------------------------+
 *                                           |            Encrypted           |
 *                                           +------ +----+----------+--------+
 *                                           |Payload|ICV |Padding   |Pad Len |
 *                                           |       |    |0-15 bytes| 1 byte |
 *                                           +-------+----+----------+--------+
 *
 * @descbuf: pointer to buffer used for descriptor construction
 * @blocksize: cipher block size in bytes. Block cipher IVs are matching the
 * cipher's block size.
 * @authsize: byte size of integrity check value. Only full ICVs were tested.
 * @cipherdata: pointer to block cipher transform definitions
 * Valid cipherdata->algtype values: OP_ALG_ALGSEL_AES, OP_ALG_ALGSEL_DES.
 * @authdata: pointer to authentication transform definitions
 * A MDHA split key must be provided.
 * Valid authdata->algtype values: OP_ALG_ALGSEL_SHA1.
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int cnstr_shdsc_tls10_enc(uint32_t *descbuf,
	unsigned int blocksize, unsigned int authsize,
	struct alginfo *cipherdata, struct alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;
	/* Associated data length is always = 13 for TLS */
	unsigned int assoclen = 13;
	uint32_t genpad;

	LABEL(keyjmp);
	LABEL(ld_datasz);
	LABEL(nfifo);
	LABEL(no_payload);
	LABEL(jmp);
	REFERENCE(pkeyjmp);
	REFERENCE(read_ld_datasz);
	REFERENCE(write_ld_datasz);
	REFERENCE(read_nfifo);
	REFERENCE(write_nfifo);
	REFERENCE(no_payload_jmp);
	REFERENCE(jmp_cmd);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	PROGRAM_SET_36BIT_ADDR(p);
	SHR_HDR(p, SHR_SERIAL, 1, 0);

	/* skip key loading if they are loaded due to sharing */
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);
	KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags, authdata->key,
	    authdata->keylen, INLINE_KEY(authdata));
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjmp);

	/* class 2 operation */
	ALG_OPERATION(p, authdata->algtype , OP_ALG_AAI_HMAC_PRECOMP,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_ENC);
	/* class 1 operation */
	ALG_OPERATION(p, cipherdata->algtype, OP_ALG_AAI_CBC,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_ENC);

	/* payloadlen = input data length - (assoclen + ivlen) */
	MATHB(p, SEQINSZ, SUB, assoclen + blocksize, MATH0, 4, IMMED2);

	/* math1 = payloadlen + icvlen */
	MATHB(p, MATH0, ADD, authsize, MATH1, 4, IMMED2);

	/* padlen = block_size - math1 % block_size */
	MATHB(p, MATH1, AND, (blocksize - 1), MATH3, 4, IMMED2);
	MATHB(p, blocksize, SUB, MATH3, MATH2, 4, IMMED);

	/* cryptlen = payloadlen + icvlen + padlen */
	MATHB(p, MATH1, ADD, MATH2, VSEQOUTSZ, 4, 0);

	/*
	 * update immediate data with the padding length value
	 * for the LOAD in the class 1 data size register.
	 */
	read_ld_datasz = MOVE(p, DESCBUF, 0, MATH2, 0, 7, IMMED);
	write_ld_datasz = MOVE(p, MATH2, 0, DESCBUF, 0, 8, WAITCOMP | IMMED);

	/* overwrite PL field for the padding iNFO FIFO entry  */
	read_nfifo = MOVE(p, DESCBUF, 0, MATH2, 0, 7, IMMED);
	write_nfifo = MOVE(p, MATH2, 0, DESCBUF, 0, 8, WAITCOMP | IMMED);

	/* store encrypted payload, icv and padding */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/* if payload length is zero, jump to zero-payload commands */
	MATHB(p, ZERO, ADD, MATH0, VSEQINSZ, 4, 0);
	no_payload_jmp = JUMP(p, no_payload, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	/* read assoc for authentication */
	SEQFIFOLOAD(p, MSG2, assoclen, 0);

	/* load iv in context1 */
	SEQLOAD(p, CONTEXT1, 0, blocksize, 0);

	/* insnoop payload */
	SEQFIFOLOAD(p, MSGINSNOOP, 0, LAST2 | VLF);

	/* jump the zero-payload commands */
	jmp_cmd = JUMP(p, jmp, LOCAL_JUMP, ALL_TRUE, 0);

	/* zero-payload commands */
	SET_LABEL(p, no_payload);

	/* assoc data is the only data for authentication */
	SEQFIFOLOAD(p, MSG2, assoclen, LAST2);

	/* load iv in context1 */
	SEQLOAD(p, CONTEXT1, 0, blocksize, 0);

	SET_LABEL(p, jmp);
	/* send icv to encryption */
	MOVE(p, CONTEXT2, 0, IFIFOAB1, 0, authsize, IMMED);

	/* update class 1 data size register with padding length */
	SET_LABEL(p, ld_datasz);
	LOAD(p, 0, DATA1SZ, 0, 4, IMMED);

	/* generate padding and send it to encryption */
	SET_LABEL(p, nfifo);
	genpad = NFIFOENTRY_DEST_CLASS1 | NFIFOENTRY_LC1 | NFIFOENTRY_FC1 |
	      NFIFOENTRY_STYPE_PAD | NFIFOENTRY_DTYPE_MSG | NFIFOENTRY_PTYPE_N;
	LOAD(p, genpad, NFIFO, 0, 4, IMMED);

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_JUMP(p, no_payload_jmp, no_payload);
	PATCH_JUMP(p, jmp_cmd, jmp);
	PATCH_MOVE(p, read_ld_datasz, ld_datasz);
	PATCH_MOVE(p, write_ld_datasz, ld_datasz);
	PATCH_MOVE(p, read_nfifo, nfifo);
	PATCH_MOVE(p, write_nfifo, nfifo);

	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_tls10_dec - stateless tls10 decapsulation shared descriptor
 * This descriptor is valid on platforms with 36/40-bit address pointers.
 * Supported cipher suites: AES_128_CBC_SHA, AES_256_CBC_SHA, 3DES_EDE_CBC_SHA.
 *
 * Decapsulation input frame format:
 *                                           +--------------------------------+
 *                                           |           Encrypted            |
 * +-------+------+-------+--------------+---+-------+----+----------+--------+
 * |SeqNum | Type |Version|Len (full rec)|IV |Payload|ICV |Padding   |Pad Len |
 * |8 bytes|1 byte|2 bytes|   2 bytes    |   |       |    |0-15 bytes| 1 byte |
 * +-------+------+-------+--------------+---+-------+----+----------+--------+
 *
 * Block Cipher decryption pre precessing (pre-decrypt Pad Len for
 * Block Cipher suites):
 *                                +------------------+----+----------+--------+
 *                                |  End of Payload  |ICV |Padding   |Pad Len |
 *                                |                  |    |0-15 bytes| 1 byte |
 *                                +------------------+----+----------+--------+
 *                                |      Use as IV      |       Decrypt       |
 *                                |     (one block)     |     (one block)     |
 *                                +---------------------+---------------------+
 *
 * Decryption processing for block cipher suites:
 * +-------+------+-------+--------------+---+-------+----+----------+--------+
 * |SeqNum | Type |Version|Len (full rec)|IV |Payload|ICV |Padding   |Pad Len |
 * |8 bytes|1 byte|2 bytes|   2 bytes    |   |       |    |0-15 bytes| 1 byte |
 * +-------+------+-------+--------------+---+-------+----+----------+--------+
 *                                           |            Decrypt             |
 *                                           +--------------------------------+
 *
 * Authentication processing:
 * +-------+------+-------+--------------+---+-------+----+----------+--------+
 * |SeqNum | Type |Version|Len (pre ICV) |IV |Payload|ICV |Padding   |Pad Len |
 * |8 bytes|1 byte|2 bytes|   2 bytes    |   |       |    |0-15 bytes| 1 byte |
 * +-------+------+-------+--------------+---+-------+----+----------+--------+
 * |               Authenticate          | * |       |
 * +-------------------------------------+---+-------+
 * (*IV) is not authenticated.
 *
 * Decapsulation output frame format:
 *                                           +------ +----+----------+--------+
 *                                           |Payload|ICV |Padding   |Pad Len |
 *                                           |       |    |0-15 bytes| 1 byte |
 *                                           +-------+----+----------+--------+
 *
 * @descbuf: pointer to buffer used for descriptor construction
 * @blocksize: cipher block size in bytes. Block cipher IVs are matching the
 * cipher's block size.
 * @authsize: byte size of integrity check value. Only full ICVs were tested.
 * @cipherdata: pointer to block cipher transform definitions
 * Valid cipherdata->algtype values: OP_ALG_ALGSEL_AES, OP_ALG_ALGSEL_DES.
 * @authdata: pointer to authentication transform definitions
 * A MDHA split key must be provided.
 * Valid authdata->algtype values: OP_ALG_ALGSEL_SHA1.
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int cnstr_shdsc_tls10_dec(uint32_t *descbuf,
	unsigned int blocksize, unsigned int authsize,
	struct alginfo *cipherdata, struct alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;
	/* Associated data length is always = 13 for TLS */
	unsigned int assoclen = 13;
	bool is_aes = false;

	LABEL(keyjmp);
	LABEL(no_payload);
	LABEL(jmp);
	LABEL(jd_idx);
	LABEL(seqinptr_idx);
	REFERENCE(pkeyjmp);
	REFERENCE(no_payload_jmp);
	REFERENCE(jmp_cmd);
	REFERENCE(copy_jd_fields);
	REFERENCE(overwrite_jd_fields);
	REFERENCE(read_seqinptr);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	PROGRAM_SET_36BIT_ADDR(p);
	if ((cipherdata->algtype & OP_ALG_ALGSEL_MASK) == OP_ALG_ALGSEL_AES) {
		is_aes = true;
		SHR_HDR(p, SHR_ALWAYS, 1, 0);
		/*
		 * ALWAYS reload the keys. Keys are deleted from the KEY
		 * registers when ALWAYS sharing is used.
		 */
		KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, 0);
		KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
		    cipherdata->keylen, 0);
	} else {
		SHR_HDR(p, SHR_SERIAL, 1, 0);
		/* skip key loading if they are loaded due to sharing */
		pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);
		KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, 0);
		KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
		    cipherdata->keylen, 0);
		SET_LABEL(p, keyjmp);
	}

	/* class 2 operation */
	ALG_OPERATION(p, authdata->algtype , OP_ALG_AAI_HMAC_PRECOMP,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_ENABLE, DIR_DEC);
	/* class 1 operation */
	ALG_OPERATION(p, cipherdata->algtype, OP_ALG_AAI_CBC,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_DEC);

	/* VSIL = input data length - 2 * block_size */
	MATHB(p, SEQINSZ, SUB, 2 * blocksize, VSEQINSZ, 4, IMMED2);

	/*
	 * payloadlen + icvlen + padlen = input data length -
	 * (assoclen + ivlen)
	 */
	MATHB(p, SEQINSZ, SUB, assoclen + blocksize, MATH3, 4, IMMED2);

	/* skip data to the last but one cipher block */
	SEQFIFOLOAD(p, SKIP, 0, VLF);

	/* load iv for the last cipher block */
	SEQLOAD(p, CONTEXT1, 0, blocksize, 0);

	/* read last cipher block */
	SEQFIFOLOAD(p, MSG1, blocksize, LAST1);

	if (is_aes) {
		/* move decrypted block into math0 and math1 */
		MOVE(p, OFIFO, 0, MATH0, 0, blocksize, WAITCOMP | IMMED);
		/* reset AES CHA */
		LOAD(p, CCTRL_RESET_CHA_AESA, CCTRL, 0, 4, IMMED);
	} else {
		/* move decrypted block into math1 */
		MOVE(p, OFIFO, 0, MATH1, 0, blocksize, WAITCOMP | IMMED);
		/* reset DES CHA */
		LOAD(p, CCTRL_RESET_CHA_DESA, CCTRL, 0, 4, IMMED);
	}

	/* rewind input sequence */
	SEQINPTR(p, 0, 65535, RTO);

	if (is_aes)
		/* key1 is in decryption form */
		ALG_OPERATION(p, cipherdata->algtype,
			      OP_ALG_AAI_CBC | OP_ALG_AAI_DK,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, DIR_DEC);
	/* read sequence number */
	SEQFIFOLOAD(p, MSG2, 8, 0);
	/* load Type, Version and Len fields in math0 */
	SEQLOAD(p, MATH0, 3, 5, 0);

	/* load iv in context1 */
	SEQLOAD(p, CONTEXT1, 0, blocksize, 0);

	/* compute (padlen - 1) */
	MATHB(p, MATH1, AND, 0xff, MATH1, 8, IFB | IMMED2);

	/* math2 = icvlen + (padlen - 1) + 1 */
	MATHB(p, MATH1, ADD, authsize + 1, MATH2, 4, IMMED2);

	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);

	/* VSOL = payloadlen + icvlen + padlen */
	MATHB(p, ZERO, ADD, MATH3, VSEQOUTSZ, 4, 0);

	/* update Len field */
	MATHB(p, MATH0, SUB, MATH2, MATH0, 8, 0);

	/* store decrypted payload, icv and padding */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/* VSIL = (payloadlen + icvlen + padlen) - (icvlen + padlen)*/
	MATHB(p, MATH3, SUB, MATH2, VSEQINSZ, 4, 0);

	no_payload_jmp = JUMP(p, no_payload, LOCAL_JUMP, ALL_TRUE, MATH_Z);

	/* send Type, Version and Len(pre ICV) fields to authentication */
	MOVE(p, MATH0, 3, IFIFOAB2, 0, 5,  WAITCOMP | IMMED);

	/* outsnooping payload */
	SEQFIFOLOAD(p, MSGOUTSNOOP, 0, LAST2 | VLF);
	jmp_cmd = JUMP(p, jmp, LOCAL_JUMP, ALL_TRUE, 0);

	SET_LABEL(p, no_payload);
	/* send Type, Version and Len(pre ICV) fields to authentication */
	MOVE(p, MATH0, 3, IFIFOAB2, 0, 5, LAST2 | WAITCOMP | IMMED);

	SET_LABEL(p, jmp);
	MATHB(p, ZERO, ADD, MATH2, VSEQINSZ, 4, 0);

	/* load icvlen and padlen */
	SEQFIFOLOAD(p, MSG1, 0, LAST1 | VLF);

	/* VSIL = (payloadlen + icvlen + padlen) - icvlen + padlen */
	MATHB(p, MATH3, SUB, MATH2, VSEQINSZ, 4, 0);

	/* move seqoutptr fields into math registers */
	copy_jd_fields = MOVE(p, DESCBUF, 0, MATH0, 0, 20, WAITCOMP | IMMED);

	/* seqinptr will point to seqoutptr */
	MATHB(p, MATH0, AND, ~(CMD_SEQ_IN_PTR ^ CMD_SEQ_OUT_PTR), MATH0, 4,
	      IMMED2);

/*
 * TODO: RTA currently doesn't support creating a LOAD command
 * with another command as IMM.
 * To be changed when proper support is added in RTA.
 */
	/* Load jump command */
	LOAD(p, 0xa00000f7, MATH2, 4, 4, IMMED);
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CALM);

	/* move updated seqinptr fields to JD */
	overwrite_jd_fields = MOVE(p, MATH0, 0, DESCBUF, 0, 24,
				   WAITCOMP | IMMED);

	/* read updated seqinptr */
	read_seqinptr = JUMP(p, seqinptr_idx, LOCAL_JUMP, ALL_TRUE, CALM);

	/* skip payload */
	SEQFIFOLOAD(p, SKIP, 0, VLF);

	/* check icv */
	SEQFIFOLOAD(p, ICV2, authsize, LAST2);

/*
 * TODO: RTA currently doesn't support adding labels in or after Job Descriptor.
 * To be changed when proper support is added in RTA.
 */
	SET_LABEL(p, jd_idx);
	jd_idx += 2;
	SET_LABEL(p, seqinptr_idx);
	seqinptr_idx += 3;

	if (!is_aes)
		PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_JUMP(p, no_payload_jmp, no_payload);
	PATCH_JUMP(p, jmp_cmd, jmp);
	PATCH_JUMP(p, read_seqinptr, seqinptr_idx);
	PATCH_MOVE(p, copy_jd_fields, jd_idx);
	PATCH_MOVE(p, overwrite_jd_fields, jd_idx);

	return PROGRAM_FINALIZE(p);
}

#endif /* __DESC_TLS_H__ */
