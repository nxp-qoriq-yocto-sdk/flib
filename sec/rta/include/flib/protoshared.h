#ifndef __RTA_PROTOSHARED_H__
#define __RTA_PROTOSHARED_H__

#include "rta.h"

/**
 * @file                 protoshared.h
 * @brief                SEC Descriptor Construction Library Protocol-level
 *                       Shared Descriptor Constructors
 */

/**
 * @defgroup descriptor_lib_group RTA Descriptors Library
 * @{
 */
/** @} end of descriptor_lib_group */

/**
 * @defgroup defines_group Auxiliary Defines
 * @ingroup descriptor_lib_group
 * @{
 */

/**
 * @def PDCP_NULL_MAX_FRAME_LEN
 * The maximum frame frame length that is supported by PDCP NULL protocol.
 */
#define PDCP_NULL_MAX_FRAME_LEN		0x00002FFF

/**
 * @def PDCP_MAC_I_LEN
 * The length of the MAC-I for PDCP protocol operation.
 */
#define PDCP_MAC_I_LEN			0x00000004

/**
 * #def PDCP_MAX_FRAME_LEN_STATUS
 * The status returned in FD status/command field in case the input frame
 * is larger than PDCP_NULL_MAX_FRAME_LEN
 */
#define PDCP_MAX_FRAME_LEN_STATUS	0xF1

/**
 * @def PDCP_SN_MASK
 * This mask is used in the PDCP descriptors for extracting the sequence
 * number (SN) from the PDCP Control Plane header. For PDCP Control Plane,
 * the SN is constant (5 bits) as opposed to PDCP Data Plane (7/12 bits).
 */
#define PDCP_SN_MASK			0x0000001F

/**
 * @def PDCP_BEARER_MASK
 * This mask is used masking out the bearer for PDCP processing with SNOW f9
 * in LTE. The value on which this mask is applied is formatted as below:
 *
 *     Count-C (32 bit) | Bearer (5 bit) | Direction (1 bit) | 0 (26 bits)
 *
 * Applying this mask is done for creating the upper 64 bits of the IV needed
 * for SNOW f9.
 *
 * The lower 32 bits of the mask are used for masking the direction for AES
 * CMAC IV.
 */
#define PDCP_BEARER_MASK		0xFFFFFFFF04000000ull

/**
 * @def PDCP_DIR_MASK
 * This mask is used masking out the direction for PDCP processing with SNOW f9
 * in LTE. The value on which this mask is applied is formatted as below:
 *
 *     Bearer (5 bit) | Direction (1 bit) | 0 (26 bits)
 *
 * Applying this mask is done for creating the lower 32 bits of the IV needed
 * for SNOW f9.
 *
 * The upper 32 bits of the mask are used for masking the direction for AES
 * CMAC IV.
 */
#define PDCP_DIR_MASK			0xF800000000000000ull

/**
 * @def PDCP_NULL_INT_MAC_I_VAL
 * The value of the PDCP PDU MAC-I in case NULL integrity is used
 */

#define PDCP_NULL_INT_MAC_I_VAL		0x00000000
/** @} */ /* end of defines_group */
/**
 * @defgroup typedefs_group Auxiliary Data Structures
 * @ingroup descriptor_lib_group
 * @{
 */

/**
 * @struct    alginfo protoshared.h
 * @details   Container for IPsec algorithm details
 */
struct alginfo {
	uint32_t algtype;  /**< Algorithm selector. For valid values, see
				documentation of the functions where it is
				used */
	uint64_t key;      /**< Address where algorithm key resides */
	uint32_t keylen;   /**< Length of the provided key, in bytes */
};

/**
 * @enum      cipher_type_pdcp protoshared.h
 * @details   Type selectors for cipher types in PDCP protocol OP instructions.
 */
enum cipher_type_pdcp {
	PDCP_CIPHER_TYPE_NULL,
	PDCP_CIPHER_TYPE_SNOW,
	PDCP_CIPHER_TYPE_AES,
	PDCP_CIPHER_TYPE_ZUC,
	PDCP_CIPHER_TYPE_INVALID
};

/**
 * @enum       auth_type_pdcp protoshared.h
 * @details    Type selectors for integrity types in PDCP protocol OP
 *             instructions.
 */
enum auth_type_pdcp {
	PDCP_AUTH_TYPE_NULL,
	PDCP_AUTH_TYPE_SNOW,
	PDCP_AUTH_TYPE_AES,
	PDCP_AUTH_TYPE_ZUC,
	PDCP_AUTH_TYPE_INVALID
};

/**
 * @enum       pdcp_dir protoshared.h
 * @details    Type selectors for direction for PDCP protocol.
 */
enum pdcp_dir {
	PDCP_DIR_UPLINK = 0,
	PDCP_DIR_DOWNLINK = 1
};

/**
 * @enum     pdcp_plane protoshared.h
 * @details    PDCP domain selectors.
 */
enum pdcp_plane {
	PDCP_CONTROL_PLANE,
	PDCP_DATA_PLANE
};

/**
 * @enum     pdcp_sn_size protoshared.h
 * @details    Sequence Number length selectors for PDCP protocol
 */
enum pdcp_sn_size {
	PDCP_SN_SIZE_5 = 5,
	PDCP_SN_SIZE_7 = 7,
	PDCP_SN_SIZE_12 = 12
};
/** @} */ /* end of typedefs_group */
/**
 * @defgroup sharedesc_group Shared Descriptor Example Routines
 * @ingroup descriptor_lib_group
 * @{
 */
/** @} end of sharedesc_group */

/**
 * @details                  SNOW/f8 (UEA2) as a shared descriptor.
 * @ingroup                  sharedesc_group
 *
 * @param [in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param [in,out] bufsize   Points to size to be updated at completion.
 * @param [in] cipherdata    Pointer to block cipher transform definitions.
 * @param [in] dir           Cipher direction (DIR_ENCRYPT/DIR_DECRYPT).
 * @param [in] count         UEA2 count value (32 bits).
 * @param [in] bearer        UEA2 bearer ID (5 bits).
 * @param [in] direction     UEA2 direction (1 bit).
 *
 */
static inline void cnstr_shdsc_snow_f8(uint32_t *descbuf, unsigned *bufsize,
			 struct alginfo *cipherdata, uint8_t dir,
			 uint32_t count, uint8_t bearer, uint8_t direction)
{
	struct program prg;
	struct program *program = &prg;
	uint64_t ct = count;
	uint64_t br = bearer;
	uint64_t dr = direction;
	uint64_t context = (ct << 32) | (br << 27) | (dr << 26);

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_ALWAYS, 1, 0);
	{
		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, IMMED);
		MATHB(SEQINSZ, SUB, MATH2, VSEQINSZ, SIZE(4), 0);
		MATHB(SEQINSZ, SUB, MATH2, VSEQOUTSZ, SIZE(4), 0);
		ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F8, OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL, 0, dir);
		LOAD(IMM(context), CONTEXT1, 0, SIZE(8), 0);
		SEQFIFOLOAD(MSG1, SIZE(32), WITH(VLF | LAST1 | LAST2));
		SEQFIFOSTORE(MSG, 0, SIZE(32), WITH(VLF));
	}
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                 SNOW/f9 (UIA2) as a shared descriptor.
 * @ingroup                 sharedesc_group
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Points to size to be updated at completion.
 * @param[in] authdata      Pointer to authentication transform definitions.
 * @param[in] dir           Cipher direction (DIR_ENCRYPT/DIR_DECRYPT).
 * @param[in] count         UEA2 count value (32 bits).
 * @param[in] fresh         UEA2 fresh value ID (32 bits).
 * @param[in] direction     UEA2 direction (1 bit).
 * @param[in] datalen       Size of data.
 */
static inline void cnstr_shdsc_snow_f9(uint32_t *descbuf, unsigned *bufsize,
			 struct alginfo *authdata, uint8_t dir, uint32_t count,
			 uint32_t fresh, uint8_t direction, uint32_t datalen)
{
	struct program prg;
	struct program *program = &prg;
	uint64_t ct = count;
	uint64_t fr = fresh;
	uint64_t dr = direction;
	uint64_t context[2];

	context[0] = (ct << 32) | (dr << 26);
	context[1] = fr << 32;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_ALWAYS, 1, 0);
	{
		KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, IMMED);
		MATHB(SEQINSZ, SUB, MATH2, VSEQINSZ, SIZE(4), 0);
		ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F9, OP_ALG_AAI_F9,
			      OP_ALG_AS_INITFINAL, 0, dir);
		LOAD(PTR((uintptr_t)context), CONTEXT2, 0, SIZE(16), IMMED);
		SEQFIFOLOAD(BIT_DATA, datalen, WITH(CLASS2 | LAST1 | LAST2));
		/* Save lower half of MAC out into a 32-bit sequence */
		SEQSTORE(CONTEXT2, 0, SIZE(4), 0);
	}
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                 CBC block cipher
 * @ingroup                 sharedesc_group
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Limit/returned descriptor buffer size.
 * @param[in] cipherdata    Pointer to block cipher transform definitions.
 * @param[in] iv            IV data.
 * @param[in] ivlen         IV length.
 * @param[in] dir           DIR_ENCRYPT/DIR_DECRYPT.
 * @param[in] cipher        OP_ALG_ALGSEL_AES/DES/3DES.
 */
static inline void cnstr_shdsc_cbc_blkcipher(uint32_t *descbuf,
			       unsigned *bufsize, struct alginfo *cipherdata,
			       uint8_t *iv, uint32_t ivlen, uint8_t dir,
			       uint32_t cipher)
{
	struct program prg;
	struct program *program = &prg;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_ALWAYS, 1, SC);
	{
		/* Insert Key */
		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, IMMED);
		MATHB(SEQINSZ, SUB, MATH2, VSEQINSZ, SIZE(4), 0);
		MATHB(SEQINSZ, SUB, MATH2, VSEQOUTSZ, SIZE(4), 0);
		ALG_OPERATION(cipher, OP_ALG_AAI_CBC, OP_ALG_AS_INIT, 0, dir);
		/* IV load, convert size */
		LOAD(PTR((uintptr_t)iv), CONTEXT1, 0, ivlen, IMMED);
		/* Insert sequence load/store with VLF */
		SEQFIFOLOAD(MSG1, SIZE(32), WITH(VLF | LAST1 | LAST2));
		SEQFIFOSTORE(MSG, 0, SIZE(32), WITH(VLF));
	}
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                HMAC shared
 * @ingroup                sharedesc_group
 *
 * @param[in,out] descbuf  Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize  Limit/returned descriptor buffer size.
 * @param[in] authdata     Pointer to authentication transform definitions.
 *                         Message digest algorithm: OP_ALG_ALGSEL_MD5/
 *                         SHA1-512.
 * @param[in] icv          HMAC comparison for ICV, NULL if no check desired.
 */
static inline void cnstr_shdsc_hmac(uint32_t *descbuf, unsigned *bufsize,
		      struct alginfo *authdata, uint8_t *icv)
{
	struct program prg;
	struct program *program = &prg;
	uint8_t storelen;
	uint8_t opicv;

	/* Compute fixed-size store based on alg selection */
	switch (authdata->algtype) {
	case OP_ALG_ALGSEL_MD5:
		storelen = 16;
		break;
	case OP_ALG_ALGSEL_SHA1:
		storelen = 20;
		break;
	case OP_ALG_ALGSEL_SHA224:
		storelen = 28;
		break;
	case OP_ALG_ALGSEL_SHA256:
		storelen = 32;
		break;
	case OP_ALG_ALGSEL_SHA384:
		storelen = 48;
		break;
	case OP_ALG_ALGSEL_SHA512:
		storelen = 64;
		break;
	default:
		return;
	}

	opicv = icv ? ICV_CHECK_ENABLE : ICV_CHECK_DISABLE;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_ALWAYS, 1, SC);
	{
		KEY(KEY2, 0, PTR(authdata->key), storelen, IMMED);
		/* compute sequences */
		MATHB(SEQINSZ, SUB, MATH2, VSEQINSZ, SIZE(4), 0);
		MATHB(SEQINSZ, SUB, MATH2, VSEQOUTSZ, SIZE(4), 0);
		/* Do operation */
		ALG_OPERATION(authdata->algtype, OP_ALG_AAI_HMAC,
			      OP_ALG_AS_INITFINAL, opicv, DIR_ENC);
		/* Do load (variable length) */
		SEQFIFOLOAD(MSG2, SIZE(32), WITH(VLF | LAST1 | LAST2));
		SEQSTORE(CONTEXT2, 0, storelen, 0);
	}
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                 KASUMI F8 (Confidentiality) as a shared descriptor
 *                          (ETSI "Document 1: f8 and f9 specification").
 * @ingroup                 sharedesc_group
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Points to size to be updated at completion.
 * @param[in] cipherdata    Pointer to block cipher transform definitions.
 * @param[in] dir           Cipher direction (DIR_ENCRYPT/DIR_DECRYPT).
 * @param[in] count         Count value (32 bits).
 * @param[in] bearer        Bearer ID (5 bits).
 * @param[in] direction     Direction (1 bit).
 */
static inline void cnstr_shdsc_kasumi_f8(uint32_t *descbuf, unsigned *bufsize,
			   struct alginfo *cipherdata, uint8_t dir,
			   uint32_t count, uint8_t bearer, uint8_t direction)
{
	struct program prg;
	struct program *program = &prg;
	uint64_t ct = count;
	uint64_t br = bearer;
	uint64_t dr = direction;
	uint64_t context = (ct << 32) | (br << 27) | (dr << 26);

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_ALWAYS, 1, 0);
	{
		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, IMMED);
		MATHB(SEQINSZ, SUB, MATH2, VSEQINSZ, SIZE(4), 0);
		MATHB(SEQINSZ, SUB, MATH2, VSEQOUTSZ, SIZE(4), 0);
		ALG_OPERATION(OP_ALG_ALGSEL_KASUMI, OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL, 0, dir);
		LOAD(IMM(context), CONTEXT1, 0, SIZE(8), 0);
		SEQFIFOLOAD(MSG1, SIZE(32), WITH(VLF | LAST1 | LAST2));
		SEQFIFOSTORE(MSG, 0, SIZE(32), WITH(VLF));
	}
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                 KASUMI F9 (Integrity) as a shared descriptor
 *                          (ETSI "Document 1: f8 and f9 specification").
 * @ingroup                 sharedesc_group
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Points to size to be updated at completion.
 * @param[in] authdata      Pointer to authentication transform definitions.
 * @param[in] dir           Cipher direction (DIR_ENCRYPT/DIR_DECRYPT).
 * @param[in] count         Count value (32 bits).
 * @param[in] fresh         Fresh value ID (32 bits).
 * @param[in] direction     Direction (1 bit).
 * @param[in] datalen       Size of data.
 */
static inline void cnstr_shdsc_kasumi_f9(uint32_t *descbuf, unsigned *bufsize,
			   struct alginfo *authdata, uint8_t dir,
			   uint32_t count, uint32_t fresh, uint8_t direction,
			   uint32_t datalen)
{
	struct program prg;
	struct program *program = &prg;
	uint16_t ctx_offset = 16;
	uint64_t ct = count;
	uint64_t fr = fresh;
	uint64_t dr = direction;
	uint64_t context[3];

	context[0] = (ct << 32) | (dr << 26);
	context[1] = (fr << 32);

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_ALWAYS, 1, 0);
	{
		KEY(KEY1, 0, PTR(authdata->key), authdata->keylen, IMMED);
		MATHB(SEQINSZ, SUB, MATH2, VSEQINSZ, SIZE(4), 0);
		ALG_OPERATION(OP_ALG_ALGSEL_KASUMI, OP_ALG_AAI_F9,
			      OP_ALG_AS_INITFINAL, 0, dir);
		LOAD(PTR((uintptr_t)context), CONTEXT1, 0, SIZE(24), IMMED);
		SEQFIFOLOAD(BIT_DATA, datalen, WITH(CLASS1 | LAST1 | LAST2));
		/* Save output MAC of DWORD 2 into a 32-bit sequence */
		SEQSTORE(CONTEXT1, ctx_offset, SIZE(4), 0);
	}
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                CRC32 Accelerator (IEEE 802 CRC32 protocol mode)
 * @ingroup                sharedesc_group
 *
 * @param[in,out] descbuf  Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize  Limit of descriptor buffer size.
 */
static inline void cnstr_shdsc_crc(uint32_t *descbuf, unsigned *bufsize)
{
	struct program prg;
	struct program *program = &prg;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_ALWAYS, 1, 0);
	{
		MATHB(SEQINSZ, SUB, MATH2, VSEQINSZ, SIZE(4), 0);
		ALG_OPERATION(OP_ALG_ALGSEL_CRC,
			      OP_ALG_AAI_802 | OP_ALG_AAI_DOC,
			      OP_ALG_AS_FINALIZE, 0, DIR_ENC);
		SEQFIFOLOAD(MSG2, SIZE(32), WITH(VLF | LAST2));
		SEQSTORE(CONTEXT2, 0, SIZE(4), 0);
	}
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                 MACsec(802.1AE) encapsulation
 * @ingroup                 sharedesc_group
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Points to size to be updated at completion.
 * @param[in] cipherdata    Pointer to block cipher transform definitions.
 * @param[in] sci           PDB Secure Channel Identifier.
 * @param[in] ethertype     PDB EtherType.
 * @param[in] tci_an        TAG Control Information and Association Number
 *                          are treated as a single field of 8 bits in PDB.
 * @param[in] pn            PDB Packet Number.
 **/
static inline void cnstr_shdsc_macsec_encap(uint32_t *descbuf,
					    unsigned *bufsize,
					    struct alginfo *cipherdata,
					    uint64_t sci, uint16_t ethertype,
					    uint8_t tci_an, uint32_t pn)
{
	struct program prg;
	struct program *program = &prg;
	struct macsec_encap_pdb pdb;
	uint32_t startidx;

	LABEL(keyjump);
	REFERENCE(pkeyjump);

	memset(&pdb, 0x00, sizeof(struct macsec_encap_pdb));
	pdb.sci_hi = high_32b(sci);
	pdb.sci_lo = low_32b(sci);
	pdb.ethertype = ethertype;
	pdb.tci_an = tci_an;
	pdb.pn = pn;

	startidx = sizeof(struct macsec_encap_pdb) >> 2;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_SERIAL, ++startidx, WITH(SC));
	{
		ENDIAN_DATA((uint8_t *)&pdb, sizeof(struct macsec_encap_pdb));
		pkeyjump = JUMP(IMM(keyjump), LOCAL_JUMP, ALL_TRUE,
				WITH(SHRD | SELF | BOTH));
		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen,
		    WITH(IMMED));
		SET_LABEL(keyjump);
		PROTOCOL(OP_TYPE_ENCAP_PROTOCOL, OP_PCLID_MACSEC,
			 WITH(OP_PCL_MACSEC));
	}
	PATCH_JUMP(pkeyjump, keyjump);
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                 MACsec(802.1AE) decapsulation
 * @ingroup                 sharedesc_group
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Points to size to be updated at completion.
 * @param[in] cipherdata    Pointer to block cipher transform definitions.
 * @param[in] sci           PDB Secure Channel Identifier.
 * @param[in] pn            PDB Packet Number.
 **/
static inline void cnstr_shdsc_macsec_decap(uint32_t *descbuf,
					    unsigned *bufsize,
					    struct alginfo *cipherdata,
					    uint64_t sci, uint32_t pn)
{
	struct program prg;
	struct program *program = &prg;
	struct macsec_decap_pdb pdb;
	uint32_t startidx;

	LABEL(keyjump);
	REFERENCE(pkeyjump);

	memset(&pdb, 0x00, sizeof(struct macsec_decap_pdb));
	pdb.sci_hi = high_32b(sci);
	pdb.sci_lo = low_32b(sci);
	pdb.pn = pn;

	startidx = sizeof(struct macsec_decap_pdb) >> 2;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_SERIAL, ++startidx, WITH(SC));
	{
		ENDIAN_DATA((uint8_t *)&pdb, sizeof(struct macsec_decap_pdb));
		pkeyjump = JUMP(IMM(keyjump), LOCAL_JUMP, ALL_TRUE,
				WITH(SHRD | SELF | BOTH));
		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen,
		    WITH(IMMED));
		SET_LABEL(keyjump);
		PROTOCOL(OP_TYPE_DECAP_PROTOCOL, OP_PCLID_MACSEC,
			 WITH(OP_PCL_MACSEC));
	}
	PATCH_JUMP(pkeyjump, keyjump);
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details  IPSec ESP encapsulation protocol-level shared descriptor.
 *           Requires an MDHA split key.
 * @ingroup sharedesc_group
 *
 * @param[in,out] descbuf    Pointer to buffer used for descriptor construction
 * @param[in,out] bufsize    Pointer to descriptor size to be written back upon
 *      completion
 * @param[in] pdb         Pointer to the PDB to be used with this descriptor.
 *      This structure will be copied inline to the descriptor under
 *      construction. No error checking will be made. Refer to the
 *      block guide for a details of the encapsulation PDB.
 * @param[in] ip_hdr      Optional header to be prepended to an encapsulated
 *      frame. Size of the optional header is defined in pdb.ip_hdr_len.
 * @param[in] cipherdata  Pointer to block cipher transform definitions. Valid
 *      algorithm values: one of OP_PCL_IPSEC_*
 * @param[in] authdata    Pointer to authentication transform definitions. Note
 *      that since a split key is to be used, the size of the split key itself
 *      is specified. Valid algorithm values: one of OP_PCL_IPSEC_*
 **/
static inline void cnstr_shdsc_ipsec_encap(uint32_t *descbuf,
					   unsigned *bufsize,
					   struct ipsec_encap_pdb *pdb,
					   uint8_t *ip_hdr,
					   struct alginfo *cipherdata,
					   struct alginfo *authdata)
{
	struct program prg;
	struct program *program = &prg;

	LABEL(keyjmp);
	REFERENCE(pkeyjmp);
	LABEL(hdr);
	REFERENCE(phdr);

	PROGRAM_CNTXT_INIT(descbuf, 0);
	phdr = SHR_HDR(SHR_SERIAL, hdr, 0);
	ENDIAN_DATA((uint8_t *)pdb, sizeof(struct ipsec_encap_pdb));
	if (pdb->ip_hdr_len)
		ENDIAN_DATA(ip_hdr, pdb->ip_hdr_len);
	SET_LABEL(hdr);
	pkeyjmp = JUMP(IMM(keyjmp), LOCAL_JUMP, ALL_TRUE, BOTH|SHRD);
	KEY(MDHA_SPLIT_KEY, ENC, PTR(authdata->key), authdata->keylen, IMMED);
	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, IMMED);
	SET_LABEL(keyjmp);
	PROTOCOL(OP_TYPE_ENCAP_PROTOCOL,
		 OP_PCLID_IPSEC,
		 cipherdata->algtype | authdata->algtype);
	PATCH_JUMP(pkeyjmp, keyjmp);
	PATCH_HDR(phdr, hdr);
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details IPSec ESP decapsulation protocol-level sharedesc
 *          Requires an MDHA split key.
 * @ingroup sharedesc_group
 *
 * @param[in,out] descbuf    Pointer to buffer used for descriptor construction
 * @param[in,out] bufsize    Pointer to descriptor size to be written back upon
 *      completion
 * @param[in] pdb         Pointer to the PDB to be used with this descriptor.
 *      This structure will be copied inline to the descriptor under
 *      construction. No error checking will be made. Refer to the
 *      block guide for details about the decapsulation PDB.
 * @param[in] cipherdata  Pointer to block cipher transform definitions. Valid
 *      algorithm values: one of OP_PCL_IPSEC_*
 * @param[in] authdata    Pointer to authentication transform definitions. Note
 *      that since a split key is to be used, the size of the split key itself
 *      is specified. Valid algorithm values: one of OP_PCL_IPSEC_*
 **/
static inline void cnstr_shdsc_ipsec_decap(uint32_t *descbuf,
					   unsigned *bufsize,
					   struct ipsec_decap_pdb *pdb,
					   struct alginfo *cipherdata,
					   struct alginfo *authdata)
{
	struct program prg;
	struct program *program = &prg;

	LABEL(keyjmp);
	REFERENCE(pkeyjmp);
	LABEL(hdr);
	REFERENCE(phdr);

	PROGRAM_CNTXT_INIT(descbuf, 0);
	phdr = SHR_HDR(SHR_SERIAL, hdr, 0);
	ENDIAN_DATA((uint8_t *)pdb, sizeof(struct ipsec_decap_pdb));
	SET_LABEL(hdr);
	pkeyjmp = JUMP(IMM(keyjmp), LOCAL_JUMP, ALL_TRUE, BOTH|SHRD);
	KEY(MDHA_SPLIT_KEY, ENC, PTR(authdata->key), authdata->keylen, IMMED);
	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, IMMED);
	SET_LABEL(keyjmp);
	PROTOCOL(OP_TYPE_DECAP_PROTOCOL,
		 OP_PCLID_IPSEC,
		 cipherdata->algtype | authdata->algtype);
	PATCH_JUMP(pkeyjmp, keyjmp);
	PATCH_HDR(phdr, hdr);
	*bufsize = PROGRAM_FINALIZE();
}


/**
 * @details                 WiMAX(802.16) encapsulation
 * @ingroup                 sharedesc_group
 * @warning                 Descriptor valid on platforms
 *                          with support for SEC ERA 4.
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Points to size to be updated at completion.
 * @param[in] pdb_opts      PDB Options Byte.
 * @param[in] pn            PDB Packet Number.
 * @param[in] cipherdata    Pointer to block cipher transform definitions.
 * @param[in] protinfo      Protocol information: OP_PCL_WIMAX_OFDM/OFDMA.
 */
void cnstr_shdsc_wimax_encap(uint32_t *descbuf, unsigned *bufsize,
			     uint8_t pdb_opts, uint32_t pn, uint16_t protinfo,
			     struct alginfo *cipherdata)
{
	struct wimax_encap_pdb pdb;
	struct program prg;
	struct program *program = &prg;
	uint32_t startidx;

	LABEL(seq_ptr);
	LABEL(crc8);
	REFERENCE(pseq_in_ptr);
	REFERENCE(pseq_out_ptr);
	REFERENCE(pcrc8);

	memset(&pdb, 0x00, sizeof(struct wimax_encap_pdb));
	pdb.options = pdb_opts;
	pdb.pn = pn;
	pdb.b0_flags = WIMAX_PDB_B0;
	pdb.ctr_flags = WIMAX_PDB_CTR;

	startidx = sizeof(struct wimax_encap_pdb) >> 2;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_NEVER, ++startidx, WITH(0));
	{
		ENDIAN_DATA((uint8_t *)&pdb, sizeof(struct wimax_encap_pdb));
		SEQLOAD(MATH0, 0, 8, WITH(0));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
		SET_LABEL(seq_ptr);

		/* Set Encryption Control bit */
		MATHB(MATH0, OR, IMM(0x4000000000000000), MATH0, SIZE(8), 0);

		/* Update Length field */
		MOVE(DESCBUF, 0, MATH1, 0, IMM(8), WITH(0));
		MATHB(MATH0, ADD, IMM(0x00000c0000000000), MATH0, SIZE(8), 0);
		MATHB(MATH1, AND, ONE, NONE, SIZE(8), 0);

		/* Update Length field if FCS bit is enabled */
		pcrc8 = JUMP(IMM(crc8), LOCAL_JUMP, ALL_TRUE, WITH(MATH_Z));
		MATHB(MATH0, ADD, IMM(0x0000040000000000), MATH0, SIZE(8), 0);

		/*
		 * Compute the CRC-8-ATM value for the first five bytes
		 * of the header and insert the result into the sixth
		 * MATH0 byte field.
		 */
		SET_LABEL(crc8);
		KEY(KEY2, 0, IMM(0x07000000), 2, WITH(IMMED));
		ALG_OPERATION(OP_ALG_ALGSEL_CRC,
			      OP_ALG_AAI_CUST_POLY | OP_ALG_AAI_DIS,
			      OP_ALG_AS_UPDATE, ICV_CHECK_DISABLE,
			      OP_ALG_ENCRYPT);
		MOVE(MATH0, 0, IFIFOAB2, 0, IMM(5), WITH(LAST1));
		MOVE(CONTEXT2, 0, MATH1, 0, IMM(4), WITH(WAITCOMP));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CLASS2));
		MOVE(MATH1, 0, MATH0, 5, IMM(1), WITH(WAITCOMP));

		/*
		 * Rewrite encapsulation input frame with the updated
		 * Generic Mac Header from MATH0. SEC workflow is as follows:
		 *     1. Copy JD's Output Length, SEQINPTR, Input Pointer and
		 *        Input Length in MATH1, MATH2, MATH3 registers.
		 *     2. Transform SEQINPTR in SEQOUTPTR.
		 *     3. Load in MATH3 a local conditional JUMP with offset
		 *        targetting the SEQSTORE command.
		 *     4. Copy MATH1, MATH2, MATH3 contents
		 *        at the first word before seq_ptr LABEL.
		 *     5. JUMP to seq_ptr LABEL, run SEQOUTPTR, Input Pointer,
		 *        Input Length and then JUMP to SEQSTORE.
		 *     6. Save encapsulation Generic Mac Header.
		 */
		MOVE(DESCBUF, 55 * 4, MATH1, 0, IMM(20), WITH(WAITCOMP));
		MATHB(MATH1, OR, IMM(0x08000000), MATH1, SIZE(8), IFB);
		LOAD(IMM(0xa0000016), MATH3, 4, 4, WITH(0));
		MOVE(MATH1, 0, DESCBUF, 6 * 4, IMM(24), WITH(WAITCOMP));
		pseq_in_ptr = JUMP(IMM(seq_ptr), LOCAL_JUMP, ALL_TRUE, WITH(0));
		SEQSTORE(MATH0, 0, 8, WITH(0));

		SEQINPTR(0, 8, WITH(RTO));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));

		/*
		 * Restore Output Sequence. SEC workflow is as follows:
		 *     1. Copy JD's Shared Descriptor Pointer, SEQOUTPTR,
		 *        Output Pointer and Output Length in MATH0, MATH1,
		 *        MATH2 registers.
		 *     2. Load in MATH2 a local conditional JUMP with offset
		 *        targetting the KEY command.
		 *     3. Copy MATH0, MATH1, MATH2 contents
		 *        at the first word before seq_ptr LABEL.
		 *     4. JUMP to seq_ptr LABEL, run SEQOUTPTR, Output Pointer,
		 *        Output Length and then JUMP to KEY command.
		 */
		MOVE(DESCBUF, 51 * 4, MATH0, 0, IMM(20), WITH(WAITCOMP));
		LOAD(IMM(0xa000001e), MATH2, 4, 4, WITH(0));
		MOVE(MATH0, 0, DESCBUF, 6 * 4, IMM(24), WITH(WAITCOMP));
		pseq_out_ptr = JUMP(IMM(seq_ptr), LOCAL_JUMP, ALL_TRUE,
				    WITH(0));

		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen,
		    WITH(IMMED));
		LOAD(IMM(LDST_SRCDST_WORD_CLRW |
			 CLRW_CLR_C1MODE |
			 CLRW_CLR_C2MODE |
			 CLRW_CLR_C2DATAS |
			 CLRW_CLR_C2CTX |
			 CLRW_CLR_C2KEY |
			 CLRW_RESET_CLS2_CHA |
			 CLRW_RESET_CLS1_CHA),
		     CLRW, 0, 4, WITH(0));
		PROTOCOL(OP_TYPE_ENCAP_PROTOCOL, OP_PCLID_WIMAX, protinfo);
	}
	PATCH_JUMP(pcrc8, crc8);
	PATCH_JUMP(pseq_in_ptr, seq_ptr);
	PATCH_JUMP(pseq_out_ptr, seq_ptr);
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                 WiMAX(802.16) decapsulation
 * @ingroup                 sharedesc_group
 * @warning                 Descriptor valid on platforms
 *                          with support for SEC ERA 4.
 *
 * @param[in,out] descbuf   Pointer to descriptor-under-construction buffer.
 * @param[in,out] bufsize   Points to size to be updated at completion.
 * @param[in] pdb_opts      PDB Options Byte.
 * @param[in] pn            PDB Packet Number.
 * @param[in] cipherdata    Pointer to block cipher transform definitions.
 * @param[in] protinfo      Protocol information: OP_PCL_WIMAX_OFDM/OFDMA.
 */
void cnstr_shdsc_wimax_decap(uint32_t *descbuf, unsigned *bufsize,
			     uint8_t pdb_opts, uint32_t pn, uint16_t ar_len,
			     uint16_t protinfo, struct alginfo *cipherdata)
{
	struct wimax_decap_pdb pdb;
	struct program prg;
	struct program *program = &prg;
	uint32_t startidx;

	LABEL(seq_ptr);
	LABEL(crc8);
	REFERENCE(pseq_out_ptr);
	REFERENCE(pcrc8);

	memset(&pdb, 0x00, sizeof(struct wimax_decap_pdb));
	pdb.options = pdb_opts;
	pdb.pn = pn;
	pdb.antireplay_len = ar_len;
	pdb.iv_flags = WIMAX_PDB_B0;
	pdb.ctr_flags = WIMAX_PDB_CTR;

	startidx = sizeof(struct wimax_decap_pdb) >> 2;

	PROGRAM_CNTXT_INIT(descbuf, 0);
	SHR_HDR(SHR_NEVER, ++startidx, WITH(0));
	{
		ENDIAN_DATA((uint8_t *)&pdb, sizeof(struct wimax_decap_pdb));
		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen,
		    WITH(IMMED));
		PROTOCOL(OP_TYPE_DECAP_PROTOCOL, OP_PCLID_WIMAX, protinfo);
		SET_LABEL(seq_ptr);
		SEQOUTPTR(0, 8, WITH(RTO));

		/*
		 * Make Input Sequence point to decapsulation Output Frame
		 * in order to load and update Generic Mac Header.
		 * SEC workflow is as follows:
		 *     1. Copy Shared Descriptor Pointer, SEQOUTPTR,
		 *        Output Pointer, Output Length in MATH0, MATH1, MATH2
		 *        registers.
		 *     2. Transform SEQOUTPTR in SEQINPTR.
		 *     3. Load in MATH2 a local conditional JUMP with offset
		 *        targetting the SEQLOAD command.
		 *     4. Copy MATH0, MATH1, MATH2 contents
		 *        at the first word before seq_ptr LABEL.
		 *     5. JUMP to seq_ptr LABEL, run SEQINPTR, Output Pointer,
		 *        Output Length and then JUMP to SEQLOAD.
		 */
		MOVE(DESCBUF, 49 * 4, MATH0, 0, IMM(20), WITH(WAITCOMP));
		MATHB(MATH0, AND, IMM(0xfffffffff7ffffff), MATH0, SIZE(8), 0);
		LOAD(IMM(0xa0000005), MATH2, 4, 4, WITH(0));
		MOVE(MATH0, 0, DESCBUF, 13 * 4, IMM(24), WITH(WAITCOMP));
		pseq_out_ptr = JUMP(IMM(seq_ptr), LOCAL_JUMP, ALL_TRUE,
				    WITH(0));

		SEQLOAD(MATH0, 0, 8, WITH(0));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));

		/* Set Encryption Control bit. */
		MATHB(MATH0, AND, IMM(0xbfffffffffffffff), MATH0, SIZE(8), 0);

		/* Update Length field. */
		MOVE(DESCBUF, 0, MATH1, 0, IMM(8), WITH(0));
		MATHB(MATH0, SUB, IMM(0x00000c0000000000), MATH0, SIZE(8), 0);
		MATHB(MATH1, AND, ONE, NONE, SIZE(8), 0);

		/* Update Length field if FCS is enabled */
		pcrc8 = JUMP(IMM(crc8), LOCAL_JUMP, ALL_TRUE, WITH(MATH_Z));
		MATHB(MATH0, SUB, IMM(0x0000040000000000), MATH0, SIZE(8), 0);

		/*
		 * Compute the CRC-8-ATM value for the first five bytes
		 * of the header and insert the result into the sixth
		 * MATH0 byte field.
		 */
		SET_LABEL(crc8);
		LOAD(IMM(LDST_SRCDST_WORD_CLRW |
			 CLRW_CLR_C1MODE |
			 CLRW_CLR_C2MODE |
			 CLRW_CLR_C2DATAS |
			 CLRW_CLR_C2CTX |
			 CLRW_CLR_C2KEY |
			 CLRW_RESET_CLS2_CHA |
			 CLRW_RESET_CLS1_CHA),
		     CLRW, 0, 4, WITH(0));
		KEY(KEY2, 0, IMM(0x07000000), 2, WITH(IMMED));
		ALG_OPERATION(OP_ALG_ALGSEL_CRC,
			      OP_ALG_AAI_CUST_POLY | OP_ALG_AAI_DIS,
			      OP_ALG_AS_UPDATE, ICV_CHECK_DISABLE,
			      OP_ALG_ENCRYPT);
		MOVE(MATH0, 0, IFIFOAB2, 0, IMM(5), WITH(LAST1));
		MOVE(CONTEXT2, 0, MATH1, 0, IMM(4), WITH(WAITCOMP));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CLASS2));
		MOVE(MATH1, 0, MATH0, 5, IMM(1), WITH(WAITCOMP));

		/* Rewrite decapsulation Generic Mac Header. */
		SEQSTORE(MATH0, 0, 8, WITH(0));
	}
	PATCH_JUMP(pseq_out_ptr, seq_ptr);
	PATCH_JUMP(pcrc8, crc8);
	*bufsize = PROGRAM_FINALIZE();
}

/*
 * Function for appending the portion of a PDCP Control Plane shared descriptor
 * which performs NULL encryption and integrity (i.e. copies the input frame
 * to the output frame, appending 32 bits of zeros at the end (MAC-I for
 * NULL integrity).
 */
static inline int pdcp_insert_cplane_null_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	LABEL(local_offset);
	REFERENCE(move_cmd_read_descbuf);
	REFERENCE(move_cmd_write_descbuf);

	if (rta_sec_era > RTA_SEC_ERA_2) {
		MATHB(SEQINSZ, ADD, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		MATHB(SEQINSZ, dir == OP_TYPE_ENCAP_PROTOCOL ? ADD : SUB,
		      IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4), WITH(0));
	} else {
		MATHB(SEQINSZ, ADD, ONE, VSEQINSZ, SIZE(4), WITH(0));
		MATHB(VSEQINSZ, SUB, ONE, VSEQINSZ, SIZE(4), WITH(0));

		if (dir == OP_TYPE_ENCAP_PROTOCOL) {
			MATHB(SEQINSZ, ADD, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ,
			      SIZE(4), WITH(0));
			MATHB(VSEQINSZ, SUB, ONE, MATH0, SIZE(4), WITH(0));
		} else {
			MATHB(VSEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), VSEQINSZ,
			      SIZE(4), WITH(0));
			MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ,
			      SIZE(4), WITH(0));
			MATHB(VSEQOUTSZ, SUB, ONE, MATH0, SIZE(4), WITH(0));
		}

		MATHB(MATH0, ADD, ONE, MATH0, SIZE(4), WITH(0));

		/*
		 * Since MOVELEN is available only starting with
		 * SEC ERA 3, use poor man's MOVELEN: create a MOVE
		 * command dynamically by writing the length from M1 by
		 * OR-ing the command in the M1 register and MOVE the
		 * result into the descriptor buffer. Care must be taken
		 * wrt. the location of the command because of SEC
		 * pipelining. The actual MOVEs are written at the end
		 * of the descriptor due to calculations needed on the
		 * offset in the descriptor for the MOVE command.
		 */
		move_cmd_read_descbuf = MOVE(DESCBUF, 0, MATH0, 0, IMM(6),
					     WITH(0));
		move_cmd_write_descbuf = MOVE(MATH0, 0, DESCBUF, 0, IMM(8),
					      WITH(WAITCOMP));
	}
	MATHB(VSEQINSZ, SUB, IMM(PDCP_NULL_MAX_FRAME_LEN), NONE, SIZE(4),
	      WITH(0));
	JUMP(IMM(PDCP_MAX_FRAME_LEN_STATUS), HALT_STATUS, ALL_FALSE, MATH_N);

	if (rta_sec_era > RTA_SEC_ERA_2) {
		if (dir == OP_TYPE_ENCAP_PROTOCOL)
			MATHB(VSEQINSZ, ADD, ZERO, MATH0, SIZE(4), WITH(0));
		else
			MATHB(VSEQOUTSZ, ADD, ZERO, MATH0, SIZE(4), WITH(0));
	}
	SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
	SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));

	if (rta_sec_era > RTA_SEC_ERA_2) {
		MOVE(AB1, 0, OFIFO, 0, MATH0, WITH(0));
	} else {
		SET_LABEL(local_offset);

		/* Shut off automatic Info FIFO entries */
		LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0, WITH(0));
		/* Placeholder for MOVE command with length from M1 register */
		MOVE(IFIFOAB1, 0, OFIFO, 0, IMM(0), WITH(0));
		/* Enable automatic Info FIFO entries */
		LOAD(IMM(0), DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0, WITH(0));
	}

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		MATHB(MATH1, XOR, MATH1, MATH0, SIZE(8), WITH(0));
		MOVE(MATH0, 0, OFIFO, 0, IMM(4), WITH(0));
	}

	if (rta_sec_era < RTA_SEC_ERA_3) {
		PATCH_MOVE(move_cmd_read_descbuf, local_offset);
		PATCH_MOVE(move_cmd_write_descbuf, local_offset);
	}

	return 0;
}

static inline int pdcp_insert_uplane_null_op(struct program *program,
		struct alginfo *cipherdata,
		unsigned dir)
{
	LABEL(local_offset);
	REFERENCE(move_cmd_read_descbuf);
	REFERENCE(move_cmd_write_descbuf);

	if (rta_sec_era > RTA_SEC_ERA_2) {
		MATHB(SEQINSZ, ADD, ZERO, VSEQINSZ,  SIZE(4), WITH(0));
		MATHB(SEQINSZ, ADD, ZERO, VSEQOUTSZ,  SIZE(4), WITH(0));
	} else {
		MATHB(SEQINSZ, ADD, ONE, VSEQINSZ,  SIZE(4), WITH(0));
		MATHB(VSEQINSZ, SUB, ONE, VSEQINSZ,  SIZE(4), 0);
		MATHB(SEQINSZ, ADD, ONE, VSEQOUTSZ,  SIZE(4), WITH(0));
		MATHB(VSEQOUTSZ, SUB, ONE, VSEQOUTSZ,  SIZE(4), WITH(0));
		MATHB(VSEQINSZ, SUB, ONE, MATH0,  SIZE(4), WITH(0));
		MATHB(MATH0, ADD, ONE, MATH0,  SIZE(4), WITH(0));

		/*
		 * Since MOVELEN is available only starting with
		 * SEC ERA 3, use poor man's MOVELEN: create a MOVE
		 * command dynamically by writing the length from M1 by
		 * OR-ing the command in the M1 register and MOVE the
		 * result into the descriptor buffer. Care must be taken
		 * wrt. the location of the command because of SEC
		 * pipelining. The actual MOVEs are written at the end
		 * of the descriptor due to calculations needed on the
		 * offset in the descriptor for the MOVE command.
		 */
		move_cmd_read_descbuf = MOVE(DESCBUF, 0, MATH0, 0, IMM(6),
					     WITH(0));
		move_cmd_write_descbuf = MOVE(MATH0, 0, DESCBUF, 0, IMM(8),
					      WITH(WAITCOMP));
	}
	MATHB(SEQINSZ, SUB, IMM(PDCP_NULL_MAX_FRAME_LEN), NONE,  SIZE(4),
	      WITH(IFB));
	JUMP(IMM(PDCP_MAX_FRAME_LEN_STATUS), HALT_STATUS, ALL_FALSE, MATH_N);

	if (rta_sec_era > RTA_SEC_ERA_2)
		MATHB(VSEQINSZ, ADD, ZERO, MATH0,  SIZE(4), WITH(0));

	SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));
	if (rta_sec_era > RTA_SEC_ERA_2) {
		MOVE(AB1, 0, OFIFO, 0, MATH0, WITH(0));
	} else {
		SET_LABEL(local_offset);

		/* Shut off automatic Info FIFO entries */
		LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0, WITH(0));

		/* Placeholder for MOVE command with length from M0 register */
		MOVE(IFIFOAB1, 0, OFIFO, 0, IMM(0), WITH(0));

		/* Enable automatic Info FIFO entries */
		LOAD(IMM(0), DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0, WITH(0));
	}

	SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));

	if (rta_sec_era < RTA_SEC_ERA_3) {
		PATCH_MOVE(move_cmd_read_descbuf, local_offset);
		PATCH_MOVE(move_cmd_write_descbuf, local_offset);
	}
	return 0;
}

static inline int pdcp_insert_cplane_int_only_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	LABEL(local_offset);
	REFERENCE(move_cmd_read_descbuf);
	REFERENCE(move_cmd_write_descbuf);

	switch (authdata->algtype) {
	case PDCP_AUTH_TYPE_SNOW:
		/* Insert Auth Key */
		KEY(KEY2, 0, PTR(authdata->key), authdata->keylen,
		    0);
		SEQLOAD(MATH0, 7, 1, WITH(0));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));

		if (rta_sec_era > RTA_SEC_ERA_2 ||
		    (rta_sec_era == RTA_SEC_ERA_2 &&
				   era_2_sw_hfn_override == 0)) {
			SEQINPTR(0, 1, WITH(RTO));
		} else {
			SEQINPTR(0, 5, WITH(RTO));
			SEQFIFOLOAD(SKIP, 4, WITH(0));
		}

		MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1,  SIZE(8),
		      WITH(IFB));
		MATHB(MATH1, SHLD, MATH1, MATH1,  SIZE(8), WITH(0));
		MOVE(DESCBUF, 8, MATH2, 0, IMM(8), WITH(WAITCOMP));
		MATHB(MATH2, AND, IMM(PDCP_BEARER_MASK), MATH2, SIZE(8),
		      WITH(0));
		MOVE(DESCBUF, 0x0C, MATH3, 0, IMM(4), WITH(WAITCOMP));
		MATHB(MATH3, AND, IMM(PDCP_DIR_MASK), MATH3, SIZE(8),
		      WITH(0));
		MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));
		MOVE(MATH2, 0, CONTEXT2, 0, IMM(0x0C), WITH(WAITCOMP));

		if (dir == OP_TYPE_DECAP_PROTOCOL) {
			MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), MATH1, SIZE(4),
			      WITH(0));
		} else {
			if (rta_sec_era > RTA_SEC_ERA_2) {
				MATHB(SEQINSZ, SUB, ZERO, MATH1, SIZE(4),
				      WITH(0));
			} else {
				MATHB(SEQINSZ, ADD, ONE, MATH1, SIZE(4),
				      WITH(0));
				MATHB(MATH1, SUB, ONE, MATH1, SIZE(4),
				      WITH(0));
			}
		}

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MATHB(MATH1, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
			MATHB(MATH1, SUB, ZERO, VSEQOUTSZ, SIZE(4), WITH(0));
		} else {
			MATHB(ZERO, ADD, MATH1, VSEQINSZ, SIZE(4), WITH(0));
			MATHB(ZERO, ADD, MATH1, VSEQOUTSZ, SIZE(4), WITH(0));

			/*
			 * Since MOVELEN is available only starting with
			 * SEC ERA 3, use poor man's MOVELEN: create a MOVE
			 * command dynamically by writing the length from M1 by
			 * OR-ing the command in the M1 register and MOVE the
			 * result into the descriptor buffer. Care must be taken
			 * wrt. the location of the command because of SEC
			 * pipelining. The actual MOVEs are written at the end
			 * of the descriptor due to calculations needed on the
			 * offset in the descriptor for the MOVE command.
			 */
			move_cmd_read_descbuf = MOVE(DESCBUF, 0, MATH1, 0,
						     IMM(6), WITH(0));
			move_cmd_write_descbuf = MOVE(MATH1, 0, DESCBUF, 0,
						     IMM(8), WITH(WAITCOMP));
		}

		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F9, OP_ALG_AAI_F9,
			      OP_ALG_AS_INITFINAL,
			      dir == OP_TYPE_ENCAP_PROTOCOL ?
				     ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
			      OP_ALG_ENCRYPT);

		if (rta_sec_era > RTA_SEC_ERA_2) {
			SEQFIFOLOAD(MSGINSNOOP, 0,
				    WITH(VLF | LAST1 | LAST2 | FLUSH1));
			MOVE(AB1, 0, OFIFO, 0, MATH1, WITH(0));
		} else {
			SEQFIFOLOAD(MSGINSNOOP, 0,
				    WITH(VLF | LAST1 | LAST2 | FLUSH1));
			SET_LABEL(local_offset);

			/* Shut off automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0,
			     WITH(0));
			/*
			 * Placeholder for MOVE command with length from M1
			 * register
			 */
			MOVE(IFIFOAB1, 0, OFIFO, 0, IMM(0), WITH(0));
			/* Enable automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0,
			     WITH(0));
		}

		if (dir == OP_TYPE_DECAP_PROTOCOL)
			SEQFIFOLOAD(ICV2, 4, WITH(LAST2));
		else
			SEQSTORE(CONTEXT2, 0, 4, WITH(0));

		break;

	case PDCP_AUTH_TYPE_AES:
		/* Insert Auth Key */
		KEY(KEY1, 0, PTR(authdata->key), authdata->keylen, WITH(0));
		SEQLOAD(MATH0, 7, 1, WITH(0));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
		if (rta_sec_era > RTA_SEC_ERA_2 ||
		    (rta_sec_era == RTA_SEC_ERA_2 &&
		     era_2_sw_hfn_override == 0)) {
			SEQINPTR(0, 1, WITH(RTO));
		} else {
			SEQINPTR(0, 5, WITH(RTO));
			SEQFIFOLOAD(SKIP, 4, WITH(0));
		}

		MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
		MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
		MOVE(DESCBUF, 8, MATH2, 0, IMM(8), WITH(WAITCOMP));
		MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));
		MOVE(MATH2, 0, IFIFOAB1, 0, IMM(8), WITH(0));
		if (dir == OP_TYPE_DECAP_PROTOCOL) {
			MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), MATH1,
			      SIZE(4), WITH(0));
		} else {
			if (rta_sec_era > RTA_SEC_ERA_2) {
				MATHB(SEQINSZ, SUB, ZERO, MATH1, SIZE(4),
				      WITH(0));
			} else {
				MATHB(SEQINSZ, ADD, ONE, MATH1, SIZE(4),
				      WITH(0));
				MATHB(MATH1, SUB, ONE, MATH1, SIZE(4),
				      WITH(0));
			}
		}

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MATHB(MATH1, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
			MATHB(MATH1, SUB, ZERO, VSEQOUTSZ, SIZE(4), WITH(0));
		} else {
			MATHB(ZERO, ADD, MATH1, VSEQINSZ, SIZE(4), WITH(0));
			MATHB(ZERO, ADD, MATH1, VSEQOUTSZ, SIZE(4), WITH(0));

			/*
			 * Since MOVELEN is available only starting with
			 * SEC ERA 3, use poor man's MOVELEN: create a MOVE
			 * command dynamically by writing the length from M1 by
			 * OR-ing the command in the M1 register and MOVE the
			 * result into the descriptor buffer. Care must be taken
			 * wrt. the location of the command because of SEC
			 * pipelining. The actual MOVEs are written at the end
			 * of the descriptor due to calculations needed on the
			 * offset in the descriptor for the MOVE command.
			 */
			move_cmd_read_descbuf = MOVE(DESCBUF, 0, MATH1, 0,
						     IMM(6), WITH(0));
			move_cmd_write_descbuf = MOVE(MATH1, 0, DESCBUF, 0,
						      IMM(8), WITH(WAITCOMP));
		}
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		ALG_OPERATION(OP_ALG_ALGSEL_AES,
			      OP_ALG_AAI_CMAC,
			      OP_ALG_AS_INITFINAL,
			      dir == OP_TYPE_ENCAP_PROTOCOL ?
				     ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
			      OP_ALG_ENCRYPT);

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MOVE(AB2, 0, OFIFO, 0, MATH1, WITH(0));
			SEQFIFOLOAD(MSGINSNOOP, 0,
				    WITH(VLF | LAST1 | LAST2 | FLUSH1));
		} else {
			SEQFIFOLOAD(MSGINSNOOP, 0,
				    WITH(VLF | LAST1 | LAST2 | FLUSH1));
			SET_LABEL(local_offset);

			/* Shut off automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0,
			     WITH(0));

			/*
			 * Placeholder for MOVE command with length from
			 * M1 register
			 * */
			MOVE(IFIFOAB2, 0, OFIFO, 0, IMM(0), WITH(0));

			/* Enable automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0,
			     WITH(0));
		}

		if (dir == OP_TYPE_DECAP_PROTOCOL)
			SEQFIFOLOAD(ICV1, 4, WITH(LAST1 | FLUSH1));
		else
			SEQSTORE(CONTEXT1, 0, 4, WITH(0));

		break;

	case PDCP_AUTH_TYPE_ZUC:
		if (rta_sec_era < RTA_SEC_ERA_5) {
			pr_debug("Invalid era for selected algorithm\n");
			return -1;
		}
		/* Insert Auth Key */
		KEY(KEY2, 0, PTR(authdata->key), authdata->keylen,
		    WITH(0));
		SEQLOAD(MATH0, 7, 1, WITH(0));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
		SEQINPTR(0, 1, WITH(RTO));
		MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
		MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
		MOVE(DESCBUF, 8, MATH2, 8, IMM(8), WITH(WAITCOMP));
		MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));
		MOVE(MATH2, 0, CONTEXT2, 0, IMM(8), WITH(0));

		if (dir == OP_TYPE_DECAP_PROTOCOL)
			MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), MATH1,
			      SIZE(4), WITH(0));
		else
			MATHB(SEQINSZ, SUB, ZERO, MATH1, SIZE(4), WITH(0));

		MATHB(MATH1, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		MATHB(MATH1, SUB, ZERO, VSEQOUTSZ, SIZE(4), WITH(0));
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		ALG_OPERATION(OP_ALG_ALGSEL_ZUCA,
			      OP_ALG_AAI_F9,
			      OP_ALG_AS_INITFINAL,
			      dir == OP_TYPE_ENCAP_PROTOCOL ?
				     ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
			      OP_ALG_ENCRYPT);
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST1 | LAST2 | FLUSH1));
		MOVE(AB1, 0, OFIFO, 0, MATH1, WITH(0));

		if (dir == OP_TYPE_DECAP_PROTOCOL)
			SEQFIFOLOAD(ICV2, 4, WITH(LAST2));
		else
			SEQSTORE(CONTEXT2, 0, 4, WITH(0));

		break;

	default:
		pr_debug("%s: Invalid integrity algorithm selected: %d\n",
			 "pdcp_insert_cplane_int_only_op",
			 authdata->algtype);
		return -1;
	}

	if (rta_sec_era < RTA_SEC_ERA_3) {
		PATCH_MOVE(move_cmd_read_descbuf, local_offset);
		PATCH_MOVE(move_cmd_write_descbuf, local_offset);
	}

	return 0;
}

static inline int pdcp_insert_cplane_enc_only_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	/* Insert Cipher Key */
	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
	SEQLOAD(MATH0, 7, 1, WITH(0));
	JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
	MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
	SEQSTORE(MATH0, 7, 1, WITH(0));
	MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
	MOVE(DESCBUF, 8, MATH2, 8, IMM(8), WITH(WAITCOMP));
	MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));

	switch (cipherdata->algtype) {
	case PDCP_CIPHER_TYPE_SNOW:
		MOVE(MATH2, 0, CONTEXT1, 0, IMM(8), WITH(WAITCOMP));

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		} else {
			MATHB(SEQINSZ, SUB, ONE, MATH1, SIZE(4), WITH(0));
			MATHB(MATH1, ADD, ONE, VSEQINSZ, SIZE(4), WITH(0));
		}

		MATHB(SEQINSZ, dir == OP_TYPE_ENCAP_PROTOCOL ? ADD : SUB,
		      IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4), WITH(0));
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F8,
			      OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE,
			      dir == OP_TYPE_ENCAP_PROTOCOL ?
					OP_ALG_ENCRYPT : OP_ALG_DECRYPT);

		if (dir == OP_TYPE_ENCAP_PROTOCOL) {
			SEQFIFOLOAD(MSG1, 0, WITH(VLF));
			FIFOLOAD(MSG1, IMM(PDCP_NULL_INT_MAC_I_VAL), 4,
				 WITH(LAST1 | FLUSH1));
		} else {
			SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));
		}
		break;

	case PDCP_CIPHER_TYPE_AES:
		MOVE(MATH2, 0, CONTEXT1, 0x10, IMM(0x10), WITH(WAITCOMP));

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		} else {
			MATHB(SEQINSZ, SUB, ONE, MATH1, SIZE(4), WITH(0));
			MATHB(MATH1, ADD, ONE, VSEQINSZ, SIZE(4), WITH(0));
		}

		MATHB(SEQINSZ,
		      dir == OP_TYPE_ENCAP_PROTOCOL ? ADD : SUB,
			     IMM(PDCP_MAC_I_LEN),
		      VSEQOUTSZ,
		      SIZE(4),
		      0);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		ALG_OPERATION(OP_ALG_ALGSEL_AES,
			      OP_ALG_AAI_CTR,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      dir == OP_TYPE_ENCAP_PROTOCOL ?
					OP_ALG_ENCRYPT : OP_ALG_DECRYPT);

		if (dir == OP_TYPE_ENCAP_PROTOCOL) {
			SEQFIFOLOAD(MSG1, 0, WITH(VLF));
			FIFOLOAD(MSG1, IMM(PDCP_NULL_INT_MAC_I_VAL), 4,
				 WITH(LAST1 | FLUSH1));
		} else {
			SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));
		}

		break;

	case PDCP_CIPHER_TYPE_ZUC:
		if (rta_sec_era < RTA_SEC_ERA_5) {
			pr_debug("Invalid era for selected algorithm\n");
			return -1;
		}

		MOVE(MATH2, 0, CONTEXT1, 0, IMM(0x08), WITH(0));
		MOVE(MATH2, 0, CONTEXT1, 0x08, IMM(0x08), WITH(WAITCOMP));
		MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		MATHB(SEQINSZ,
		      dir == OP_TYPE_ENCAP_PROTOCOL ? ADD : SUB,
			     IMM(PDCP_MAC_I_LEN),
		      VSEQOUTSZ,
		      SIZE(4),
		      0);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		ALG_OPERATION(OP_ALG_ALGSEL_ZUCE,
			      OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      dir);
		if (dir == OP_TYPE_ENCAP_PROTOCOL) {
			SEQFIFOLOAD(MSG1, 0, WITH(VLF));
			FIFOLOAD(MSG1, IMM(PDCP_NULL_INT_MAC_I_VAL), 4,
				 WITH(LAST1 | FLUSH1));

		} else {
			SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));
		}

		break;

	default:
		pr_debug("%s: Invalid encrypt algorithm selected: %d\n",
			 "pdcp_insert_cplane_enc_only_op",
			 cipherdata->algtype);
		return -1;
	}

	return 0;
}

static inline int pdcp_insert_cplane_acc_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_hfn_override)
{
	/* Insert Auth Key */
	KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, WITH(0));

	/* Insert Cipher Key */
	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
	PROTOCOL(dir, OP_PCLID_LTE_PDCP_CTRL, cipherdata->algtype);

	return 0;
}

static inline int pdcp_insert_cplane_snow_aes_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	LABEL(back_to_sd_offset);
	LABEL(end_desc);
	LABEL(local_offset);
	LABEL(jump_to_beginning);
	LABEL(fifo_load_mac_i_offset);
	REFERENCE(seqin_ptr_read);
	REFERENCE(seqin_ptr_write);
	REFERENCE(seq_out_read);
	REFERENCE(jump_back_to_sd_cmd);
	REFERENCE(move_mac_i_to_desc_buf);

	SEQLOAD(MATH0, 7, 1, WITH(0));
	JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
	MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
	MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
	MOVE(DESCBUF, 4, MATH2, 0, IMM(0x08), WITH(WAITCOMP));
	MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));
	SEQSTORE(MATH0, 7, 1, WITH(0));
	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		if (rta_sec_era > RTA_SEC_ERA_2 ||
		    (rta_sec_era == RTA_SEC_ERA_2 &&
				   era_2_sw_hfn_override == 0)) {
			SEQINPTR(0, 1, WITH(RTO));
		} else {
			SEQINPTR(0, 5, WITH(RTO));
			SEQFIFOLOAD(SKIP, 4, WITH(0));
		}
		KEY(KEY1, 0, PTR(authdata->key), authdata->keylen, WITH(0));
		MOVE(MATH2, 0, IFIFOAB1, 0, IMM(0x08), WITH(0));

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
			MATHB(SEQINSZ, SUB, ZERO, MATH1, SIZE(4), WITH(0));
			MATHB(VSEQINSZ, ADD, IMM(PDCP_MAC_I_LEN - 1),
			      VSEQOUTSZ, SIZE(4), 0);
		} else {
			MATHB(SEQINSZ, SUB, MATH3, VSEQINSZ, SIZE(4), WITH(0));
			MATHB(VSEQINSZ, ADD, IMM(PDCP_MAC_I_LEN - 1), VSEQOUTSZ,
			      SIZE(4), 0);
			/*
			 * Note: Although the calculations below might seem a
			 * little off, the logic is the following:
			 *
			 * - SEQ IN PTR RTO below needs the full length of the
			 *   frame; in case of P4080_REV_2_HFN_OV_WORKAROUND,
			 *   this means the length of the frame to be processed
			 *   + 4 bytes (the HFN override flag and value).
			 *   The length of the frame to be processed minus 1
			 *   byte is in the VSIL register (because
			 *   VSIL = SIL + 3, due to 1 byte, the header being
			 *   already written by the SEQ STORE above). So for
			 *   calculating the length to use in RTO, I add one
			 *   to the VSIL value in order to obtain the total
			 *   frame length. This helps in case of P4080 which
			 *   can have the value 0 as an operand in a MATH
			 *   command only as SRC1 When the HFN override
			 *   workaround is not enabled, the length of the
			 *   frame is given by the SIL register; the
			 *   calculation is similar to the one in the SEC 4.2
			 *   and SEC 5.3 cases.
			 */
			if (era_2_sw_hfn_override)
				MATHB(VSEQOUTSZ, ADD, ONE, MATH1, SIZE(4),
				      WITH(0));
			else
				MATHB(SEQINSZ, ADD, MATH3, MATH1, SIZE(4),
				      WITH(0));
		}
		/*
		 * Placeholder for filling the length in
		 * SEQIN PTR RTO below
		 */
		seqin_ptr_read = MOVE(DESCBUF, 0, MATH1, 0, IMM(6), WITH(0));
		seqin_ptr_write = MOVE(MATH1, 0, DESCBUF, 0, IMM(8),
				       WITH(WAITCOMP));
		ALG_OPERATION(OP_ALG_ALGSEL_AES,
			      OP_ALG_AAI_CMAC,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_DECRYPT);
		SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));
		MOVE(CONTEXT1, 0, MATH3, 0, IMM(4), WITH(WAITCOMP));
		if (rta_sec_era <= RTA_SEC_ERA_3)
			LOAD(IMM(CLRW_CLR_C1KEY |
				 CLRW_CLR_C1CTX |
				 CLRW_CLR_C1ICV |
				 CLRW_CLR_C1DATAS |
				 CLRW_CLR_C1MODE),
			     CLRW, 0, 4, WITH(0));
		else
			LOAD(IMM(CLRW_RESET_CLS1_CHA |
				 CLRW_CLR_C1KEY |
				 CLRW_CLR_C1CTX |
				 CLRW_CLR_C1ICV |
				 CLRW_CLR_C1DATAS |
				 CLRW_CLR_C1MODE),
			     CLRW, 0, 4, WITH(0));

		if (rta_sec_era <= RTA_SEC_ERA_3)
			LOAD(IMM(CCTRL_RESET_CHA_ALL), CCTRL, 0, 4, WITH(0));

		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
		SET_LABEL(local_offset);
		MOVE(MATH2, 0, CONTEXT1, 0, IMM(8), WITH(0));
		SEQINPTR(0, 0, WITH(RTO));

		if (rta_sec_era == RTA_SEC_ERA_2 && era_2_sw_hfn_override) {
			SEQFIFOLOAD(SKIP, 5, WITH(0));
			MATHB(SEQINSZ, ADD, ONE, SEQINSZ, SIZE(4), WITH(0));
		}

		MATHB(SEQINSZ, SUB, ONE, VSEQINSZ, SIZE(4), WITH(0));
		ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F8,
			      OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_ENCRYPT);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));

		if (rta_sec_era > RTA_SEC_ERA_2 ||
		    (rta_sec_era == RTA_SEC_ERA_2 &&
				   era_2_sw_hfn_override == 0))
			SEQFIFOLOAD(SKIP, 1, WITH(0));

		SEQFIFOLOAD(MSG1, 0, WITH(VLF));
		MOVE(MATH3, 0, IFIFOAB1, 0, IMM(4), WITH(LAST1 | FLUSH1));
		PATCH_MOVE(seqin_ptr_read, local_offset);
		PATCH_MOVE(seqin_ptr_write, local_offset);
	} else {
		MOVE(MATH2, 0, CONTEXT1, 0, IMM(8), WITH(0));

		if (rta_sec_era >= RTA_SEC_ERA_5)
			MOVE(CONTEXT1, 0, CONTEXT2, 0, IMM(8), WITH(0));

		if (rta_sec_era > RTA_SEC_ERA_2)
			MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		else
			MATHB(SEQINSZ, SUB, MATH3, VSEQINSZ, SIZE(4), WITH(0));

		MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));
/*
 * TODO: To be changed when proper support is added in RTA (can't load a
 * command that is also written by RTA (or patch it for that matter).
 * Change when proper RTA support is added.
 */
		if (program->ps)
			WORD(0x168B0004);
		else
			WORD(0x16880404);

		jump_back_to_sd_cmd = JUMP(IMM(0), LOCAL_JUMP, ALL_TRUE,
					   WITH(0));
		/*
		 * Placeholder for command reading  the SEQ OUT command in
		 * JD. Done for rereading the decrypted data and performing
		 * the integrity check
		 */
/*
 * TODO: RTA currently doesn't support patching of length of a MOVE command
 * Thus, it is inserted as a raw word, as per PS setting.
 */
		if (program->ps)
			seq_out_read = MOVE(DESCBUF, 0, MATH1, 0, IMM(20),
					    WITH(WAITCOMP));
		else
			seq_out_read = MOVE(DESCBUF, 0, MATH1, 0, IMM(16),
					    WITH(WAITCOMP));

		MATHB(MATH1, XOR, IMM(CMD_SEQ_IN_PTR ^ CMD_SEQ_OUT_PTR), MATH1,
		      SIZE(4), WITH(0));
		/* Placeholder for overwriting the SEQ IN  with SEQ OUT */
/*
 * TODO: RTA currently doesn't support patching of length of a MOVE command
 * Thus, it is inserted as a raw word, as per PS setting.
 */
		if (program->ps)
			MOVE(MATH1, 0, DESCBUF, 0, IMM(24), WITH(0));
		else
			MOVE(MATH1, 0, DESCBUF, 0, IMM(20), WITH(0));

		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));

		if (rta_sec_era >= RTA_SEC_ERA_5)
			MOVE(CONTEXT1, 0, CONTEXT2, 0, IMM(8), WITH(0));
		else
			MOVE(CONTEXT1, 0, MATH3, 0, IMM(8), WITH(0));

		ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F8,
			      OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_DECRYPT);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF | CONT));
		SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));

		if (rta_sec_era <= RTA_SEC_ERA_3)
			move_mac_i_to_desc_buf = MOVE(OFIFO, 0, DESCBUF, 0,
						      IMM(4), WITH(0));
		else
			MOVE(OFIFO, 0, MATH3, 0, IMM(4), WITH(0));

		if (rta_sec_era <= RTA_SEC_ERA_3)
			LOAD(IMM(CLRW_CLR_C1KEY |
				 CLRW_CLR_C1CTX |
				 CLRW_CLR_C1ICV |
				 CLRW_CLR_C1DATAS |
				 CLRW_CLR_C1MODE),
			     CLRW, 0, 4, WITH(0));
		else
			LOAD(IMM(CLRW_RESET_CLS1_CHA |
				 CLRW_CLR_C1KEY |
				 CLRW_CLR_C1CTX |
				 CLRW_CLR_C1ICV |
				 CLRW_CLR_C1DATAS |
				 CLRW_CLR_C1MODE),
			     CLRW, 0, 4, WITH(0));

		KEY(KEY1, 0, PTR(authdata->key), authdata->keylen, WITH(0));
		/*
		 * Placeholder for jump in SD for executing the new SEQ IN PTR
		 * command (which is actually the old SEQ OUT PTR command
		 * copied over from JD.
		 */
		SET_LABEL(jump_to_beginning);
		JUMP(IMM(1 - jump_to_beginning), LOCAL_JUMP, ALL_TRUE, WITH(0));
		SET_LABEL(back_to_sd_offset);
		ALG_OPERATION(OP_ALG_ALGSEL_AES,
			      OP_ALG_AAI_CMAC,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_ENABLE,
			      OP_ALG_DECRYPT);

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		} else {
			MATHB(SEQINSZ, SUB, ONE, VSEQINSZ, SIZE(4), WITH(0));
			MATHB(VSEQINSZ, ADD, ONE, VSEQINSZ, SIZE(4), WITH(0));
		}

		if (rta_sec_era <= RTA_SEC_ERA_3)
			MOVE(MATH3, 0, IFIFOAB1, 0, IMM(8), WITH(0));
		else
			MOVE(CONTEXT2, 0, IFIFOAB1, 0, IMM(8), WITH(0));

		SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));

		if (rta_sec_era >= RTA_SEC_ERA_5) {
			LOAD(IMM(NFIFOENTRY_STYPE_ALTSOURCE |
				 NFIFOENTRY_DEST_CLASS1 |
				 NFIFOENTRY_DTYPE_ICV |
				 NFIFOENTRY_LC1 |
				 NFIFOENTRY_FC1 | 4), NFIFO_SZL, 0, 4, WITH(0));
			MOVE(MATH3, 0, ALTSOURCE, 0, IMM(4), WITH(0));
		} else {
			SET_LABEL(fifo_load_mac_i_offset);
			FIFOLOAD(ICV1, IMM(fifo_load_mac_i_offset), 4,
				 WITH(LAST1 | FLUSH1));
		}

		SET_LABEL(end_desc);

		if (!program->ps) {
			PATCH_MOVE(seq_out_read, end_desc + 1);
			PATCH_JUMP(jump_back_to_sd_cmd,
				   back_to_sd_offset + jump_back_to_sd_cmd - 5);

			if (rta_sec_era <= RTA_SEC_ERA_3)
				PATCH_MOVE(move_mac_i_to_desc_buf,
					   fifo_load_mac_i_offset + 1);
		} else {
			PATCH_MOVE(seq_out_read, end_desc + 2);
			PATCH_JUMP(jump_back_to_sd_cmd,
				   back_to_sd_offset + jump_back_to_sd_cmd - 5);

			if (rta_sec_era <= RTA_SEC_ERA_3)
				PATCH_MOVE(move_mac_i_to_desc_buf,
					   fifo_load_mac_i_offset + 1);
		}
	}

	return 0;
}

static inline int pdcp_insert_cplane_aes_snow_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	LABEL(local_offset);
	REFERENCE(read_load_nfifo);
	REFERENCE(write_load_nfifo);

	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
	KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, WITH(0));

	if (rta_sec_era <= RTA_SEC_ERA_2)
		MATHB(SEQINSZ, SUB, ONE, VSEQINSZ, SIZE(4), WITH(0));

	SEQLOAD(MATH0, 7, 1, WITH(0));
	JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
	MOVE(MATH0, 7, IFIFOAB2, 0, IMM(1), WITH(0));
	MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
	SEQSTORE(MATH0, 7, 1, WITH(0));
	MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
	MOVE(DESCBUF, 4, MATH2, 0, IMM(8), WITH(WAITCOMP));
	MATHB(MATH1, OR, MATH2, MATH1, SIZE(8), WITH(0));
	MOVE(MATH1, 0, CONTEXT1, 16, IMM(8), WITH(0));
	MOVE(MATH1, 0, CONTEXT2, 0, IMM(4), WITH(0));
	MATHB(MATH1, AND, IMM(low_32b(PDCP_BEARER_MASK)), MATH2,
	      SIZE(4), WITH(0));
	MATHB(MATH1, AND, IMM(high_32b(PDCP_DIR_MASK)), MATH3, SIZE(4),
	      WITH(0));
	MATHB(MATH3, SHLD, MATH3, MATH3, SIZE(8), WITH(0));
	MOVE(MATH2, 4, OFIFO, 0, IMM(12), WITH(0));
	MOVE(OFIFO, 0, CONTEXT2, 4, IMM(12), WITH(0));
	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		MATHB(SEQINSZ, ADD, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));
	} else {
		MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), MATH1, SIZE(4),
		      WITH(0));

		if (rta_sec_era <= RTA_SEC_ERA_2)
			MATHB(ZERO, ADD, MATH1, VSEQOUTSZ, SIZE(4), WITH(0));
		else
			MATHB(MATH1, SUB, ZERO, VSEQOUTSZ, SIZE(4), WITH(0));

		read_load_nfifo = MOVE(DESCBUF, 0, MATH1, 0, IMM(6),
				       WITH(WAITCOMP));
		write_load_nfifo = MOVE(MATH1, 0, DESCBUF, 0, IMM(8),
					WITH(WAITCOMP));
	}

	if (dir == OP_TYPE_ENCAP_PROTOCOL)
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
	else
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF | CONT));

	if (rta_sec_era > RTA_SEC_ERA_2)
		MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));

	ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F9,
		      OP_ALG_AAI_F9,
		      OP_ALG_AS_INITFINAL,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      OP_ALG_DECRYPT);
	SET_LABEL(local_offset);
	ALG_OPERATION(OP_ALG_ALGSEL_AES,
		      OP_ALG_AAI_CTR,
		      OP_ALG_AS_INITFINAL,
		      ICV_CHECK_DISABLE,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     OP_ALG_ENCRYPT : OP_ALG_DECRYPT);

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST2));
		MOVE(CONTEXT2, 0, IFIFOAB1, 0, IMM(4), WITH(LAST1 | FLUSH1));
	} else {
		SEQFIFOLOAD(MSGOUTSNOOP, 0, WITH(LAST2));
		SEQFIFOLOAD(MSG1, 4, WITH(LAST1 | FLUSH1));
		MOVE(OFIFO, 0, MATH0, 0, IMM(4), WITH(WAITCOMP));

		NFIFOADD(IFIFO, ICV2, 4, WITH(LAST2));

		if (rta_sec_era <= RTA_SEC_ERA_2) {
			/* Shut off automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0,
			     WITH(0));
			MOVE(MATH0, 0, IFIFOAB2, 0, IMM(4), WITH(WAITCOMP));
		} else {
			MOVE(MATH0, 0, IFIFO, 0, IMM(4), WITH(WAITCOMP));
		}

		PATCH_MOVE(read_load_nfifo, local_offset);
		PATCH_MOVE(write_load_nfifo, local_offset);
	}

	return 0;
}

static inline int pdcp_insert_cplane_snow_zuc_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	LABEL(keyjump);
	REFERENCE(pkeyjump);

	if (rta_sec_era < RTA_SEC_ERA_5) {
		pr_debug("Invalid era for selected algorithm\n");
		return -1;
	}

	pkeyjump = JUMP(IMM(keyjump), LOCAL_JUMP, ALL_TRUE,
			WITH(SHRD | SELF | BOTH));
	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
	KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, WITH(0));

	SET_LABEL(keyjump);
	SEQLOAD(MATH0, 7, 1, WITH(0));
	JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
	MOVE(MATH0, 7, IFIFOAB2, 0, IMM(1), WITH(0));
	MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
	MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
	MOVE(DESCBUF, 4, MATH2, 0, IMM(8), WITH(WAITCOMP));
	MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));
	MOVE(MATH2, 0, CONTEXT1, 0, IMM(8), WITH(0));
	MOVE(MATH2, 0, CONTEXT2, 0, IMM(8), WITH(WAITCOMP));

	if (dir == OP_TYPE_ENCAP_PROTOCOL)
		MATHB(SEQINSZ, ADD, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));
	else
		MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));

	MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
	SEQSTORE(MATH0, 7, 1, WITH(0));

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST2));
	} else {
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF | CONT));
		SEQFIFOLOAD(MSGOUTSNOOP, 0, WITH(VLF | LAST1 | FLUSH1));
	}

	ALG_OPERATION(OP_ALG_ALGSEL_ZUCA,
		      OP_ALG_AAI_F9,
		      OP_ALG_AS_INITFINAL,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      OP_ALG_ENCRYPT);

	ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F8,
		      OP_ALG_AAI_F8,
		      OP_ALG_AS_INITFINAL,
		      ICV_CHECK_DISABLE,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     OP_ALG_ENCRYPT : OP_ALG_DECRYPT);
	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		MOVE(CONTEXT2, 0, IFIFOAB1, 0, IMM(4), WITH(LAST1 | FLUSH1));
	} else {
		/* Save ICV */
		MOVE(OFIFO, 0, MATH0, 0, IMM(4), WITH(0));
		LOAD(IMM(NFIFOENTRY_STYPE_ALTSOURCE |
			 NFIFOENTRY_DEST_CLASS2 |
			 NFIFOENTRY_DTYPE_ICV |
			 NFIFOENTRY_LC2 | 4), NFIFO_SZL, 0, 4, WITH(0));
		MOVE(MATH0, 0, ALTSOURCE, 0, IMM(4), WITH(WAITCOMP));
	}

	/* Reset ZUCA mode and done interrupt */
	LOAD(IMM(CLRW_CLR_C2MODE), CLRW, 0, 4, WITH(0));
/* TODO: Add ICTRL definitions */
	LOAD(IMM(0x00001000), ICTRL, 0, 4, WITH(0));

	PATCH_JUMP(pkeyjump, keyjump);
	return 0;
}

static inline int pdcp_insert_cplane_aes_zuc_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	LABEL(keyjump);
	REFERENCE(pkeyjump);

	if (rta_sec_era < RTA_SEC_ERA_5) {
		pr_debug("Invalid era for selected algorithm\n");
		return -1;
	}

	pkeyjump = JUMP(IMM(keyjump), LOCAL_JUMP, ALL_TRUE,
			WITH(SHRD | SELF | BOTH));
	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
	KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, WITH(0));

	SET_LABEL(keyjump);
	SEQLOAD(MATH0, 7, 1, WITH(0));
	JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
	MOVE(MATH0, 7, IFIFOAB2, 0, IMM(1), WITH(0));
	MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));

	MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
	MOVE(DESCBUF, 4, MATH2, 0, IMM(8), WITH(WAITCOMP));
	MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));
	MOVE(MATH2, 0, CONTEXT1, 16, IMM(8), WITH(0));
	MOVE(MATH2, 0, CONTEXT2, 0, IMM(8), WITH(WAITCOMP));

	if (dir == OP_TYPE_ENCAP_PROTOCOL)
		MATHB(SEQINSZ, ADD, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));
	else
		MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));

	MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
	SEQSTORE(MATH0, 7, 1, WITH(0));

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST2));
	} else {
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF | CONT));
		SEQFIFOLOAD(MSGOUTSNOOP, 0, WITH(VLF | LAST1 | FLUSH1));
	}

	ALG_OPERATION(OP_ALG_ALGSEL_ZUCA,
		      OP_ALG_AAI_F9,
		      OP_ALG_AS_INITFINAL,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      OP_ALG_ENCRYPT);

	ALG_OPERATION(OP_ALG_ALGSEL_AES,
		      OP_ALG_AAI_CTR,
		      OP_ALG_AS_INITFINAL,
		      ICV_CHECK_DISABLE,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     OP_ALG_ENCRYPT : OP_ALG_DECRYPT);

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		MOVE(CONTEXT2, 0, IFIFOAB1, 0, IMM(4), WITH(LAST1 | FLUSH1));
	} else {
		/* Save ICV */
		MOVE(OFIFO, 0, MATH0, 0, IMM(4), WITH(0));

		LOAD(IMM(NFIFOENTRY_STYPE_ALTSOURCE |
			 NFIFOENTRY_DEST_CLASS2 |
			 NFIFOENTRY_DTYPE_ICV |
			 NFIFOENTRY_LC2 | 4), NFIFO_SZL, 0, 4, WITH(0));
		MOVE(MATH0, 0, ALTSOURCE, 0, IMM(4), WITH(WAITCOMP));
	}

	/* Reset ZUCA mode and done interrupt */
	LOAD(IMM(CLRW_CLR_C2MODE), CLRW, 0, 4, WITH(0));
/* TODO: Add ICTRL definitions */
	LOAD(IMM(0x00001000), ICTRL, 0, 4, WITH(0));

	PATCH_JUMP(pkeyjump, keyjump);

	return 0;
}

static inline int pdcp_insert_cplane_zuc_snow_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	LABEL(keyjump);
	REFERENCE(pkeyjump);

	if (rta_sec_era < RTA_SEC_ERA_5) {
		pr_debug("Invalid era for selected algorithm\n");
		return -1;
	}

	pkeyjump = JUMP(IMM(keyjump), LOCAL_JUMP, ALL_TRUE,
				WITH(SHRD | SELF | BOTH));
	KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
	KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, WITH(0));

	SET_LABEL(keyjump);
	SEQLOAD(MATH0, 7, 1, WITH(0));
	JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
	MOVE(MATH0, 7, IFIFOAB2, 0, IMM(1), WITH(0));
	MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
	MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
	MOVE(DESCBUF, 4, MATH2, 0, IMM(8), WITH(WAITCOMP));
	MATHB(MATH1, OR, MATH2, MATH1, SIZE(8), WITH(0));
	MOVE(MATH1, 0, CONTEXT1, 0, IMM(8), WITH(0));
	MOVE(MATH1, 0, CONTEXT2, 0, IMM(4), WITH(0));
	MATHB(MATH1, AND, IMM(low_32b(PDCP_BEARER_MASK)), MATH2,
	      SIZE(4), WITH(0));
	MATHB(MATH1, AND, IMM(high_32b(PDCP_DIR_MASK)), MATH3, SIZE(4),
	      WITH(0));
	MATHB(MATH3, SHLD, MATH3, MATH3, SIZE(8), WITH(0));
	MOVE(MATH2, 4, OFIFO, 0, IMM(12), WITH(0));
	MOVE(OFIFO, 0, CONTEXT2, 4, IMM(12), WITH(0));

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		MATHB(SEQINSZ, ADD, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));
		MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
	} else {
		MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));
		MATHB(VSEQOUTSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
	}

	SEQSTORE(MATH0, 7, 1, WITH(0));

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST2));
	} else {
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF | CONT));
		SEQFIFOLOAD(MSGOUTSNOOP, 0, WITH(VLF | LAST2));
	}

	ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F9,
		      OP_ALG_AAI_F9,
		      OP_ALG_AS_INITFINAL,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      OP_ALG_DECRYPT);

	ALG_OPERATION(OP_ALG_ALGSEL_ZUCE,
		      OP_ALG_AAI_F8,
		      OP_ALG_AS_INITFINAL,
		      ICV_CHECK_DISABLE,
		      dir == OP_TYPE_ENCAP_PROTOCOL ?
			     OP_ALG_ENCRYPT : OP_ALG_DECRYPT);

	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		MOVE(CONTEXT2, 0, IFIFOAB1, 0, IMM(4), WITH(LAST1 | FLUSH1));
	} else {
		SEQFIFOLOAD(MSG1, 4, WITH(LAST1 | FLUSH1));

		/* Save ICV */
		MOVE(OFIFO, 0, MATH0, 0, IMM(4), WITH(WAITCOMP));

		LOAD(IMM(NFIFOENTRY_STYPE_ALTSOURCE |
			 NFIFOENTRY_DEST_CLASS2 |
			 NFIFOENTRY_DTYPE_ICV |
			 NFIFOENTRY_LC2 | 4), NFIFO_SZL, 0, 4, WITH(0));
		MOVE(MATH0, 0, ALTSOURCE, 0, IMM(4), WITH(0));
	}

	PATCH_JUMP(pkeyjump, keyjump);
	return 0;
}

static inline int pdcp_insert_cplane_zuc_aes_op(struct program *program,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned dir,
		unsigned char era_2_sw_hfn_override)
{
	if (rta_sec_era < RTA_SEC_ERA_5) {
		pr_debug("Invalid era for selected algorithm\n");
		return -1;
	}

	SEQLOAD(MATH0, 7, 1, WITH(0));
	JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
	MATHB(MATH0, AND, IMM(PDCP_SN_MASK), MATH1, SIZE(8), WITH(IFB));
	MATHB(MATH1, SHLD, MATH1, MATH1, SIZE(8), WITH(0));
	MOVE(DESCBUF, 4, MATH2, 0, IMM(0x08), WITH(WAITCOMP));
	MATHB(MATH1, OR, MATH2, MATH2, SIZE(8), WITH(0));
	SEQSTORE(MATH0, 7, 1, WITH(0));
	if (dir == OP_TYPE_ENCAP_PROTOCOL) {
		KEY(KEY1, 0, PTR(authdata->key), authdata->keylen, WITH(0));
		MOVE(MATH2, 0, IFIFOAB1, 0, IMM(0x08), WITH(0));
		MOVE(MATH0, 7, IFIFOAB1, 0, IMM(1), WITH(0));

		MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		MATHB(VSEQINSZ, ADD, IMM(PDCP_MAC_I_LEN),
		      VSEQOUTSZ, SIZE(4), 0);

		ALG_OPERATION(OP_ALG_ALGSEL_AES,
			      OP_ALG_AAI_CMAC,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_DECRYPT);
		SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));
		MOVE(CONTEXT1, 0, MATH3, 0, IMM(4), WITH(WAITCOMP));
		LOAD(IMM(CLRW_RESET_CLS1_CHA |
			 CLRW_CLR_C1KEY |
			 CLRW_CLR_C1CTX |
			 CLRW_CLR_C1ICV |
			 CLRW_CLR_C1DATAS |
			 CLRW_CLR_C1MODE),
		     CLRW, 0, 4, WITH(0));

		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));

		MOVE(MATH2, 0, CONTEXT1, 0, IMM(8), WITH(0));
		SEQINPTR(0, PDCP_NULL_MAX_FRAME_LEN, WITH(RTO));

		ALG_OPERATION(OP_ALG_ALGSEL_ZUCE,
			      OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_ENCRYPT);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));

		SEQFIFOLOAD(SKIP, 1, WITH(0));

		SEQFIFOLOAD(MSG1, 0, WITH(VLF));
		MOVE(MATH3, 0, IFIFOAB1, 0, IMM(4), WITH(LAST1 | FLUSH1));
	} else {
		MOVE(MATH2, 0, CONTEXT1, 0, IMM(8), WITH(0));

		MOVE(CONTEXT1, 0, CONTEXT2, 0, IMM(8), WITH(0));

		MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));

		MATHB(SEQINSZ, SUB, IMM(PDCP_MAC_I_LEN), VSEQOUTSZ, SIZE(4),
		      WITH(0));

		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));

		MOVE(CONTEXT1, 0, CONTEXT2, 0, IMM(8), WITH(0));

		ALG_OPERATION(OP_ALG_ALGSEL_ZUCE,
			      OP_ALG_AAI_F8,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_DECRYPT);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF | CONT));
		SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));

		MOVE(OFIFO, 0, MATH3, 0, IMM(4), WITH(0));

		LOAD(IMM(CLRW_RESET_CLS1_CHA |
			 CLRW_CLR_C1KEY |
			 CLRW_CLR_C1CTX |
			 CLRW_CLR_C1ICV |
			 CLRW_CLR_C1DATAS |
			 CLRW_CLR_C1MODE),
			 CLRW, 0, 4, WITH(0));

		KEY(KEY1, 0, PTR(authdata->key), authdata->keylen, WITH(0));

/* TODO: Add support in RTA for SOP bit in SEQINPTR command */
		WORD(0xF0080000);

		ALG_OPERATION(OP_ALG_ALGSEL_AES,
			      OP_ALG_AAI_CMAC,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_ENABLE,
			      OP_ALG_DECRYPT);

		MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));

		MOVE(CONTEXT2, 0, IFIFOAB1, 0, IMM(8), WITH(0));

		SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | FLUSH1));

		LOAD(IMM(NFIFOENTRY_STYPE_ALTSOURCE |
			 NFIFOENTRY_DEST_CLASS1 |
			 NFIFOENTRY_DTYPE_ICV |
			 NFIFOENTRY_LC1 |
			 NFIFOENTRY_FC1 | 4), NFIFO_SZL, 0, 4, WITH(0));
		MOVE(MATH3, 0, ALTSOURCE, 0, IMM(4), WITH(0));
	}

	return 0;
}

/*
 * Function for inserting the snippet of code responsible for creating
 * the HFN override code via either DPOVRD or via the input frame.
 */
static inline int pdcp_insert_hfn_ov_op(struct program *program,
		uint32_t shift,
		enum pdb_type_e pdb_type,
		unsigned char era_2_sw_hfn_override)
{
	uint32_t imm = 0x80000000;
	uint32_t hfn_pdb_offset;

	if (rta_sec_era == RTA_SEC_ERA_2 && !era_2_sw_hfn_override)
		return 0;

	switch (pdb_type) {
	case PDCP_PDB_TYPE_NO_PDB:
		/*
		 * If there is no PDB, then HFN override mechanism does not
		 * make any sense, thus in this case the function will
		 * return the pointer to the current position in the
		 * descriptor buffer
		 */
		return 0;

	case PDCP_PDB_TYPE_REDUCED_PDB:
		hfn_pdb_offset = 4;
		break;

	case PDCP_PDB_TYPE_FULL_PDB:
		hfn_pdb_offset = 8;
		break;

	default:
		return -1;
	}

	if (rta_sec_era > RTA_SEC_ERA_2) {
		MATHB(DPOVRD, AND, IMM(imm), NONE, SIZE(8), WITH(IFB));
	} else {
		SEQLOAD(MATH0, 4, 4, WITH(0));
		JUMP(IMM(1), LOCAL_JUMP, ALL_TRUE, WITH(CALM));
		MATHB(MATH0, AND, IMM(imm), NONE, SIZE(8), WITH(IFB));
		SEQSTORE(MATH0, 4, 4, WITH(0));
	}

	JUMP(IMM(5), LOCAL_JUMP, ALL_TRUE, WITH(MATH_Z));

	if (rta_sec_era > RTA_SEC_ERA_2)
		MATHB(DPOVRD, LSHIFT, IMM(shift), MATH0, SIZE(4), WITH(0));
	else
		MATHB(MATH0, LSHIFT, IMM(shift), MATH0, SIZE(4), WITH(0));

	MATHB(MATH0, SHLD, MATH0, MATH0, SIZE(8), WITH(0));
	MOVE(MATH0, 0, DESCBUF, hfn_pdb_offset, IMM(4), WITH(0));

	return 0;
}

/*
 * PDCP Control PDB creation function
 */
static inline enum pdb_type_e cnstr_pdcp_c_plane_pdb(struct program *program,
		uint32_t hfn,
		unsigned char bearer,
		unsigned char direction,
		uint32_t hfn_threshold,
		struct alginfo *cipherdata,
		struct alginfo *authdata)
{
	struct pdcp_pdb pdb;
	enum pdb_type_e
		pdb_mask[PDCP_CIPHER_TYPE_INVALID][PDCP_AUTH_TYPE_INVALID] = {
			{	/* NULL */
				PDCP_PDB_TYPE_NO_PDB,		/* NULL */
				PDCP_PDB_TYPE_FULL_PDB,		/* SNOW f9 */
				PDCP_PDB_TYPE_FULL_PDB,		/* AES CMAC */
				PDCP_PDB_TYPE_FULL_PDB		/* ZUC-I */
			},
			{	/* SNOW f8 */
				PDCP_PDB_TYPE_FULL_PDB,		/* NULL */
				PDCP_PDB_TYPE_FULL_PDB,		/* SNOW f9 */
				PDCP_PDB_TYPE_REDUCED_PDB,	/* AES CMAC */
				PDCP_PDB_TYPE_REDUCED_PDB	/* ZUC-I */
			},
			{	/* AES CTR */
				PDCP_PDB_TYPE_FULL_PDB,		/* NULL */
				PDCP_PDB_TYPE_REDUCED_PDB,	/* SNOW f9 */
				PDCP_PDB_TYPE_FULL_PDB,		/* AES CMAC */
				PDCP_PDB_TYPE_REDUCED_PDB	/* ZUC-I */
			},
			{	/* ZUC-E */
				PDCP_PDB_TYPE_FULL_PDB,		/* NULL */
				PDCP_PDB_TYPE_REDUCED_PDB,	/* SNOW f9 */
				PDCP_PDB_TYPE_REDUCED_PDB,	/* AES CMAC */
				PDCP_PDB_TYPE_FULL_PDB		/* ZUC-I */
			},
	};

	switch (pdb_mask[cipherdata->algtype][authdata->algtype]) {
	case PDCP_PDB_TYPE_NO_PDB:
		break;

	case PDCP_PDB_TYPE_REDUCED_PDB:
		WORD((hfn << PDCP_C_PLANE_PDB_HFN_SHIFT));
		WORD((bearer << PDCP_C_PLANE_PDB_BEARER_SHIFT) |
			(direction << PDCP_C_PLANE_PDB_DIR_SHIFT));
		break;

	case PDCP_PDB_TYPE_FULL_PDB:
		memset(&pdb, 0x00, sizeof(struct pdcp_pdb));

		/* This is a HW issue. Bit 2 should be set to zero,
		 * but it does not work this way. Override here.
		 */
		pdb.opt_res.rsvd = 0x00000002;

		/* Copy relevant information from user to PDB */
		pdb.hfn_res = hfn << PDCP_C_PLANE_PDB_HFN_SHIFT;
		pdb.bearer_dir_res =
			(bearer << PDCP_C_PLANE_PDB_BEARER_SHIFT) |
			(direction << PDCP_C_PLANE_PDB_DIR_SHIFT);
		pdb.hfn_thr_res =
			hfn_threshold << PDCP_C_PLANE_PDB_HFN_THR_SHIFT;

		/* copy PDB in descriptor*/
		ENDIAN_DATA((uint8_t *)&pdb, sizeof(struct pdcp_pdb));

		break;

	default:
		return PDCP_PDB_TYPE_INVALID;
	}

	return pdb_mask[cipherdata->algtype][authdata->algtype];
}

/**
 * @details                   Function for creating a PDCP Control Plane
 *                            encapsulation descriptor.
 * @ingroup                   sharedesc_group
 *
 * @param [in,out] descbuf    Pointer to buffer for descriptor construction.
 *
 * @param [in,out] bufsize    Size of descriptor written. Once the function
 *                            returns, the value of this parameter can be used
 *                            for reclaiming the space that wasn't used for the
 *                            descriptor.
 *
 * @param [in] ps             If 36/40bit addressing is desired, this parameter
 *                            must be non-zero.
 *
 * @param [in] hfn            Starting Hyper Frame Number to be used together
 *                            with the SN from the PDCP frames.
 *
 * @param [in] bearer         Radio bearer ID.
 *
 * @param [in] direction      The direction of the PDCP frame (UL/DL).
 *
 * @param [in] hfn_threshold  HFN value that once reached triggers a warning
 *                            from SEC that keys should be renegociated at the
 *                            earliest convenience.
 *
 * @param [in] cipherdata     Pointer to block cipher transform definitions.
 *                            Valid algorithm values are those from
 *                            cipher_type_pdcp enum.
 *
 * @param [in] authdata       Pointer to authentication transform definitions.
 *                            Valid algorithm values are those from
 *                            auth_type_pdcp enum.
 *
 * @param [in] era_2_sw_hfn_override    If software HFN override mechanism is
 *                                      desired for this descriptor.
 *                                      @note Can only be used for SEC ERA 2
 *
 * @note  @b descbuf must be large enough to contain a full 256 byte long
 *        descriptor; after the function returns, by subtracting the actual
 *        number of bytes used (using @b bufsize), the user can reuse the
 *        remaining buffer space for other purposes.
 *
 */
static inline void cnstr_shdsc_pdcp_c_plane_encap(uint32_t *descbuf,
		unsigned *bufsize,
		unsigned short ps,
		uint32_t hfn,
		unsigned short bearer,
		unsigned short direction,
		uint32_t hfn_threshold,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned char era_2_sw_hfn_override)
{
	static int
		(*pdcp_cp_fp[PDCP_CIPHER_TYPE_INVALID][PDCP_AUTH_TYPE_INVALID])
			(struct program*, struct alginfo *,
			 struct alginfo *, unsigned, unsigned char) = {
		{	/* NULL */
			pdcp_insert_cplane_null_op,	/* NULL */
			pdcp_insert_cplane_int_only_op,	/* SNOW f9 */
			pdcp_insert_cplane_int_only_op,	/* AES CMAC */
			pdcp_insert_cplane_int_only_op	/* ZUC-I */
		},
		{	/* SNOW f8 */
			pdcp_insert_cplane_enc_only_op,	/* NULL */
			pdcp_insert_cplane_acc_op,	/* SNOW f9 */
			pdcp_insert_cplane_snow_aes_op,	/* AES CMAC */
			pdcp_insert_cplane_snow_zuc_op	/* ZUC-I */
		},
		{	/* AES CTR */
			pdcp_insert_cplane_enc_only_op,	/* NULL */
			pdcp_insert_cplane_aes_snow_op,	/* SNOW f9 */
			pdcp_insert_cplane_acc_op,	/* AES CMAC */
			pdcp_insert_cplane_aes_zuc_op	/* ZUC-I */
		},
		{	/* ZUC-E */
			pdcp_insert_cplane_enc_only_op,	/* NULL */
			pdcp_insert_cplane_zuc_snow_op,	/* SNOW f9 */
			pdcp_insert_cplane_zuc_aes_op,	/* AES CMAC */
			pdcp_insert_cplane_acc_op	/* ZUC-I */
		},
	};
	static uint32_t
		desc_share[PDCP_CIPHER_TYPE_INVALID][PDCP_AUTH_TYPE_INVALID] = {
		{	/* NULL */
			SHR_WAIT,	/* NULL */
			SHR_ALWAYS,	/* SNOW f9 */
			SHR_ALWAYS,	/* AES CMAC */
			SHR_ALWAYS	/* ZUC-I */
		},
		{	/* SNOW f8 */
			SHR_ALWAYS,	/* NULL */
			SHR_ALWAYS,	/* SNOW f9 */
			SHR_WAIT,	/* AES CMAC */
			SHR_WAIT	/* ZUC-I */
		},
		{	/* AES CTR */
			SHR_ALWAYS,	/* NULL */
			SHR_ALWAYS,	/* SNOW f9 */
			SHR_ALWAYS,	/* AES CMAC */
			SHR_WAIT	/* ZUC-I */
		},
		{	/* ZUC-E */
			SHR_ALWAYS,	/* NULL */
			SHR_WAIT,	/* SNOW f9 */
			SHR_WAIT,	/* AES CMAC */
			SHR_ALWAYS	/* ZUC-I */
		},
	};
	enum pdb_type_e pdb_type;
	struct program prg;
	struct program *program = &prg;
	LABEL(pdb_end);

	if (rta_sec_era != RTA_SEC_ERA_2 && era_2_sw_hfn_override) {
		pr_debug("Cannot select SW HFN override for other era than 2");
		return;
	}

	PROGRAM_CNTXT_INIT(descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR();

	SHR_HDR(desc_share[cipherdata->algtype][authdata->algtype], 0, WITH(0));

	pdb_type = cnstr_pdcp_c_plane_pdb(program,
			hfn,
			bearer,
			direction,
			hfn_threshold,
			cipherdata,
			authdata);

	SET_LABEL(pdb_end);

	if (pdcp_insert_hfn_ov_op(program, PDCP_SN_SIZE_5, pdb_type,
				  era_2_sw_hfn_override))
		return;

	if (pdcp_cp_fp[cipherdata->algtype][authdata->algtype](program,
			cipherdata,
			authdata,
			OP_TYPE_ENCAP_PROTOCOL,
			era_2_sw_hfn_override))
		return;

	PATCH_HDR(0, pdb_end);

	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                   Function for creating a PDCP Control Plane
 *                            decapsulation descriptor.
 * @ingroup                   sharedesc_group
 *
 * @param [in,out] descbuf    Pointer to buffer for descriptor construction.
 *
 * @param [in,out] bufsize    Size of descriptor written. Once the function
 *                            returns, the value of this parameter can be used
 *                            for reclaiming the space that wasn't used for the
 *                            descriptor.
 *
 * @param [in] ps             If 36/40bit addressing is desired, this parameter
 *                            must be non-zero.
 *
 * @param [in] hfn            Starting Hyper Frame Number to be used together
 *                            with the SN from the PDCP frames.
 *
 * @param [in] bearer         Radio bearer ID.
 *
 * @param [in] direction      The direction of the PDCP frame (UL/DL).
 *
 * @param [in] hfn_threshold  HFN value that once reached triggers a warning
 *                            from SEC that keys should be renegociated at the
 *                            earliest convenience.
 *
 * @param [in] cipherdata     Pointer to block cipher transform definitions.
 *                            Valid algorithm values are those from
 *                            cipher_type_pdcp enum.
 *
 * @param [in] authdata       Pointer to authentication transform definitions.
 *                            Valid algorithm values are those from
 *                            auth_type_pdcp enum.
 *
 * @param [in] era_2_sw_hfn_override    If software HFN override mechanism is
 *                                      desired for this descriptor.
 *                                      @note Can only be used for SEC ERA 2
 *
 * @note  @b descbuf must be large enough to contain a full 256 byte long
 *        descriptor; after the function returns, by subtracting the actual
 *        number of bytes used (using @b bufsize), the user can reuse the
 *        remaining buffer space for other purposes.
 *
 */
static inline void cnstr_shdsc_pdcp_c_plane_decap(uint32_t *descbuf,
		unsigned *bufsize,
		unsigned short ps,
		uint32_t hfn,
		unsigned short bearer,
		unsigned short direction,
		uint32_t hfn_threshold,
		struct alginfo *cipherdata,
		struct alginfo *authdata,
		unsigned char era_2_sw_hfn_override)
{
	static int
		(*pdcp_cp_fp[PDCP_CIPHER_TYPE_INVALID][PDCP_AUTH_TYPE_INVALID])
			(struct program*, struct alginfo *,
			 struct alginfo *, unsigned, unsigned char) = {
		{	/* NULL */
			pdcp_insert_cplane_null_op,	/* NULL */
			pdcp_insert_cplane_int_only_op,	/* SNOW f9 */
			pdcp_insert_cplane_int_only_op,	/* AES CMAC */
			pdcp_insert_cplane_int_only_op	/* ZUC-I */
		},
		{	/* SNOW f8 */
			pdcp_insert_cplane_enc_only_op,	/* NULL */
			pdcp_insert_cplane_acc_op,	/* SNOW f9 */
			pdcp_insert_cplane_snow_aes_op,	/* AES CMAC */
			pdcp_insert_cplane_snow_zuc_op	/* ZUC-I */
		},
		{	/* AES CTR */
			pdcp_insert_cplane_enc_only_op,	/* NULL */
			pdcp_insert_cplane_aes_snow_op,	/* SNOW f9 */
			pdcp_insert_cplane_acc_op,	/* AES CMAC */
			pdcp_insert_cplane_aes_zuc_op	/* ZUC-I */
		},
		{	/* ZUC-E */
			pdcp_insert_cplane_enc_only_op,	/* NULL */
			pdcp_insert_cplane_zuc_snow_op,	/* SNOW f9 */
			pdcp_insert_cplane_zuc_aes_op,	/* AES CMAC */
			pdcp_insert_cplane_acc_op	/* ZUC-I */
		},
	};
	static uint32_t
		desc_share[PDCP_CIPHER_TYPE_INVALID][PDCP_AUTH_TYPE_INVALID] = {
		{	/* NULL */
			SHR_WAIT,	/* NULL */
			SHR_ALWAYS,	/* SNOW f9 */
			SHR_ALWAYS,	/* AES CMAC */
			SHR_ALWAYS	/* ZUC-I */
		},
		{	/* SNOW f8 */
			SHR_ALWAYS,	/* NULL */
			SHR_ALWAYS,	/* SNOW f9 */
			SHR_WAIT,	/* AES CMAC */
			SHR_WAIT	/* ZUC-I */
		},
		{	/* AES CTR */
			SHR_ALWAYS,	/* NULL */
			SHR_ALWAYS,	/* SNOW f9 */
			SHR_ALWAYS,	/* AES CMAC */
			SHR_WAIT	/* ZUC-I */
		},
		{	/* ZUC-E */
			SHR_ALWAYS,	/* NULL */
			SHR_WAIT,	/* SNOW f9 */
			SHR_WAIT,	/* AES CMAC */
			SHR_ALWAYS	/* ZUC-I */
		},
	};
	enum pdb_type_e pdb_type;
	struct program prg;
	struct program *program = &prg;
	LABEL(pdb_end);

	if (rta_sec_era != RTA_SEC_ERA_2 && era_2_sw_hfn_override) {
		pr_debug("Cannot select SW HFN override for other era than 2");
		return;
	}

	PROGRAM_CNTXT_INIT(descbuf, 0);
	if (ps)
		PROGRAM_SET_36BIT_ADDR();

	SHR_HDR(desc_share[cipherdata->algtype][authdata->algtype], 0, WITH(0));

	pdb_type = cnstr_pdcp_c_plane_pdb(program,
			hfn,
			bearer,
			direction,
			hfn_threshold,
			cipherdata,
			authdata);

	SET_LABEL(pdb_end);

	if (pdcp_insert_hfn_ov_op(program, PDCP_SN_SIZE_5, pdb_type,
				  era_2_sw_hfn_override))
		return;

	if (pdcp_cp_fp[cipherdata->algtype][authdata->algtype](program,
			cipherdata,
			authdata,
			OP_TYPE_DECAP_PROTOCOL,
			era_2_sw_hfn_override))
		return;

	PATCH_HDR(0, pdb_end);

	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                   Function for creating a PDCP User Plane
 *                            encapsulation descriptor.
 * @ingroup                   sharedesc_group
 *
 * @param [in,out] descbuf    Pointer to buffer for descriptor construction.
 *
 * @param [in,out] bufsize    Size of descriptor written. Once the function
 *                            returns, the value of this parameter can be used
 *                            for reclaiming the space that wasn't used for the
 *                            descriptor.
 *
 * @param [in] ps             If 36/40bit addressing is desired, this parameter
 *                            must be non-zero.
 *
 * @param [in] sns            Selects if Short Sequence Number is used.
 *
 * @param [in] hfn            Starting Hyper Frame Number to be used together
 *                            with the SN from the PDCP frames.
 *
 * @param [in] bearer         Radio bearer ID.
 *
 * @param [in] direction      The direction of the PDCP frame (UL/DL).
 *
 * @param [in] hfn_threshold  HFN value that once reached triggers a warning
 *                            from SEC that keys should be renegociated at the
 *                            earliest convenience.
 *
 * @param [in] cipherdata     Pointer to block cipher transform definitions.
 *                            Valid algorithm values are those from
 *                            cipher_type_pdcp enum.
 *
 * @param [in] era_2_sw_hfn_override    If software HFN override mechanism is
 *                                      desired for this descriptor.
 *                                      @note Can only be used for SEC ERA 2
 *
 * @note  @b descbuf must be large enough to contain a full 256 byte long
 *        descriptor; after the function returns, by subtracting the actual
 *        number of bytes used (using @b bufsize), the user can reuse the
 *        remaining buffer space for other purposes.
 *
 */
static inline void cnstr_shdsc_pdcp_u_plane_encap(uint32_t *descbuf,
		unsigned *bufsize,
		unsigned short ps,
		unsigned short sns,
		uint32_t hfn,
		unsigned short bearer,
		unsigned short direction,
		uint32_t hfn_threshold,
		struct alginfo *cipherdata,
		unsigned char era_2_sw_hfn_override)
{
	struct program prg;
	struct program *program = &prg;
	struct pdcp_pdb pdb;
	LABEL(pdb_end);

	if (rta_sec_era != RTA_SEC_ERA_2 && era_2_sw_hfn_override) {
		pr_debug("Cannot select SW HFN override for other era than 2");
		return;
	}

	PROGRAM_CNTXT_INIT(descbuf, 0);

	if (ps)
		PROGRAM_SET_36BIT_ADDR();

	SHR_HDR(SHR_ALWAYS, 0, WITH(0));

	/* Read options from user */
	/* If SNS is enabled, then the HFN and HFN threshold
	 * have different lengths.
	 */
	memset(&pdb, 0x00, sizeof(struct pdcp_pdb));

	if (PDCP_SN_SIZE_7 == sns) {
		pdb.opt_res.opt |= PDCP_U_PLANE_PDB_OPT_SHORT_SN;
		pdb.hfn_res = hfn << PDCP_U_PLANE_PDB_SHORT_SN_HFN_SHIFT;
		pdb.hfn_thr_res =
			hfn_threshold<<PDCP_U_PLANE_PDB_SHORT_SN_HFN_THR_SHIFT;
	} else {
		pdb.opt_res.opt &= ~PDCP_U_PLANE_PDB_OPT_SHORT_SN;
		pdb.hfn_res = hfn << PDCP_U_PLANE_PDB_LONG_SN_HFN_SHIFT;
		pdb.hfn_thr_res =
			hfn_threshold<<PDCP_U_PLANE_PDB_LONG_SN_HFN_THR_SHIFT;
	}

	pdb.bearer_dir_res = (bearer << PDCP_U_PLANE_PDB_BEARER_SHIFT) |
				(direction << PDCP_U_PLANE_PDB_DIR_SHIFT);

	/* copy PDB in descriptor*/
	ENDIAN_DATA((uint8_t *)&pdb, sizeof(struct pdcp_pdb));

	SET_LABEL(pdb_end);

	if (pdcp_insert_hfn_ov_op(program,
				  PDCP_SN_SIZE_7 == sns ?
					PDCP_SN_SIZE_7 : PDCP_SN_SIZE_12,
				  PDCP_PDB_TYPE_FULL_PDB,
				  era_2_sw_hfn_override))
		return;

	switch (cipherdata->algtype) {
	case PDCP_CIPHER_TYPE_ZUC:
		if (rta_sec_era < RTA_SEC_ERA_5) {
			pr_debug("Invalid era for selected algorithm\n");
			return;
		}
	case PDCP_CIPHER_TYPE_AES:
	case PDCP_CIPHER_TYPE_SNOW:
		/* Insert Cipher Key */
		KEY(KEY1, 0, PTR((uint64_t)cipherdata->key),
		    cipherdata->keylen, WITH(0));
		PROTOCOL(OP_TYPE_ENCAP_PROTOCOL,
			 OP_PCLID_LTE_PDCP_USER,
			 cipherdata->algtype);
		break;
	case PDCP_CIPHER_TYPE_NULL:
		pdcp_insert_uplane_null_op(program,
					   cipherdata,
					   OP_TYPE_ENCAP_PROTOCOL);
		break;
	default:
		pr_debug("%s: Invalid encrypt algorithm selected: %d\n",
			 "cnstr_pcl_shdsc_pdcp_u_plane_decap",
			 cipherdata->algtype);
		return;
	}

	PATCH_HDR(0, pdb_end);
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                   Function for creating a PDCP User Plane
 *                            decapsulation descriptor.
 * @ingroup                   sharedesc_group
 *
 * @param [in,out] descbuf    Pointer to buffer for descriptor construction.
 *
 * @param [in,out] bufsize    Size of descriptor written. Once the function
 *                            returns, the value of this parameter can be used
 *                            for reclaiming the space that wasn't used for the
 *                            descriptor.
 *
 * @param [in] ps             If 36/40bit addressing is desired, this parameter
 *                            must be non-zero.
 *
 * @param [in] sns            Selects if Short Sequence Number is used.
 *
 * @param [in] hfn            Starting Hyper Frame Number to be used together
 *                            with the SN from the PDCP frames.
 *
 * @param [in] bearer         Radio bearer ID.
 *
 * @param [in] direction      The direction of the PDCP frame (UL/DL).
 *
 * @param [in] hfn_threshold  HFN value that once reached triggers a warning
 *                            from SEC that keys should be renegociated at the
 *                            earliest convenience.
 *
 * @param [in] cipherdata     Pointer to block cipher transform definitions.
 *                            Valid algorithm values are those from
 *                            cipher_type_pdcp enum.
 *
 * @param [in] era_2_sw_hfn_override    If software HFN override mechanism is
 *                                      desired for this descriptor.
 *                                      @note Can only be used for SEC ERA 2
 *
 * @note  @b descbuf must be large enough to contain a full 256 byte long
 *        descriptor; after the function returns, by subtracting the actual
 *        number of bytes used (using @b bufsize), the user can reuse the
 *        remaining buffer space for other purposes.
 *
 */
static inline void cnstr_shdsc_pdcp_u_plane_decap(uint32_t *descbuf,
		unsigned *bufsize,
		unsigned short ps,
		unsigned short sns,
		uint32_t hfn,
		unsigned short bearer,
		unsigned short direction,
		uint32_t hfn_threshold,
		struct alginfo *cipherdata,
		unsigned char era_2_sw_hfn_override)
{
	struct program prg;
	struct program *program = &prg;
	struct pdcp_pdb pdb;
	LABEL(pdb_end);

	if (rta_sec_era != RTA_SEC_ERA_2 && era_2_sw_hfn_override) {
		pr_debug("Cannot select SW HFN override for other era than 2");
		return;
	}

	PROGRAM_CNTXT_INIT(descbuf, 0);

	if (ps)
		PROGRAM_SET_36BIT_ADDR();

	SHR_HDR(SHR_ALWAYS, 0, WITH(0));

	/* Read options from user */
	/* If SNS is enabled, then the HFN and HFN threshold
	 * have different lengths.
	 */
	memset(&pdb, 0x00, sizeof(struct pdcp_pdb));

	if (PDCP_SN_SIZE_7 == sns) {
		pdb.opt_res.opt |= PDCP_U_PLANE_PDB_OPT_SHORT_SN;
		pdb.hfn_res = hfn << PDCP_U_PLANE_PDB_SHORT_SN_HFN_SHIFT;
		pdb.hfn_thr_res =
			hfn_threshold<<PDCP_U_PLANE_PDB_SHORT_SN_HFN_THR_SHIFT;
	} else {
		pdb.opt_res.opt &= ~PDCP_U_PLANE_PDB_OPT_SHORT_SN;
		pdb.hfn_res = hfn << PDCP_U_PLANE_PDB_LONG_SN_HFN_SHIFT;
		pdb.hfn_thr_res =
			hfn_threshold<<PDCP_U_PLANE_PDB_LONG_SN_HFN_THR_SHIFT;
	}

	pdb.bearer_dir_res = (bearer << PDCP_U_PLANE_PDB_BEARER_SHIFT) |
				(direction << PDCP_U_PLANE_PDB_DIR_SHIFT);

	/* copy PDB in descriptor*/
	ENDIAN_DATA((uint8_t *)&pdb, sizeof(struct pdcp_pdb));

	SET_LABEL(pdb_end);

	if (pdcp_insert_hfn_ov_op(program,
				  PDCP_SN_SIZE_7 == sns ?
					PDCP_SN_SIZE_7 : PDCP_SN_SIZE_12,
				  PDCP_PDB_TYPE_FULL_PDB,
				  era_2_sw_hfn_override))
		return;

	switch (cipherdata->algtype) {
	case PDCP_CIPHER_TYPE_ZUC:
		if (rta_sec_era < RTA_SEC_ERA_5) {
			pr_debug("Invalid era for selected algorithm\n");
			return;
		}
	case PDCP_CIPHER_TYPE_AES:
	case PDCP_CIPHER_TYPE_SNOW:
		/* Insert Cipher Key */
		KEY(KEY1, 0, PTR(cipherdata->key), cipherdata->keylen, WITH(0));
		PROTOCOL(OP_TYPE_DECAP_PROTOCOL,
			 OP_PCLID_LTE_PDCP_USER,
			 cipherdata->algtype);
		break;
	case PDCP_CIPHER_TYPE_NULL:
		pdcp_insert_uplane_null_op(program,
					   cipherdata,
					   OP_TYPE_DECAP_PROTOCOL);
		break;
	default:
		pr_debug("%s: Invalid encrypt algorithm selected: %d\n",
			 "cnstr_pcl_shdsc_pdcp_u_plane_decap",
			 cipherdata->algtype);
		return;
	}

	PATCH_HDR(0, pdb_end);
	*bufsize = PROGRAM_FINALIZE();
}

/**
 * @details                   Function for creating a PDCP Short MAC descriptor.
 * @ingroup                   sharedesc_group
 *
 * @param [in,out] descbuf    Pointer to buffer for descriptor construction.
 *
 * @param [in,out] bufsize    Size of descriptor written. Once the function
 *                            returns, the value of this parameter can be used
 *                            for reclaiming the space that wasn't used for the
 *                            descriptor.
 *
 * @param [in] ps             If 36/40bit addressing is desired, this parameter
 *                            must be non-zero.
 *
 * @param [in] authdata       Pointer to authentication transform definitions.
 *                            Valid algorithm values are those from
 *                            auth_type_pdcp enum.
 *
 * @param [in] era_2_sw_hfn_override    If software HFN override mechanism is
 *                                      desired for this descriptor.
 *                                      @note Can only be used for SEC ERA 2
 *
 * @note  @b descbuf must be large enough to contain a full 256 byte long
 *        descriptor; after the function returns, by subtracting the actual
 *        number of bytes used (using @b bufsize), the user can reuse the
 *        remaining buffer space for other purposes.
 *
 */
static inline void cnstr_shdsc_pdcp_short_mac(uint32_t *descbuf,
		unsigned *bufsize,
		unsigned short ps,
		struct alginfo *authdata)
{
	struct program prg;
	struct program *program = &prg;
	uint32_t iv[3] = {0, 0, 0};
	LABEL(local_offset);
	REFERENCE(move_cmd_read_descbuf);
	REFERENCE(move_cmd_write_descbuf);

	PROGRAM_CNTXT_INIT(descbuf, 0);

	if (ps)
		PROGRAM_SET_36BIT_ADDR();

	SHR_HDR(SHR_ALWAYS, 1, WITH(0));

	if (rta_sec_era > RTA_SEC_ERA_2) {
		MATHB(SEQINSZ, SUB, ZERO, VSEQINSZ, SIZE(4), WITH(0));
		MATHB(SEQINSZ, SUB, ZERO, MATH1, SIZE(4), WITH(0));
	} else {
		MATHB(SEQINSZ, ADD, ONE, MATH1, SIZE(4), WITH(0));
		MATHB(MATH1, SUB, ONE, MATH1, SIZE(4), WITH(0));
		MATHB(ZERO, ADD, MATH1, VSEQINSZ, SIZE(4), WITH(0));
		MOVE(MATH1, 0, MATH0, 0, IMM(8), WITH(0));

		/*
		 * Since MOVELEN is available only starting with
		 * SEC ERA 3, use poor man's MOVELEN: create a MOVE
		 * command dynamically by writing the length from M1 by
		 * OR-ing the command in the M1 register and MOVE the
		 * result into the descriptor buffer. Care must be taken
		 * wrt. the location of the command because of SEC
		 * pipelining. The actual MOVEs are written at the end
		 * of the descriptor due to calculations needed on the
		 * offset in the descriptor for the MOVE command.
		 */
		move_cmd_read_descbuf = MOVE(DESCBUF, 0, MATH0, 0, IMM(6),
					     WITH(0));
		move_cmd_write_descbuf = MOVE(MATH0, 0, DESCBUF, 0, IMM(8),
					      WITH(WAITCOMP));
	}
	MATHB(ZERO, ADD, MATH1, VSEQOUTSZ, SIZE(4), WITH(0));

	switch (authdata->algtype) {
	case PDCP_AUTH_TYPE_NULL:
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		if (rta_sec_era > RTA_SEC_ERA_2) {
			MOVE(AB1, 0, OFIFO, 0, MATH1, WITH(0));
		} else {
			SET_LABEL(local_offset);

			/* Shut off automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0,
			     WITH(0));

			/* Placeholder for MOVE command with length from M1
			 * register
			 */
			MOVE(IFIFOAB1, 0, OFIFO, 0, IMM(0), WITH(0));

			/* Enable automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0,
			     WITH(0));
		}

		LOAD(PTR((uintptr_t)iv), MATH0, 0, SIZE(8), IMMED);
		SEQFIFOLOAD(MSG1, 0, WITH(VLF | LAST1 | LAST2 | FLUSH1));
		SEQSTORE(MATH0, 0, 4, WITH(0));

		break;

	case PDCP_AUTH_TYPE_SNOW:
		iv[0] = 0xFFFFFFFF;
		iv[1] = 0x04000000;
		iv[2] = 0xF8000000;

		KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, WITH(0));
		LOAD(PTR((uintptr_t)&iv), CONTEXT2, 0, SIZE(12), IMMED);
		ALG_OPERATION(OP_ALG_ALGSEL_SNOW_F9,
			      OP_ALG_AAI_F9,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_ENCRYPT);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MOVE(AB1, 0, OFIFO, 0, MATH1, WITH(0));
		} else {
			SET_LABEL(local_offset);


			/* Shut off automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0,
			     WITH(0));

			/* Placeholder for MOVE command with length from M1
			 * register */
			MOVE(IFIFOAB1, 0, OFIFO, 0, IMM(0), WITH(0));

			/* Enable automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0,
			     WITH(0));
		}
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST1 | LAST2 | FLUSH1));
		SEQSTORE(CONTEXT2, 0, 4, WITH(0));

		break;

	case PDCP_AUTH_TYPE_AES:
		iv[0] = 0xFFFFFFFF;
		iv[1] = 0xFC000000;
		iv[2] = 0x00000000; /* unused */

		KEY(KEY1, 0, PTR(authdata->key), authdata->keylen, WITH(0));
		LOAD(PTR((uintptr_t)&iv), MATH0, 0, 8, IMMED);
		MOVE(MATH0, 0, IFIFOAB1, 0, IMM(8), WITH(0));
		ALG_OPERATION(OP_ALG_ALGSEL_AES,
			      OP_ALG_AAI_CMAC,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_ENCRYPT);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));

		if (rta_sec_era > RTA_SEC_ERA_2) {
			MOVE(AB2, 0, OFIFO, 0, MATH1, WITH(0));
		} else {
			SET_LABEL(local_offset);

			/* Shut off automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_DISABLE_AUTO_NFIFO, 0,
			     WITH(0));

			/* Placeholder for MOVE command with length from M1
			 * register */
			MOVE(IFIFOAB2, 0, OFIFO, 0, IMM(0), WITH(0));

			/* Enable automatic Info FIFO entries */
			LOAD(IMM(0), DCTRL, LDOFF_ENABLE_AUTO_NFIFO, 0,
			     WITH(0));
		}
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST1 | LAST2 | FLUSH1));
		SEQSTORE(CONTEXT1, 0, 4, WITH(0));

		break;

	case PDCP_AUTH_TYPE_ZUC:
		if (rta_sec_era < RTA_SEC_ERA_5) {
			pr_debug("Invalid era for selected algorithm\n");
			return;
		}
		iv[0] = 0xFFFFFFFF;
		iv[1] = 0xFC000000;
		iv[2] = 0x00000000; /* unused */

		KEY(KEY2, 0, PTR(authdata->key), authdata->keylen, WITH(0));
		LOAD(PTR((uintptr_t)&iv), CONTEXT2, 0, 12, IMMED);
		ALG_OPERATION(OP_ALG_ALGSEL_ZUCA,
			      OP_ALG_AAI_F9,
			      OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE,
			      OP_ALG_ENCRYPT);
		SEQFIFOSTORE(MSG, 0, 0, WITH(VLF));
		MOVE(AB1, 0, OFIFO, 0, MATH1, WITH(0));
		SEQFIFOLOAD(MSGINSNOOP, 0, WITH(VLF | LAST1 | LAST2 | FLUSH1));
		SEQSTORE(CONTEXT2, 0, 4, WITH(0));

		break;

	default:
		pr_debug("%s: Invalid integrity algorithm selected: %d\n",
			 "cnstr_shdsc_pdcp_short_mac",
			 authdata->algtype);
		return;
	}


	if (rta_sec_era < RTA_SEC_ERA_3) {
		PATCH_MOVE(move_cmd_read_descbuf, local_offset);
		PATCH_MOVE(move_cmd_write_descbuf, local_offset);
	}

	*bufsize = PROGRAM_FINALIZE();
}

#endif /* __RTA_PROTOSHARED_H__ */
