/*
 * 2011 - Nico Golde <nico@ngolde.de>
 * this is from gsm_data.h of the openbsc code base
*/

#include <stdint.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/msgb.h>

struct msgb *gsm411_msgb_alloc(void);
struct msgb *gsm48_l3_msgb_alloc(void);
int gsm48_gen_classmark2(struct gsm48_classmark2 *cm);

#define SMS_TEXT_SIZE   160

struct gsm_sms {
	uint8_t validity_period;
	uint8_t reply_path_req;
	uint8_t status_rep_req;
	uint8_t ud_hdr_ind;
	uint8_t protocol_id;
	uint8_t data_coding_scheme;
	uint8_t reject_duplicates;
	uint8_t msg_ref;
	char dest_addr[20+1];   /* DA LV is 12 bytes max, i.e. 10 bytes
							 * BCD == 20 bytes string */
	uint8_t user_data_len;
	uint8_t user_data[SMS_TEXT_SIZE];
};

