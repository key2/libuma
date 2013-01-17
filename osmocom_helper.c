/*
 * 2011 - Nico Golde <nico@ngolde.de>
 * this is heavily based on parts of openbsc/osmocom/libosmocore
*/


#include <stdlib.h>
#include <string.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/msgb.h>

#define L3_MSG_HEAD 4
#define L3_ALLOC_HEADROOM 64
#define L3_ALLOC_SIZE 256
#define GSM411_ALLOC_SIZE       1024
#define GSM411_ALLOC_HEADROOM   128
#define SMS_HDR_SIZE    128

struct msgb *gsm48_l3_msgb_alloc(void) {
	struct msgb *msg;

	msg = msgb_alloc_headroom(L3_ALLOC_SIZE+L3_ALLOC_HEADROOM,
			L3_ALLOC_HEADROOM, "GSM 04.08 L3");
	if (!msg)
		return NULL;
	msg->l3h = msg->data;

	return msg;
}

struct msgb *gsm411_msgb_alloc(void){
	struct msgb *msg;

	msg = msgb_alloc_headroom(GSM411_ALLOC_SIZE, GSM411_ALLOC_HEADROOM, "GSM 04.11");
	if (!msg)
		return NULL;

	return msg;
}

int gsm48_gen_classmark2(struct gsm48_classmark2 *cm) {
	cm->pwr_lev = 7;
	cm->a5_1 = 0;
	cm->es_ind = 1;
	cm->rev_lev = 2;
	cm->fc = 0;
	cm->vgcs = 0;
	cm->vbs = 0;
	cm->sm_cap = 1;
	cm->ss_scr = 1;
	cm->ps_cap = 0;
	cm->a5_2 = 0;
	cm->a5_3 = 1;
	cm->cmsp = 0;
	cm->solsa = 0;
	cm->lcsva_cap = 1;

	return 0;
}

int gsm48_encode_mi(uint8_t *buf, uint8_t *mi, uint8_t len){
	/* we only handle imsi and tmsi, no imei etc. */
	buf[0] = len + 1;
	if(len == 4){
		/* this is hackish... the encoding includes odd/even and the type (4 being tmsi)
		   will do the same for imsi, assuming its odd and always 13 bytes
		*/
		buf[1] = 0x4;
	} else {
		buf[1] = 0x1;
	}
	memcpy(buf+2, mi, len);

	return 0;
}

