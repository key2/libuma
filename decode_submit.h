/*
 * -------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Nico Golde <nico@ngolde.de> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day,
 * and you think this stuff is worth it, you can buy me a beer in return.
 * -------------------------------------------------------------------------
 */

#define PDU_SIZE 160
#define IE_L_MAX 0xff + 1

typedef struct ie {
	struct ie_t *next;
	unsigned char ie_type;
	unsigned char data[IE_L_MAX];
	unsigned char ie_l;
} ie_t;

typedef struct udh {
	ie_t *head;
	unsigned char udh_l;
} udh_t;

typedef struct sms {
	unsigned int tp_rp   :1;
	unsigned int tp_udhi :1;
	unsigned int tp_srr  :1;
	unsigned int tp_vpf  :2;
	unsigned int tp_rd   :1;
	unsigned int tp_mti  :2;
	unsigned char msg_ref;
	unsigned char msisdn_l;
	unsigned char msisdn_t;
	unsigned char *msisdn;
	unsigned char tp_pid;
	unsigned char tp_dcs;
	unsigned char tp_vp;
	unsigned char tp_ud_l;
	udh_t *udh;
} sms_t;

unsigned char *parse_pdu_header(sms_t *csms, unsigned char *ptr);
void destroy_sms(sms_t *csms);
unsigned char *read_pdu(char *pdu);
unsigned char *decode_msisdn(unsigned char *ptr, unsigned char len);


