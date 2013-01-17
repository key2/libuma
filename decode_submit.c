/* rudimentary SMS_SUBMIT decoder - 2010
   The file is licenced under Revision 42 of the Beerware Licence
   Nico Golde <nico@ngolde.de> wrote this file. As long as you retain this
   notice you can do whatever you want with this stuff. If we meet some day,
   and you think this stuff is worth it, you can buy me a beer in return.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode_submit.h"

unsigned char *
read_pdu(char *pdu){
	unsigned char *p = malloc(PDU_SIZE);
	unsigned char *ret = p;
	unsigned char tmp;
	char foo[3] = { 0, 0, 0 };
	char *ptr = NULL;
	memset(p, 0, PDU_SIZE);

	for(ptr = pdu; ptr && *ptr; ptr += 2){
		memcpy(foo, ptr, 2);
		sscanf(foo, "%hhx", &tmp);
		memcpy(p, &tmp, 1);
		p++;
	}

	return ret;
}

unsigned char *
decode_msisdn(unsigned char *ptr, unsigned char len){
	int i;
	unsigned char *ret = NULL;
	unsigned char *tmp = NULL;
	if((ret = malloc(len)) == NULL)
		return NULL;

	memset(ret, 0, len);
	tmp = ret;

	for(i = 0; i< (len / 2) + (len % 2);i++){
		*ret = (ptr[i] & 0x0f) + 48;
		if((ptr[i] >> 4) != 0x0f){
			ret++;
			*ret = (ptr[i] >> 4) + 48;
			ret++;
		}
	}

	return tmp;
}

unsigned char *
parse_pdu_header(sms_t *csms, unsigned char *ptr){
	unsigned char *tmp;
	csms->tp_rp   = (*ptr & (1<<7)) ? 1 : 0;
	csms->tp_udhi = (*ptr & (1<<6)) ? 1 : 0;
	csms->tp_srr  = (*ptr & (1<<5)) ? 1 : 0;
	csms->tp_vpf  = (*ptr & (1<<4)) | (*ptr & (1<<3)) ? 1 : 0;
	csms->tp_rd   = (*ptr & (1<<2)) ? 1 : 0;
	csms->tp_mti  = (*ptr & (1<<1)) | (*ptr & (1<<0));

	ptr++;
	csms->msg_ref = *ptr;
	ptr++;
	csms->msisdn_l = *ptr;
	ptr++;
	csms->msisdn_t = *ptr;
	ptr++;
	tmp = ptr;

	csms->msisdn = malloc(csms->msisdn_l + 1);
	if(!csms->msisdn)
		return NULL;

	memcpy(csms->msisdn, ptr, csms->msisdn_l);
	csms->msisdn[csms->msisdn_l] = 0;

	ptr += csms->msisdn_l / 2 + (csms->msisdn_l % 2);
	csms->tp_pid = *ptr;
	ptr++;
	csms->tp_dcs = *ptr;

	if(csms->tp_vpf){
	/* optional flag, assuming it's one byte */
		ptr++;
		csms->tp_vp = *ptr;
	}

	ptr++;
	csms->tp_ud_l = *ptr;
	ptr++;
	return ptr;
}

ie_t *
add_information_element(unsigned char *ptr, unsigned char iel, unsigned char iet){
	ie_t *ie = malloc(sizeof(ie_t));
	if(!ie)
		return NULL;

	ie->ie_l = iel;
	ie->ie_type = iet;
	memset(ie->data, 0, ie->ie_l);
	memcpy(ie->data, ptr, ie->ie_l);

	return ie;
}

ie_t *
parse_information_elements(unsigned char *ptr, unsigned char udh_l){
	ie_t *ie = NULL;
	ie_t *ret = NULL;
	ie_t *tmp = NULL;
	unsigned char iel;
	unsigned char iet;
	unsigned char i = 0;

	while(i < udh_l){
		iet = *ptr;
		ptr++;
		iel = *ptr;
		ptr++;
		ie = add_information_element(ptr, iel, iet);
		if(ret == NULL)
			ret = ie;
		else
			tmp->next = (struct ie_t*) ie;

		tmp = ie;
		ie = (ie_t *) ie->next;

		ptr += iel;
		i += iel + 2;
	}

	return ret;
}

void
print_udh(sms_t *csms){
	udh_t *udh = csms->udh;
	ie_t *ie = udh->head;
	int i;
	while(ie){
		ie_t *tmp = ie;
		printf("IEL: %0.2x, IET: %0.2x, ", ie->ie_l, ie->ie_type);
		printf("IED: ");
		for(i = 0; i < ie->ie_l; i++){
			printf("%0.2x", ie->data[i]);
		}
		ie = (ie_t *) tmp->next;
		printf("\n");
	}
}

void
print_ud(sms_t *csms, unsigned char *ptr){
	size_t l = csms->tp_ud_l;
	size_t i;

	/* 7 bit encoding...  */
	if(!(csms->tp_dcs >> 2) & 0x03)
		l = l*7/8 + 1;

	if(csms->tp_udhi){
		l = l - csms->udh->udh_l - 1;
	}

	printf("decoding %0.2x hex bytes user data\n", l);

	for(i = 0; i < l; i++){
		printf("%0.2x", ptr[i]);
	}
	printf("\n");
}

unsigned char *
parse_udh(sms_t *csms, unsigned char *ptr){
	udh_t *udh;
	csms->udh = malloc(sizeof(udh_t));
	udh = csms->udh;

	if(!udh)
		return NULL;

	udh->udh_l = *ptr;
	ptr++;
	udh->head = parse_information_elements(ptr, udh->udh_l);

	if(!udh->head){
		printf("error in parsing information elements\n");
		return NULL;
	}

	ptr += udh->udh_l;

	return ptr;
}

void
destroy_sms(sms_t *csms){
	ie_t *ie = NULL;
	ie_t *tmp;
	if(csms->tp_udhi){
		ie = csms->udh->head;
		while(ie){
			tmp = (ie_t *) ie->next;
			free(ie);
			ie = tmp;
		}
	}
	free(csms->msisdn);
	free(csms->udh);
	free(csms);
}
