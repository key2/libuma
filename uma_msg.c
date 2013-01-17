/*
   Copyright (C) 2010 Ramtin Amin <keytwo@gmail.com>
   See COPYING file for license details
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "iei_types.h"
#include "ga_types.h"
#include "uma_msg.h"
#include "tlv.h"


struct uma_msg_s *uma_create_msg(u_int8_t type, u_int8_t skip, u_int8_t pd)
{
	struct uma_msg_s *msg;
	msg = (struct uma_msg_s *)malloc(sizeof(struct uma_msg_s));
	memset(msg,0,sizeof(struct uma_msg_s));
	msg->msgtype = type;
	msg->pd = pd;
	msg->skip = skip;
	return msg;
}


struct uma_msg_s *uma_parse_msg(u_int8_t *buf, u_int32_t len)
{
	struct uma_msg_s *msg;
	u_int8_t *pnt;
	u_int32_t tmplen;
	if(len <4)
		return NULL;

	msg = (struct uma_msg_s*)malloc(sizeof(struct uma_msg_s));
	memset(msg,0,sizeof(struct uma_msg_s));
	msg->len = (buf[0] << 8) + buf[1];
	msg->skip = (buf[2] >> 4) & 0xf;
	msg->pd = buf[2] & 0xf;
	msg->msgtype = buf[3];
	pnt = buf + 4;

	while(pnt < buf + len - 2){
		tmplen = tlv_get_len(pnt) + 1;
		if(pnt[1] & 0x80)
			tmplen += pnt[1] * 0x7f;
		else
			tmplen += 1;
		msg->tlv[msg->ntlv] = (u_int8_t *)malloc(tmplen);
		memcpy(msg->tlv[msg->ntlv],pnt,tmplen);
		pnt += tmplen;
		msg->ntlv++;
	}
	return msg;
}

void uma_delete_msg(struct uma_msg_s *msg)
{
	u_int32_t i;

	for(i = 0; i < msg->ntlv; i++){
		free(msg->tlv[i]);
		msg->tlv[i] = NULL;
	}
	free(msg);
	msg = NULL;
}

u_int32_t uma_create_buffer(u_int8_t **buf, struct uma_msg_s *msg)
{
	u_int32_t i;
	u_int32_t len=0;
	u_int8_t *pnt;
	for(i = 0; i < msg->ntlv; i++){
		len += tlv_get_header_len(msg->tlv[i]);
		len += tlv_get_len(msg->tlv[i]);
	}
	len += 2; /* add the UMA header len =  skip/pd + msg_type = 2*/
	*buf = (u_int8_t*)malloc(len+1);
	pnt = *buf;
	*pnt++ = ((len) >> 8) & 0xff;
	*pnt++ = ((len) & 0xff);
	*pnt++ = (msg->skip << 4) | ( msg->pd & 0x0F);
	*pnt++ = (msg->msgtype);
	for(i=0; i < msg->ntlv; i++){
		memcpy(pnt,msg->tlv[i],tlv_get_header_len(msg->tlv[i]) + tlv_get_len(msg->tlv[i]));
		pnt += tlv_get_header_len(msg->tlv[i]) + tlv_get_len(msg->tlv[i]);
	}
	return len +2;
}

void tlv_write_len(u_int8_t *buf, u_int32_t len)
{
	u_int8_t lenc=0;	
	int i;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	if(lenc > 0){
		buf[0] = 0x80 | lenc;
		for(i = 0; i < lenc; i++){
			buf[i+1] = (len >> (8*(lenc - i - 1))) & 0xff;
		}
	} else {
		buf[0] = len & 0xff;
	}
}


/*  Mobile Identity  1 */
u_int8_t *create_IEI_Mobile_Identity(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_Mobile_Identity *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Mobile_Identity;
	msg = (struct IEI_Mobile_Identity*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  GAN Release Indicator  2 */
u_int8_t *create_IEI_GAN_Release_Indicator(u_int8_t URI)
{
	struct IEI_GAN_Release_Indicator *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Release_Indicator;
	msg = (struct IEI_GAN_Release_Indicator*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->URI = URI;

	return buf;
}

/*  Radio Identity  3 */
u_int8_t *create_IEI_Radio_Identity(u_int8_t type, u_int8_t *value)
{
	struct IEI_Radio_Identity *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 9;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Radio_Identity;
	msg = (struct IEI_Radio_Identity*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->type = type;
	memcpy(msg->value, value, 6);

	return buf;
}

/*  GERAN Cell Identity  4 */
u_int8_t *create_IEI_GERAN_Cell_Identity(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_GERAN_Cell_Identity *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GERAN_Cell_Identity;
	msg = (struct IEI_GERAN_Cell_Identity*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  Location Area Identification  5 */
u_int8_t *create_IEI_Location_Area_Identification(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_Location_Area_Identification *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Location_Area_Identification;
	msg = (struct IEI_Location_Area_Identification*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  GERAN UTRAN coverage Indicator  6 */
u_int8_t *create_IEI_GERAN_UTRAN_coverage_Indicator(u_int8_t CGI)
{
	struct IEI_GERAN_UTRAN_coverage_Indicator *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GERAN_UTRAN_coverage_Indicator;
	msg = (struct IEI_GERAN_UTRAN_coverage_Indicator*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->CGI = CGI;

	return buf;
}

/*  GAN Classmark  7 */
u_int8_t *create_IEI_GAN_Classmark(u_int8_t TGA, u_int8_t GC, u_int8_t UC, u_int8_t RRS, u_int8_t PS_HA, u_int8_t GMSI)
{
	struct IEI_GAN_Classmark *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Classmark;
	msg = (struct IEI_GAN_Classmark*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->TGA = TGA;
	msg->GC = GC;
	msg->UC = UC;
	msg->RRS = RRS;
	msg->PS_HA = PS_HA;
	msg->GMSI = GMSI;

	return buf;
}

/*  Geographical Location  8 */
u_int8_t *create_IEI_Geographical_Location(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_Geographical_Location *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Geographical_Location;
	msg = (struct IEI_Geographical_Location*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  GANC SEGW IP Address  9 */
u_int8_t *create_IEI_GANC_SEGW_IP_Address(u_int8_t ip_type, u_int8_t *address, u_int32_t address_len)
{
	struct IEI_GANC_SEGW_IP_Address *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + address_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GANC_SEGW_IP_Address;
	msg = (struct IEI_GANC_SEGW_IP_Address*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->ip_type = ip_type;
	memcpy(msg->address, address, address_len);

	return buf;
}

/*  GANC SEGW Fully Qualified Domain Host Name  10 */
u_int8_t *create_IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name(u_int8_t *fqdn, u_int32_t fqdn_len)
{
	struct IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + fqdn_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GANC_SEGW_Fully_Qualified_Domain_Host_Name;
	msg = (struct IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->fqdn, fqdn, fqdn_len);

	return buf;
}

/*  Redirection Counter  11 */
u_int8_t *create_IEI_Redirection_Counter(u_int8_t redircnt)
{
	struct IEI_Redirection_Counter *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Redirection_Counter;
	msg = (struct IEI_Redirection_Counter*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->redircnt = redircnt;

	return buf;
}

/*  Discovery Reject Cause  12 */
u_int8_t *create_IEI_Discovery_Reject_Cause(u_int8_t discrej)
{
	struct IEI_Discovery_Reject_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Discovery_Reject_Cause;
	msg = (struct IEI_Discovery_Reject_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->discrej = discrej;

	return buf;
}

/*  GAN Cell Description  13 */
u_int8_t *create_IEI_GAN_Cell_Description(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_GAN_Cell_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Cell_Description;
	msg = (struct IEI_GAN_Cell_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  GAN Control Channel Description  14 */
u_int8_t *create_IEI_GAN_Control_Channel_Description(u_int8_t ECMC, u_int8_t NMO, u_int8_t GPRS, u_int8_t DTM, u_int8_t ATT, u_int8_t MSCR, u_int8_t T3212, u_int8_t RAC, u_int8_t SGSNR, u_int8_t ECMP, u_int8_t RE, u_int8_t PFCFM, u_int8_t _3GECS, u_int8_t PS_HA, u_int8_t ACC8, u_int8_t ACC9, u_int8_t ACC10, u_int8_t ACC11, u_int8_t ACC12, u_int8_t ACC13, u_int8_t ACC14, u_int8_t ACC15, u_int8_t ACC0, u_int8_t ACC1, u_int8_t ACC2, u_int8_t ACC3, u_int8_t ACC4, u_int8_t ACC5, u_int8_t ACC6, u_int8_t ACC7)
{
	struct IEI_GAN_Control_Channel_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 8;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Control_Channel_Description;
	msg = (struct IEI_GAN_Control_Channel_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->ECMC = ECMC;
	msg->NMO = NMO;
	msg->GPRS = GPRS;
	msg->DTM = DTM;
	msg->ATT = ATT;
	msg->MSCR = MSCR;
	msg->T3212 = T3212;
	msg->RAC = RAC;
	msg->SGSNR = SGSNR;
	msg->ECMP = ECMP;
	msg->RE = RE;
	msg->PFCFM = PFCFM;
	msg->_3GECS = _3GECS;
	msg->PS_HA = PS_HA;
	msg->ACC8 = ACC8;
	msg->ACC9 = ACC9;
	msg->ACC10 = ACC10;
	msg->ACC11 = ACC11;
	msg->ACC12 = ACC12;
	msg->ACC13 = ACC13;
	msg->ACC14 = ACC14;
	msg->ACC15 = ACC15;
	msg->ACC0 = ACC0;
	msg->ACC1 = ACC1;
	msg->ACC2 = ACC2;
	msg->ACC3 = ACC3;
	msg->ACC4 = ACC4;
	msg->ACC5 = ACC5;
	msg->ACC6 = ACC6;
	msg->ACC7 = ACC7;

	return buf;
}

/*  Cell Identifier List  15 */
u_int8_t *create_IEI_Cell_Identifier_List(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_Cell_Identifier_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Cell_Identifier_List;
	msg = (struct IEI_Cell_Identifier_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  TU3907 Timer  16 */
u_int8_t *create_IEI_TU3907_Timer(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_TU3907_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU3907_Timer;
	msg = (struct IEI_TU3907_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  GSM RR UTRAN RRC State  17 */
u_int8_t *create_IEI_GSM_RR_UTRAN_RRC_State(u_int8_t GRS)
{
	struct IEI_GSM_RR_UTRAN_RRC_State *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GSM_RR_UTRAN_RRC_State;
	msg = (struct IEI_GSM_RR_UTRAN_RRC_State*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->GRS = GRS;

	return buf;
}

/*  Routing Area Identification  18 */
u_int8_t *create_IEI_Routing_Area_Identification(u_int8_t *RAI)
{
	struct IEI_Routing_Area_Identification *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 8;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Routing_Area_Identification;
	msg = (struct IEI_Routing_Area_Identification*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->RAI, RAI, 6);

	return buf;
}

/*  GAN Band  19 */
u_int8_t *create_IEI_GAN_Band(u_int8_t GANBand)
{
	struct IEI_GAN_Band *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Band;
	msg = (struct IEI_GAN_Band*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->GANBand = GANBand;

	return buf;
}

/*  GA RC GA CSR GA PSR State  20 */
u_int8_t *create_IEI_GA_RC_GA_CSR_GA_PSR_State(u_int8_t URS, u_int8_t UPS, u_int8_t GA_RRC_CS, u_int8_t GA_RRC_PS)
{
	struct IEI_GA_RC_GA_CSR_GA_PSR_State *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GA_RC_GA_CSR_GA_PSR_State;
	msg = (struct IEI_GA_RC_GA_CSR_GA_PSR_State*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->URS = URS;
	msg->UPS = UPS;
	msg->GA_RRC_CS = GA_RRC_CS;
	msg->GA_RRC_PS = GA_RRC_PS;

	return buf;
}

/*  Register Reject Cause  21 */
u_int8_t *create_IEI_Register_Reject_Cause(u_int8_t RRC)
{
	struct IEI_Register_Reject_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Register_Reject_Cause;
	msg = (struct IEI_Register_Reject_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RRC = RRC;

	return buf;
}

/*  TU3906 Timer  22 */
u_int8_t *create_IEI_TU3906_Timer(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_TU3906_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU3906_Timer;
	msg = (struct IEI_TU3906_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  TU3910 Timer  23 */
u_int8_t *create_IEI_TU3910_Timer(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_TU3910_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU3910_Timer;
	msg = (struct IEI_TU3910_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  TU3902 Timer  24 */
u_int8_t *create_IEI_TU3902_Timer(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_TU3902_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU3902_Timer;
	msg = (struct IEI_TU3902_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  L3 Message  26 */
u_int8_t *create_IEI_L3_Message(u_int8_t *l3, u_int32_t l3_len)
{
	struct IEI_L3_Message *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + l3_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = L3_Message;
	msg = (struct IEI_L3_Message*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->l3, l3, l3_len);

	return buf;
}

/*  Channel Mode  27 */
u_int8_t *create_IEI_Channel_Mode(u_int8_t *chanmode, u_int32_t chanmode_len)
{
	struct IEI_Channel_Mode *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + chanmode_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Channel_Mode;
	msg = (struct IEI_Channel_Mode*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->chanmode, chanmode, chanmode_len);

	return buf;
}

/*  Mobile Station Classmark 2  28 */
u_int8_t *create_IEI_Mobile_Station_Classmark_2(u_int8_t *msclass2, u_int32_t msclass2_len)
{
	struct IEI_Mobile_Station_Classmark_2 *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + msclass2_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Mobile_Station_Classmark_2;
	msg = (struct IEI_Mobile_Station_Classmark_2*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->msclass2, msclass2, msclass2_len);

	return buf;
}

/*  RR Cause  29 */
u_int8_t *create_IEI_RR_Cause(u_int8_t *RRCause, u_int32_t RRCause_len)
{
	struct IEI_RR_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + RRCause_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = RR_Cause;
	msg = (struct IEI_RR_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->RRCause, RRCause, RRCause_len);

	return buf;
}

/*  Cipher Mode Setting  30 */
u_int8_t *create_IEI_Cipher_Mode_Setting(u_int8_t SC, u_int8_t algoID, u_int8_t soare)
{
	struct IEI_Cipher_Mode_Setting *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Cipher_Mode_Setting;
	msg = (struct IEI_Cipher_Mode_Setting*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->SC = SC;
	msg->algoID = algoID;
	msg->soare = soare;

	return buf;
}

/*  GPRS Resumption  31 */
u_int8_t *create_IEI_GPRS_Resumption(u_int8_t *GPRSRes, u_int32_t GPRSRes_len)
{
	struct IEI_GPRS_Resumption *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + GPRSRes_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GPRS_Resumption;
	msg = (struct IEI_GPRS_Resumption*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->GPRSRes, GPRSRes, GPRSRes_len);

	return buf;
}

/*  Handover From GAN Command  32 */
u_int8_t *create_IEI_Handover_From_GAN_Command(u_int8_t *HoFGComm, u_int32_t HoFGComm_len)
{
	struct IEI_Handover_From_GAN_Command *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + HoFGComm_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Handover_From_GAN_Command;
	msg = (struct IEI_Handover_From_GAN_Command*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->HoFGComm, HoFGComm, HoFGComm_len);

	return buf;
}

/*  UL Quality Indication  33 */
u_int8_t *create_IEI_UL_Quality_Indication(u_int8_t ULQI)
{
	struct IEI_UL_Quality_Indication *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = UL_Quality_Indication;
	msg = (struct IEI_UL_Quality_Indication*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->ULQI = ULQI;

	return buf;
}

/*  TLLI  34 */
u_int8_t *create_IEI_TLLI(u_int8_t *TLLIm, u_int32_t TLLIm_len)
{
	struct IEI_TLLI *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + TLLIm_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TLLI;
	msg = (struct IEI_TLLI*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->TLLIm, TLLIm, TLLIm_len);

	return buf;
}

/*  Packet Flow Identifier  35 */
u_int8_t *create_IEI_Packet_Flow_Identifier(u_int8_t *PFID, u_int32_t PFID_len)
{
	struct IEI_Packet_Flow_Identifier *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + PFID_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Packet_Flow_Identifier;
	msg = (struct IEI_Packet_Flow_Identifier*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->PFID, PFID, PFID_len);

	return buf;
}

/*  Suspension Cause  36 */
u_int8_t *create_IEI_Suspension_Cause(u_int8_t *caue, u_int32_t caue_len)
{
	struct IEI_Suspension_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + caue_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Suspension_Cause;
	msg = (struct IEI_Suspension_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->caue, caue, caue_len);

	return buf;
}

/*  TU3920 Timer  37 */
u_int8_t *create_IEI_TU3920_Timer(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_TU3920_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU3920_Timer;
	msg = (struct IEI_TU3920_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  QoS  38 */
u_int8_t *create_IEI_QoS(u_int8_t PEAK_TROUGHPOUT_CLASS, u_int8_t RADIO_PRIORITY, u_int8_t RLC_MODE)
{
	struct IEI_QoS *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = QoS;
	msg = (struct IEI_QoS*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->PEAK_TROUGHPOUT_CLASS = PEAK_TROUGHPOUT_CLASS;
	msg->RADIO_PRIORITY = RADIO_PRIORITY;
	msg->RLC_MODE = RLC_MODE;

	return buf;
}

/*  GA PSR Cause  39 */
u_int8_t *create_IEI_GA_PSR_Cause(u_int8_t cause)
{
	struct IEI_GA_PSR_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GA_PSR_Cause;
	msg = (struct IEI_GA_PSR_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->cause = cause;

	return buf;
}

/*  User Data Rate  40 */
u_int8_t *create_IEI_User_Data_Rate(u_int8_t *R)
{
	struct IEI_User_Data_Rate *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 5;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = User_Data_Rate;
	msg = (struct IEI_User_Data_Rate*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->R, R, 3);

	return buf;
}

/*  Routing Area Code  41 */
u_int8_t *create_IEI_Routing_Area_Code(u_int8_t code)
{
	struct IEI_Routing_Area_Code *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Routing_Area_Code;
	msg = (struct IEI_Routing_Area_Code*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->code = code;

	return buf;
}

/*  AP Location  42 */
u_int8_t *create_IEI_AP_Location(u_int8_t *APLoc, u_int32_t APLoc_len)
{
	struct IEI_AP_Location *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + APLoc_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = AP_Location;
	msg = (struct IEI_AP_Location*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->APLoc, APLoc, APLoc_len);

	return buf;
}

/*  TU4001 Timer  43 */
u_int8_t *create_IEI_TU4001_Timer(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_TU4001_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU4001_Timer;
	msg = (struct IEI_TU4001_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  Location Status  44 */
u_int8_t *create_IEI_Location_Status(u_int8_t LS)
{
	struct IEI_Location_Status *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Location_Status;
	msg = (struct IEI_Location_Status*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->LS = LS;

	return buf;
}

/*  Cipher Response  45 */
u_int8_t *create_IEI_Cipher_Response(u_int8_t CR)
{
	struct IEI_Cipher_Response *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Cipher_Response;
	msg = (struct IEI_Cipher_Response*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->CR = CR;

	return buf;
}

/*  Ciphering Command RAND  46 */
u_int8_t *create_IEI_Ciphering_Command_RAND(u_int8_t *CipherRand)
{
	struct IEI_Ciphering_Command_RAND *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 18;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Ciphering_Command_RAND;
	msg = (struct IEI_Ciphering_Command_RAND*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->CipherRand, CipherRand, 16);

	return buf;
}

/*  Ciphering Command MAC  47 */
u_int8_t *create_IEI_Ciphering_Command_MAC(u_int8_t *MAC)
{
	struct IEI_Ciphering_Command_MAC *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 14;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Ciphering_Command_MAC;
	msg = (struct IEI_Ciphering_Command_MAC*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->MAC, MAC, 12);

	return buf;
}

/*  Ciphering Key Sequence Number  48 */
u_int8_t *create_IEI_Ciphering_Key_Sequence_Number(u_int8_t keyseq)
{
	struct IEI_Ciphering_Key_Sequence_Number *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Ciphering_Key_Sequence_Number;
	msg = (struct IEI_Ciphering_Key_Sequence_Number*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->keyseq = keyseq;

	return buf;
}

/*  SAPI ID  49 */
u_int8_t *create_IEI_SAPI_ID(u_int8_t SapiID)
{
	struct IEI_SAPI_ID *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = SAPI_ID;
	msg = (struct IEI_SAPI_ID*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->SapiID = SapiID;

	return buf;
}

/*  Establishment Cause  50 */
u_int8_t *create_IEI_Establishment_Cause(u_int8_t cause)
{
	struct IEI_Establishment_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Establishment_Cause;
	msg = (struct IEI_Establishment_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->cause = cause;

	return buf;
}

/*  Channel Needed  51 */
u_int8_t *create_IEI_Channel_Needed(u_int8_t Chan)
{
	struct IEI_Channel_Needed *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Channel_Needed;
	msg = (struct IEI_Channel_Needed*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->Chan = Chan;

	return buf;
}

/*  PDU in Error  52 */
u_int8_t *create_IEI_PDU_in_Error(u_int8_t *PDU, u_int32_t PDU_len)
{
	struct IEI_PDU_in_Error *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + PDU_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PDU_in_Error;
	msg = (struct IEI_PDU_in_Error*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->PDU, PDU, PDU_len);

	return buf;
}

/*  Sample Size  53 */
u_int8_t *create_IEI_Sample_Size(u_int8_t samplesize)
{
	struct IEI_Sample_Size *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Sample_Size;
	msg = (struct IEI_Sample_Size*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->samplesize = samplesize;

	return buf;
}

/*  Payload Type  54 */
u_int8_t *create_IEI_Payload_Type(u_int8_t payloadtype)
{
	struct IEI_Payload_Type *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Payload_Type;
	msg = (struct IEI_Payload_Type*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->payloadtype = payloadtype;

	return buf;
}

/*  Multi rate Configuration  55 */
u_int8_t *create_IEI_Multi_rate_Configuration(u_int8_t *multiconf, u_int32_t multiconf_len)
{
	struct IEI_Multi_rate_Configuration *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + multiconf_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Multi_rate_Configuration;
	msg = (struct IEI_Multi_rate_Configuration*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->multiconf, multiconf, multiconf_len);

	return buf;
}

/*  Mobile Station Classmar 3  56 */
u_int8_t *create_IEI_Mobile_Station_Classmar_3(u_int8_t ClassMark3)
{
	struct IEI_Mobile_Station_Classmar_3 *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Mobile_Station_Classmar_3;
	msg = (struct IEI_Mobile_Station_Classmar_3*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->ClassMark3 = ClassMark3;

	return buf;
}

/*  LLC PDU  57 */
u_int8_t *create_IEI_LLC_PDU(u_int8_t *llcpdu, u_int32_t llcpdu_len)
{
	struct IEI_LLC_PDU *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + llcpdu_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = LLC_PDU;
	msg = (struct IEI_LLC_PDU*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->llcpdu, llcpdu, llcpdu_len);

	return buf;
}

/*  Location Black List indicator  58 */
u_int8_t *create_IEI_Location_Black_List_indicator(u_int8_t LBLI)
{
	struct IEI_Location_Black_List_indicator *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Location_Black_List_indicator;
	msg = (struct IEI_Location_Black_List_indicator*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->LBLI = LBLI;

	return buf;
}

/*  Reset Indicator  59 */
u_int8_t *create_IEI_Reset_Indicator(u_int8_t RI)
{
	struct IEI_Reset_Indicator *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Reset_Indicator;
	msg = (struct IEI_Reset_Indicator*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RI = RI;

	return buf;
}

/*  TU4003 Timer  60 */
u_int8_t *create_IEI_TU4003_Timer(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_TU4003_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU4003_Timer;
	msg = (struct IEI_TU4003_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  AP Service Name  61 */
u_int8_t *create_IEI_AP_Service_Name(u_int8_t *AP, u_int32_t AP_len)
{
	struct IEI_AP_Service_Name *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + AP_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = AP_Service_Name;
	msg = (struct IEI_AP_Service_Name*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->AP, AP, AP_len);

	return buf;
}

/*  GAN Service Zone Information  62 */
u_int8_t *create_IEI_GAN_Service_Zone_Information(u_int8_t GanzoneID, u_int8_t Len, u_int8_t *GANstr, u_int32_t GANstr_len)
{
	struct IEI_GAN_Service_Zone_Information *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4 + GANstr_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Service_Zone_Information;
	msg = (struct IEI_GAN_Service_Zone_Information*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->GanzoneID = GanzoneID;
	msg->Len = Len;
	memcpy(msg->GANstr, GANstr, GANstr_len);

	return buf;
}

/*  RTP Redundancy Configuration  63 */
u_int8_t *create_IEI_RTP_Redundancy_Configuration(u_int8_t winsize, u_int8_t ganlumode, u_int8_t ganmode)
{
	struct IEI_RTP_Redundancy_Configuration *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = RTP_Redundancy_Configuration;
	msg = (struct IEI_RTP_Redundancy_Configuration*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->winsize = winsize;
	msg->ganlumode = ganlumode;
	msg->ganmode = ganmode;

	return buf;
}

/*  UTRAN Classmark  64 */
u_int8_t *create_IEI_UTRAN_Classmark(u_int8_t *classmark, u_int32_t classmark_len)
{
	struct IEI_UTRAN_Classmark *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + classmark_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = UTRAN_Classmark;
	msg = (struct IEI_UTRAN_Classmark*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->classmark, classmark, classmark_len);

	return buf;
}

/*  Classmark Enquiry Mask  65 */
u_int8_t *create_IEI_Classmark_Enquiry_Mask(u_int8_t *mask, u_int32_t mask_len)
{
	struct IEI_Classmark_Enquiry_Mask *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + mask_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Classmark_Enquiry_Mask;
	msg = (struct IEI_Classmark_Enquiry_Mask*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->mask, mask, mask_len);

	return buf;
}

/*  UTRAN Cell Identifier List  66 */
u_int8_t *create_IEI_UTRAN_Cell_Identifier_List(u_int8_t celldesc, u_int8_t *utrancellid, u_int32_t utrancellid_len)
{
	struct IEI_UTRAN_Cell_Identifier_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + utrancellid_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = UTRAN_Cell_Identifier_List;
	msg = (struct IEI_UTRAN_Cell_Identifier_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->celldesc = celldesc;
	memcpy(msg->utrancellid, utrancellid, utrancellid_len);

	return buf;
}

/*  Serving GANC table indicator  67 */
u_int8_t *create_IEI_Serving_GANC_table_indicator(u_int8_t SUTI)
{
	struct IEI_Serving_GANC_table_indicator *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Serving_GANC_table_indicator;
	msg = (struct IEI_Serving_GANC_table_indicator*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->SUTI = SUTI;

	return buf;
}

/*  Registration indicators  68 */
u_int8_t *create_IEI_Registration_indicators(u_int8_t MPS)
{
	struct IEI_Registration_indicators *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Registration_indicators;
	msg = (struct IEI_Registration_indicators*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MPS = MPS;

	return buf;
}

/*  GAN PLMN List  69 */
u_int8_t *create_IEI_GAN_PLMN_List(u_int8_t PLMNnumb, u_int8_t *PLMN, u_int32_t PLMN_len)
{
	struct IEI_GAN_PLMN_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + PLMN_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_PLMN_List;
	msg = (struct IEI_GAN_PLMN_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->PLMNnumb = PLMNnumb;
	memcpy(msg->PLMN, PLMN, PLMN_len);

	return buf;
}

/*  Required GAN Services  71 */
u_int8_t *create_IEI_Required_GAN_Services(u_int8_t CBS)
{
	struct IEI_Required_GAN_Services *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Required_GAN_Services;
	msg = (struct IEI_Required_GAN_Services*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->CBS = CBS;

	return buf;
}

/*  Broadcast Container  72 */
u_int8_t *create_IEI_Broadcast_Container(u_int8_t nCBS, u_int8_t *CBSFrames, u_int32_t CBSFrames_len)
{
	struct IEI_Broadcast_Container *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + CBSFrames_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Broadcast_Container;
	msg = (struct IEI_Broadcast_Container*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nCBS = nCBS;
	memcpy(msg->CBSFrames, CBSFrames, CBSFrames_len);

	return buf;
}

/*  Cell 3G Identity  73 */
u_int8_t *create_IEI_Cell_3G_Identity(u_int8_t *CellID)
{
	struct IEI_Cell_3G_Identity *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 6;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Cell_3G_Identity;
	msg = (struct IEI_Cell_3G_Identity*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->CellID, CellID, 4);

	return buf;
}

/*  Security Capability 3G  74 */
u_int8_t *create_IEI_Security_Capability_3G(u_int8_t ciph_algo_cap, u_int8_t ciph_algo_cap2, u_int8_t integ_protec_algo, u_int8_t integ_protec_algo2)
{
	struct IEI_Security_Capability_3G *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 6;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Security_Capability_3G;
	msg = (struct IEI_Security_Capability_3G*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->ciph_algo_cap = ciph_algo_cap;
	msg->ciph_algo_cap2 = ciph_algo_cap2;
	msg->integ_protec_algo = integ_protec_algo;
	msg->integ_protec_algo2 = integ_protec_algo2;

	return buf;
}

/*  NAS Synchronisation Indicator  75 */
u_int8_t *create_IEI_NAS_Synchronisation_Indicator(u_int8_t NSI)
{
	struct IEI_NAS_Synchronisation_Indicator *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = NAS_Synchronisation_Indicator;
	msg = (struct IEI_NAS_Synchronisation_Indicator*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->NSI = NSI;

	return buf;
}

/*  GANC TEID  76 */
u_int8_t *create_IEI_GANC_TEID(u_int8_t *TEID)
{
	struct IEI_GANC_TEID *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 6;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GANC_TEID;
	msg = (struct IEI_GANC_TEID*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->TEID, TEID, 4);

	return buf;
}

/*  MS TEID  77 */
u_int8_t *create_IEI_MS_TEID(u_int8_t *TEID)
{
	struct IEI_MS_TEID *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 6;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = MS_TEID;
	msg = (struct IEI_MS_TEID*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->TEID, TEID, 4);

	return buf;
}

/*  UTRAN RRC Message  78 */
u_int8_t *create_IEI_UTRAN_RRC_Message(u_int8_t *RRCmsg, u_int32_t RRCmsg_len)
{
	struct IEI_UTRAN_RRC_Message *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + RRCmsg_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = UTRAN_RRC_Message;
	msg = (struct IEI_UTRAN_RRC_Message*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->RRCmsg, RRCmsg, RRCmsg_len);

	return buf;
}

/*  GAN Mode Indicator  79 */
u_int8_t *create_IEI_GAN_Mode_Indicator(u_int8_t GMI)
{
	struct IEI_GAN_Mode_Indicator *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Mode_Indicator;
	msg = (struct IEI_GAN_Mode_Indicator*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->GMI = GMI;

	return buf;
}

/*  CN Domain Identity  80 */
u_int8_t *create_IEI_CN_Domain_Identity(u_int8_t CNDI)
{
	struct IEI_CN_Domain_Identity *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CN_Domain_Identity;
	msg = (struct IEI_CN_Domain_Identity*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->CNDI = CNDI;

	return buf;
}

/*  GAN Iu Mode Cell Description  81 */
u_int8_t *create_IEI_GAN_Iu_Mode_Cell_Description(u_int8_t UARFCN, u_int8_t UARFCN2, u_int8_t PSC, u_int8_t PSC2)
{
	struct IEI_GAN_Iu_Mode_Cell_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 6;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GAN_Iu_Mode_Cell_Description;
	msg = (struct IEI_GAN_Iu_Mode_Cell_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->UARFCN = UARFCN;
	msg->UARFCN2 = UARFCN2;
	msg->PSC = PSC;
	msg->PSC2 = PSC2;

	return buf;
}

/*  UARFCN 3G  82 */
u_int8_t *create_IEI_UARFCN_3G(u_int8_t UARFCN, u_int8_t UARFCN2)
{
	struct IEI_UARFCN_3G *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = UARFCN_3G;
	msg = (struct IEI_UARFCN_3G*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->UARFCN = UARFCN;
	msg->UARFCN2 = UARFCN2;

	return buf;
}

/*  RAB ID  83 */
u_int8_t *create_IEI_RAB_ID(u_int8_t RABID)
{
	struct IEI_RAB_ID *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = RAB_ID;
	msg = (struct IEI_RAB_ID*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RABID = RABID;

	return buf;
}

/*  RAB ID List  84 */
u_int8_t *create_IEI_RAB_ID_List(u_int8_t nRABID, u_int8_t *RAIDList, u_int32_t RAIDList_len)
{
	struct IEI_RAB_ID_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + RAIDList_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = RAB_ID_List;
	msg = (struct IEI_RAB_ID_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nRABID = nRABID;
	memcpy(msg->RAIDList, RAIDList, RAIDList_len);

	return buf;
}

/*  GA RRC Establishment Cause  85 */
u_int8_t *create_IEI_GA_RRC_Establishment_Cause(u_int8_t cause)
{
	struct IEI_GA_RRC_Establishment_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GA_RRC_Establishment_Cause;
	msg = (struct IEI_GA_RRC_Establishment_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->cause = cause;

	return buf;
}

/*  GA RRC Cause  86 */
u_int8_t *create_IEI_GA_RRC_Cause(u_int8_t cause_MSB, u_int8_t cause_LSB)
{
	struct IEI_GA_RRC_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GA_RRC_Cause;
	msg = (struct IEI_GA_RRC_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->cause_MSB = cause_MSB;
	msg->cause_LSB = cause_LSB;

	return buf;
}

/*  GA RRC Paging Cause  87 */
u_int8_t *create_IEI_GA_RRC_Paging_Cause(u_int8_t pagingcause)
{
	struct IEI_GA_RRC_Paging_Cause *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GA_RRC_Paging_Cause;
	msg = (struct IEI_GA_RRC_Paging_Cause*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->pagingcause = pagingcause;

	return buf;
}

/*  Intra Domain NAS Node Selector  88 */
u_int8_t *create_IEI_Intra_Domain_NAS_Node_Selector(u_int8_t type, u_int8_t routparam, u_int8_t routparam2)
{
	struct IEI_Intra_Domain_NAS_Node_Selector *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 5;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Intra_Domain_NAS_Node_Selector;
	msg = (struct IEI_Intra_Domain_NAS_Node_Selector*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->type = type;
	msg->routparam = routparam;
	msg->routparam2 = routparam2;

	return buf;
}

/*  CTC Activation List  89 */
u_int8_t *create_IEI_CTC_Activation_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len)
{
	struct IEI_CTC_Activation_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + CTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CTC_Activation_List;
	msg = (struct IEI_CTC_Activation_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nCTC = nCTC;
	memcpy(msg->CTCs, CTCs, CTCs_len);

	return buf;
}

/*  CTC Description  90 */
u_int8_t *create_IEI_CTC_Description(u_int8_t RABID, u_int8_t GARConfig, u_int8_t SampleSize, u_int8_t RTPUDPPort, u_int8_t GanIpAddr, u_int8_t PayloadType, u_int8_t MultirateConfig2, u_int8_t RTPRedundancyConfig, u_int8_t RTCPUDPPort, u_int8_t NSI)
{
	struct IEI_CTC_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 12;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CTC_Description;
	msg = (struct IEI_CTC_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RABID = RABID;
	msg->GARConfig = GARConfig;
	msg->SampleSize = SampleSize;
	msg->RTPUDPPort = RTPUDPPort;
	msg->GanIpAddr = GanIpAddr;
	msg->PayloadType = PayloadType;
	msg->MultirateConfig2 = MultirateConfig2;
	msg->RTPRedundancyConfig = RTPRedundancyConfig;
	msg->RTCPUDPPort = RTCPUDPPort;
	msg->NSI = NSI;

	return buf;
}

/*  CTC Activation Ack List  91 */
u_int8_t *create_IEI_CTC_Activation_Ack_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len)
{
	struct IEI_CTC_Activation_Ack_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + CTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CTC_Activation_Ack_List;
	msg = (struct IEI_CTC_Activation_Ack_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nCTC = nCTC;
	memcpy(msg->CTCs, CTCs, CTCs_len);

	return buf;
}

/*  CTC Activation Ack Description  92 */
u_int8_t *create_IEI_CTC_Activation_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t RTPUDPPort, u_int8_t SampleSize, u_int8_t PAYLoadType, u_int8_t RTCPUDPPort)
{
	struct IEI_CTC_Activation_Ack_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 8;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CTC_Activation_Ack_Description;
	msg = (struct IEI_CTC_Activation_Ack_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RABID = RABID;
	msg->GARRCCause = GARRCCause;
	msg->RTPUDPPort = RTPUDPPort;
	msg->SampleSize = SampleSize;
	msg->PAYLoadType = PAYLoadType;
	msg->RTCPUDPPort = RTCPUDPPort;

	return buf;
}

/*  CTC Modification List  93 */
u_int8_t *create_IEI_CTC_Modification_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len)
{
	struct IEI_CTC_Modification_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + CTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CTC_Modification_List;
	msg = (struct IEI_CTC_Modification_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nCTC = nCTC;
	memcpy(msg->CTCs, CTCs, CTCs_len);

	return buf;
}

/*  CTC Modification Ack List  94 */
u_int8_t *create_IEI_CTC_Modification_Ack_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len)
{
	struct IEI_CTC_Modification_Ack_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + CTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CTC_Modification_Ack_List;
	msg = (struct IEI_CTC_Modification_Ack_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nCTC = nCTC;
	memcpy(msg->CTCs, CTCs, CTCs_len);

	return buf;
}

/*  CTC Modification Ack Description  95 */
u_int8_t *create_IEI_CTC_Modification_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t SampleSize)
{
	struct IEI_CTC_Modification_Ack_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 5;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CTC_Modification_Ack_Description;
	msg = (struct IEI_CTC_Modification_Ack_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RABID = RABID;
	msg->GARRCCause = GARRCCause;
	msg->SampleSize = SampleSize;

	return buf;
}

/*  MS Radio Identity  96 */
u_int8_t *create_IEI_MS_Radio_Identity(u_int8_t type, u_int8_t *value)
{
	struct IEI_MS_Radio_Identity *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 9;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = MS_Radio_Identity;
	msg = (struct IEI_MS_Radio_Identity*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->type = type;
	memcpy(msg->value, value, 6);

	return buf;
}

/*  GANC IP Address  97 */
u_int8_t *create_IEI_GANC_IP_Address(u_int8_t *IPAddr, u_int32_t IPAddr_len)
{
	struct IEI_GANC_IP_Address *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + IPAddr_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GANC_IP_Address;
	msg = (struct IEI_GANC_IP_Address*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->IPAddr, IPAddr, IPAddr_len);

	return buf;
}

/*  GANC Fully Qualified Domain Host Name  98 */
u_int8_t *create_IEI_GANC_Fully_Qualified_Domain_Host_Name(u_int8_t *fqdn, u_int32_t fqdn_len)
{
	struct IEI_GANC_Fully_Qualified_Domain_Host_Name *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + fqdn_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GANC_Fully_Qualified_Domain_Host_Name;
	msg = (struct IEI_GANC_Fully_Qualified_Domain_Host_Name*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->fqdn, fqdn, fqdn_len);

	return buf;
}

/*  IP address for GPRS user data transport  99 */
u_int8_t *create_IEI_IP_address_for_GPRS_user_data_transport(u_int8_t *IPAddr, u_int32_t IPAddr_len)
{
	struct IEI_IP_address_for_GPRS_user_data_transport *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + IPAddr_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = IP_address_for_GPRS_user_data_transport;
	msg = (struct IEI_IP_address_for_GPRS_user_data_transport*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->IPAddr, IPAddr, IPAddr_len);

	return buf;
}

/*  UDP Port for GPRS user data transport  100 */
u_int8_t *create_IEI_UDP_Port_for_GPRS_user_data_transport(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_UDP_Port_for_GPRS_user_data_transport *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = UDP_Port_for_GPRS_user_data_transport;
	msg = (struct IEI_UDP_Port_for_GPRS_user_data_transport*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  GANC TCP port  103 */
u_int8_t *create_IEI_GANC_TCP_port(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_GANC_TCP_port *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GANC_TCP_port;
	msg = (struct IEI_GANC_TCP_port*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  RTP UDP port  104 */
u_int8_t *create_IEI_RTP_UDP_port(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_RTP_UDP_port *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = RTP_UDP_port;
	msg = (struct IEI_RTP_UDP_port*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  RTCP UDP port  105 */
u_int8_t *create_IEI_RTCP_UDP_port(u_int8_t MSB, u_int8_t LSB)
{
	struct IEI_RTCP_UDP_port *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 4;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = RTCP_UDP_port;
	msg = (struct IEI_RTCP_UDP_port*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->MSB = MSB;
	msg->LSB = LSB;

	return buf;
}

/*  GERAN Received Signal Level List  106 */
u_int8_t *create_IEI_GERAN_Received_Signal_Level_List(u_int8_t *RXLEVELs, u_int32_t RXLEVELs_len)
{
	struct IEI_GERAN_Received_Signal_Level_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + RXLEVELs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = GERAN_Received_Signal_Level_List;
	msg = (struct IEI_GERAN_Received_Signal_Level_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->RXLEVELs, RXLEVELs, RXLEVELs_len);

	return buf;
}

/*  UTRAN Received Signal Level List  107 */
u_int8_t *create_IEI_UTRAN_Received_Signal_Level_List(u_int8_t *RSLL, u_int32_t RSLL_len)
{
	struct IEI_UTRAN_Received_Signal_Level_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + RSLL_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = UTRAN_Received_Signal_Level_List;
	msg = (struct IEI_UTRAN_Received_Signal_Level_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->RSLL, RSLL, RSLL_len);

	return buf;
}

/*  PS Handover to GERAN Command  108 */
u_int8_t *create_IEI_PS_Handover_to_GERAN_Command(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_PS_Handover_to_GERAN_Command *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PS_Handover_to_GERAN_Command;
	msg = (struct IEI_PS_Handover_to_GERAN_Command*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  PS Handover to UTRAN Command  109 */
u_int8_t *create_IEI_PS_Handover_to_UTRAN_Command(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_PS_Handover_to_UTRAN_Command *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PS_Handover_to_UTRAN_Command;
	msg = (struct IEI_PS_Handover_to_UTRAN_Command*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  PS Handover to GERAN PSI  110 */
u_int8_t *create_IEI_PS_Handover_to_GERAN_PSI(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_PS_Handover_to_GERAN_PSI *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PS_Handover_to_GERAN_PSI;
	msg = (struct IEI_PS_Handover_to_GERAN_PSI*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  PS Handover to GERAN SI  111 */
u_int8_t *create_IEI_PS_Handover_to_GERAN_SI(u_int8_t *data, u_int32_t data_len)
{
	struct IEI_PS_Handover_to_GERAN_SI *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + data_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PS_Handover_to_GERAN_SI;
	msg = (struct IEI_PS_Handover_to_GERAN_SI*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->data, data, data_len);

	return buf;
}

/*  TU4004 Timer  112 */
u_int8_t *create_IEI_TU4004_Timer(u_int8_t Tu4004val)
{
	struct IEI_TU4004_Timer *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = TU4004_Timer;
	msg = (struct IEI_TU4004_Timer*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->Tu4004val = Tu4004val;

	return buf;
}

/*  PTC Activation List  115 */
u_int8_t *create_IEI_PTC_Activation_List(u_int8_t nPTCS, u_int8_t *PTCs, u_int32_t PTCs_len)
{
	struct IEI_PTC_Activation_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + PTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PTC_Activation_List;
	msg = (struct IEI_PTC_Activation_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nPTCS = nPTCS;
	memcpy(msg->PTCs, PTCs, PTCs_len);

	return buf;
}

/*  PTC Description  116 */
u_int8_t *create_IEI_PTC_Description(u_int8_t RABID, u_int8_t RABConf, u_int8_t GANCTEID, u_int8_t MSTEID, u_int8_t GANCUDPPort, u_int8_t GANCIPADDR)
{
	struct IEI_PTC_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 8;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PTC_Description;
	msg = (struct IEI_PTC_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RABID = RABID;
	msg->RABConf = RABConf;
	msg->GANCTEID = GANCTEID;
	msg->MSTEID = MSTEID;
	msg->GANCUDPPort = GANCUDPPort;
	msg->GANCIPADDR = GANCIPADDR;

	return buf;
}

/*  PTC Activation Ack List  117 */
u_int8_t *create_IEI_PTC_Activation_Ack_List(u_int8_t nPTC, u_int8_t *PTCs, u_int32_t PTCs_len)
{
	struct IEI_PTC_Activation_Ack_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + PTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PTC_Activation_Ack_List;
	msg = (struct IEI_PTC_Activation_Ack_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nPTC = nPTC;
	memcpy(msg->PTCs, PTCs, PTCs_len);

	return buf;
}

/*  PTC Activation Ack Description  118 */
u_int8_t *create_IEI_PTC_Activation_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t MSUDPort)
{
	struct IEI_PTC_Activation_Ack_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 5;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PTC_Activation_Ack_Description;
	msg = (struct IEI_PTC_Activation_Ack_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RABID = RABID;
	msg->GARRCCause = GARRCCause;
	msg->MSUDPort = MSUDPort;

	return buf;
}

/*  PTC Modification List  119 */
u_int8_t *create_IEI_PTC_Modification_List(u_int8_t nPTC, u_int8_t *PTCs, u_int32_t PTCs_len)
{
	struct IEI_PTC_Modification_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + PTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PTC_Modification_List;
	msg = (struct IEI_PTC_Modification_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nPTC = nPTC;
	memcpy(msg->PTCs, PTCs, PTCs_len);

	return buf;
}

/*  PTC Modification Ack List  120 */
u_int8_t *create_IEI_PTC_Modification_Ack_List(u_int8_t nPTC, u_int8_t *PTCs, u_int32_t PTCs_len)
{
	struct IEI_PTC_Modification_Ack_List *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + PTCs_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PTC_Modification_Ack_List;
	msg = (struct IEI_PTC_Modification_Ack_List*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->nPTC = nPTC;
	memcpy(msg->PTCs, PTCs, PTCs_len);

	return buf;
}

/*  PTC Modification Ack Description  121 */
u_int8_t *create_IEI_PTC_Modification_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t RABConfig, u_int8_t GANUDPPort, u_int8_t GANCIPAddr)
{
	struct IEI_PTC_Modification_Ack_Description *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 7;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = PTC_Modification_Ack_Description;
	msg = (struct IEI_PTC_Modification_Ack_Description*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->RABID = RABID;
	msg->GARRCCause = GARRCCause;
	msg->RABConfig = RABConfig;
	msg->GANUDPPort = GANUDPPort;
	msg->GANCIPAddr = GANCIPAddr;

	return buf;
}

/*  RAB Configuration  122 */
u_int8_t *create_IEI_RAB_Configuration(u_int8_t TrafficClass, u_int8_t AI, u_int8_t DO, u_int8_t SSD, u_int8_t SI, u_int8_t TrafficHandlingPriority, u_int8_t *MaxDLBitRate, u_int8_t *MaxUlBitRate, u_int8_t *GuaranteedDlBitRate, u_int8_t *GuaranteedUlBitRate)
{
	struct IEI_RAB_Configuration *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 20;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = RAB_Configuration;
	msg = (struct IEI_RAB_Configuration*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->TrafficClass = TrafficClass;
	msg->AI = AI;
	msg->DO = DO;
	msg->SSD = SSD;
	msg->SI = SI;
	msg->TrafficHandlingPriority = TrafficHandlingPriority;
	memcpy(msg->MaxDLBitRate, MaxDLBitRate, 4);
	memcpy(msg->MaxUlBitRate, MaxUlBitRate, 4);
	memcpy(msg->GuaranteedDlBitRate, GuaranteedDlBitRate, 4);
	memcpy(msg->GuaranteedUlBitRate, GuaranteedUlBitRate, 4);

	return buf;
}

/*  Multi rate Configuration 2  123 */
u_int8_t *create_IEI_Multi_rate_Configuration_2(u_int8_t *MultiRateConf2, u_int32_t MultiRateConf2_len)
{
	struct IEI_Multi_rate_Configuration_2 *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + MultiRateConf2_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Multi_rate_Configuration_2;
	msg = (struct IEI_Multi_rate_Configuration_2*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->MultiRateConf2, MultiRateConf2, MultiRateConf2_len);

	return buf;
}

/*  Selected Integrity Protection Algorithm  124 */
u_int8_t *create_IEI_Selected_Integrity_Protection_Algorithm(u_int8_t IntegrityProtectionAlgo)
{
	struct IEI_Selected_Integrity_Protection_Algorithm *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Selected_Integrity_Protection_Algorithm;
	msg = (struct IEI_Selected_Integrity_Protection_Algorithm*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->IntegrityProtectionAlgo = IntegrityProtectionAlgo;

	return buf;
}

/*  Selected Encryption Algorithm  125 */
u_int8_t *create_IEI_Selected_Encryption_Algorithm(u_int8_t EncryptProtectionAlgo)
{
	struct IEI_Selected_Encryption_Algorithm *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = Selected_Encryption_Algorithm;
	msg = (struct IEI_Selected_Encryption_Algorithm*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->EncryptProtectionAlgo = EncryptProtectionAlgo;

	return buf;
}

/*  CN Domains to Handover  126 */
u_int8_t *create_IEI_CN_Domains_to_Handover(u_int8_t CNDH)
{
	struct IEI_CN_Domains_to_Handover *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = CN_Domains_to_Handover;
	msg = (struct IEI_CN_Domains_to_Handover*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->CNDH = CNDH;

	return buf;
}

/*  SRNS Relocation Info  127 */
u_int8_t *create_IEI_SRNS_Relocation_Info(u_int8_t *UTRANRRCMsg, u_int32_t UTRANRRCMsg_len)
{
	struct IEI_SRNS_Relocation_Info *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 2 + UTRANRRCMsg_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = SRNS_Relocation_Info;
	msg = (struct IEI_SRNS_Relocation_Info*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	memcpy(msg->UTRANRRCMsg, UTRANRRCMsg, UTRANRRCMsg_len);

	return buf;
}

/*  MS Radio Access Capability  128 */
u_int8_t *create_IEI_MS_Radio_Access_Capability(u_int8_t Len, u_int8_t *MSRAC, u_int32_t MSRAC_len)
{
	struct IEI_MS_Radio_Access_Capability *msg;
	u_int8_t *buf;
	u_int32_t len;
	u_int32_t lenc=0;

	len = 3 + MSRAC_len;
	if(len & 0xFF000000) lenc = 4; else if(len & 0xFF0000) lenc = 3; else if(len & 0xFF00) lenc = 2; else if(len & 0x80)lenc = 1;
	buf = (u_int8_t*)malloc(len + lenc);
	memset(buf, 0, len + lenc);

	buf[0] = MS_Radio_Access_Capability;
	msg = (struct IEI_MS_Radio_Access_Capability*)(buf + lenc + 2);
	tlv_write_len(buf + 1, len - 2);
	msg->Len = Len;
	memcpy(msg->MSRAC, MSRAC, MSRAC_len);

	return buf;
}














#if 0

int main()
{

	unsigned char toto[] = "\x00\x2d\x03\x1b\x4b\x11\x00\x7f\x70\xeb\x05\x01\x32\xc2\x25\xf8\x43\x78\xf5\x31\x05\x9c\x16\x4d\x01\x00\x4c\x13\x02\x5e\x66\x51\xfb\x73\xe0\xe5\x71\xce\xf1\x9b\x79\xa8\x48\x83\xf3\x01\x00"; //"\x00\x1b\x01\x70\x1a\x17\x05\x08\x00\x02\xf8\x01\x38\x40\x57\x08\x29\x80\x01\x43\x98\x03\x47\x37\x33\x03\x57\x18\xa0"; 
	struct uma_msg_s *uma_msg;
	int i,j;

	u_int8_t *titi, *tata;
	u_int8_t tem[610];

	uma_msg = uma_create_msg(GA_RC_REGISTER_REQUEST ,0,GA_RC);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Mobile_Identity("\x29\x80\x01\x43\x58\x58\x54\x39",8);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GAN_Release_Indicator(1);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GAN_Classmark(7,1,1,0,0,0);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Radio_Identity(0,"\x00\x1b\x67\x00\x93\x87");
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_MS_Radio_Identity(0,"\x00\x1b\x67\x00\x93\x87");
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GSM_RR_UTRAN_RRC_State(7);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GERAN_UTRAN_coverage_Indicator(2);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Registration_indicators(0);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Location_Area_Identification("\x02\xf8\x11\xff\xfc",5);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GAN_Control_Channel_Description(0,1,0,0,1,1,16,1,1,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_TU3906_Timer(00,0x1e);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_TU3920_Timer(00,0x1e);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_TU4001_Timer(00,0x0f);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_TU4003_Timer(00,0x0f);
	uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Cell_3G_Identity("\x32\x22\x00\x00");
	j = uma_create_buffer(&titi,uma_msg);

	


	for(i = 0; i < uma_msg->ntlv; i++){
		tlv_printf(uma_msg->tlv[i]);
	}
	uma_delete_msg(uma_msg);


	for(i = 0; i < j; i++){
		printf("%02x ",titi[i]);	
	}



}

#endif
