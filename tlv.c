/*
   Copyright (C) 2010 Ramtin Amin <keytwo@gmail.com>
   See COPYING file for license details
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
//#include <sys/types.h>
#include "iei_types.h"
#include "tlv.h"

u_int32_t tlv_get_len(u_int8_t *buf)
{

	u_int32_t len=0;
	u_int8_t i;

	if(!(buf[1] & 0x80))
		return  buf[1] & 0x7f;

	for(i = 0; i < (buf[1] & 0x7f); i++){
		len = (len << 8) + buf[2+i];
	}
	return len;
}

u_int32_t tlv_get_header_len(u_int8_t *buf)
{
	u_int32_t len=0;
	if(buf[1] & 0x80)
		len = 1 +  (buf[1] & 0x7f);
	else
		len = 2;
	return len;
}

void tlv_printf(u_int8_t *buf)
{
	u_int32_t len;
	u_int8_t *pnt;
	void (*fp)(u_int8_t *buffer);
	fp = print_table[buf[0]];
	fp(buf);

}


struct tlv_s *tlv_create(u_int8_t type, u_int8_t *buf, u_int32_t len)
{
	struct tlv_s *tlv;
	tlv = (struct tlv_s*)malloc(sizeof(struct tlv_s));
	tlv->type  = type;
	tlv->len = len;
	tlv->value = (u_int8_t*)malloc(len);
	memcpy(tlv->value,buf,len);
	return tlv;
}

u_int32_t tlv_to_buf(u_int8_t **buf, struct tlv_s *tlv)
{
	u_int8_t len[5];
	u_int32_t lenc=0;

	/* look how many bytes needed to code lenght*/
	if(tlv->len & 0xFF000000)
		lenc = 4;
	else if(tlv->len & 0xFF0000)
		lenc = 3;
	else if(tlv->len & 0xFF00)
		lenc = 2;
	else if(tlv->len & 0x80)
		lenc = 1;

	*buf = (u_int8_t*)malloc(1 + lenc + tlv->len);
	*buf[0] = tlv->type;

	/* if it's not a simple type  code it here*/
	if(lenc > 0){
		len[4] = tlv->len & 0xff;
		len[3] = (tlv->len & 0xff00) >> 8;
		len[2] = (tlv->len & 0xff0000) >> 16;
		len[1] = (tlv->len & 0xff000000) >> 24;
		len[0] = lenc | 0x80;
	} else {
		len[0] = tlv->len;
	}
	/* we put right after the type, the lenght */
	memcpy(*buf+1,len,1+lenc);
	/* and let's write the content after */
	memcpy(*buf + 2 + lenc,tlv->value,tlv->len);

	return tlv->len + 2 + lenc;
}


/* TLV Print function for  Mobile Identity  1 */
void tlv_print_IEI_Mobile_Identity(u_int8_t *buf)
{
  struct IEI_Mobile_Identity *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Mobile_Identity*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Mobile Identity\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GAN Release Indicator  2 */
void tlv_print_IEI_GAN_Release_Indicator(u_int8_t *buf)
{
  struct IEI_GAN_Release_Indicator *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Release_Indicator*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Release Indicator\n");
  printf("------------------------------\n");
  printf("URI = ");
  printf("%02x\n",msg->URI);
  printf("\n\n");
  
}


/* TLV Print function for  Radio Identity  3 */
void tlv_print_IEI_Radio_Identity(u_int8_t *buf)
{
  struct IEI_Radio_Identity *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Radio_Identity*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Radio Identity\n");
  printf("------------------------------\n");
  printf("type = ");
  printf("%02x\n",msg->type);
  printf("value = ");
  pnt = msg->value;
  for(i = 0; i < 6; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GERAN Cell Identity  4 */
void tlv_print_IEI_GERAN_Cell_Identity(u_int8_t *buf)
{
  struct IEI_GERAN_Cell_Identity *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GERAN_Cell_Identity*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GERAN Cell Identity\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Location Area Identification  5 */
void tlv_print_IEI_Location_Area_Identification(u_int8_t *buf)
{
  struct IEI_Location_Area_Identification *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Location_Area_Identification*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Location Area Identification\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GERAN UTRAN coverage Indicator  6 */
void tlv_print_IEI_GERAN_UTRAN_coverage_Indicator(u_int8_t *buf)
{
  struct IEI_GERAN_UTRAN_coverage_Indicator *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GERAN_UTRAN_coverage_Indicator*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GERAN UTRAN coverage Indicator\n");
  printf("------------------------------\n");
  printf("CGI = ");
  printf("%02x\n",msg->CGI);
  printf("\n\n");
  
}


/* TLV Print function for  GAN Classmark  7 */
void tlv_print_IEI_GAN_Classmark(u_int8_t *buf)
{
  struct IEI_GAN_Classmark *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Classmark*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Classmark\n");
  printf("------------------------------\n");
  printf("TGA = ");
  printf("%02x\n",msg->TGA);
  printf("GC = ");
  printf("%02x\n",msg->GC);
  printf("UC = ");
  printf("%02x\n",msg->UC);
  printf("RRS = ");
  printf("%02x\n",msg->RRS);
  printf("PS_HA = ");
  printf("%02x\n",msg->PS_HA);
  printf("GMSI = ");
  printf("%02x\n",msg->GMSI);
  printf("\n\n");
  
}


/* TLV Print function for  Geographical Location  8 */
void tlv_print_IEI_Geographical_Location(u_int8_t *buf)
{
  struct IEI_Geographical_Location *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Geographical_Location*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Geographical Location\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GANC SEGW IP Address  9 */
void tlv_print_IEI_GANC_SEGW_IP_Address(u_int8_t *buf)
{
  struct IEI_GANC_SEGW_IP_Address *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GANC_SEGW_IP_Address*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GANC SEGW IP Address\n");
  printf("------------------------------\n");
  printf("ip_type = ");
  printf("%02x\n",msg->ip_type);
  printf("address = ");
  pnt = msg->address;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GANC SEGW Fully Qualified Domain Host Name  10 */
void tlv_print_IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name(u_int8_t *buf)
{
  struct IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GANC SEGW Fully Qualified Domain Host Name\n");
  printf("------------------------------\n");
  printf("fqdn = ");
  pnt = msg->fqdn;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Redirection Counter  11 */
void tlv_print_IEI_Redirection_Counter(u_int8_t *buf)
{
  struct IEI_Redirection_Counter *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Redirection_Counter*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Redirection Counter\n");
  printf("------------------------------\n");
  printf("redircnt = ");
  printf("%02x\n",msg->redircnt);
  printf("\n\n");
  
}


/* TLV Print function for  Discovery Reject Cause  12 */
void tlv_print_IEI_Discovery_Reject_Cause(u_int8_t *buf)
{
  struct IEI_Discovery_Reject_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Discovery_Reject_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Discovery Reject Cause\n");
  printf("------------------------------\n");
  printf("discrej = ");
  printf("%02x\n",msg->discrej);
  printf("\n\n");
  
}


/* TLV Print function for  GAN Cell Description  13 */
void tlv_print_IEI_GAN_Cell_Description(u_int8_t *buf)
{
  struct IEI_GAN_Cell_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Cell_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Cell Description\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GAN Control Channel Description  14 */
void tlv_print_IEI_GAN_Control_Channel_Description(u_int8_t *buf)
{
  struct IEI_GAN_Control_Channel_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Control_Channel_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Control Channel Description\n");
  printf("------------------------------\n");
  printf("ECMC = ");
  printf("%02x\n",msg->ECMC);
  printf("NMO = ");
  printf("%02x\n",msg->NMO);
  printf("GPRS = ");
  printf("%02x\n",msg->GPRS);
  printf("DTM = ");
  printf("%02x\n",msg->DTM);
  printf("ATT = ");
  printf("%02x\n",msg->ATT);
  printf("MSCR = ");
  printf("%02x\n",msg->MSCR);
  printf("T3212 = ");
  printf("%02x\n",msg->T3212);
  printf("RAC = ");
  printf("%02x\n",msg->RAC);
  printf("SGSNR = ");
  printf("%02x\n",msg->SGSNR);
  printf("ECMP = ");
  printf("%02x\n",msg->ECMP);
  printf("RE = ");
  printf("%02x\n",msg->RE);
  printf("PFCFM = ");
  printf("%02x\n",msg->PFCFM);
  printf("_3GECS = ");
  printf("%02x\n",msg->_3GECS);
  printf("PS_HA = ");
  printf("%02x\n",msg->PS_HA);
  printf("ACC8 = ");
  printf("%02x\n",msg->ACC8);
  printf("ACC9 = ");
  printf("%02x\n",msg->ACC9);
  printf("ACC10 = ");
  printf("%02x\n",msg->ACC10);
  printf("ACC11 = ");
  printf("%02x\n",msg->ACC11);
  printf("ACC12 = ");
  printf("%02x\n",msg->ACC12);
  printf("ACC13 = ");
  printf("%02x\n",msg->ACC13);
  printf("ACC14 = ");
  printf("%02x\n",msg->ACC14);
  printf("ACC15 = ");
  printf("%02x\n",msg->ACC15);
  printf("ACC0 = ");
  printf("%02x\n",msg->ACC0);
  printf("ACC1 = ");
  printf("%02x\n",msg->ACC1);
  printf("ACC2 = ");
  printf("%02x\n",msg->ACC2);
  printf("ACC3 = ");
  printf("%02x\n",msg->ACC3);
  printf("ACC4 = ");
  printf("%02x\n",msg->ACC4);
  printf("ACC5 = ");
  printf("%02x\n",msg->ACC5);
  printf("ACC6 = ");
  printf("%02x\n",msg->ACC6);
  printf("ACC7 = ");
  printf("%02x\n",msg->ACC7);
  printf("\n\n");
  
}


/* TLV Print function for  Cell Identifier List  15 */
void tlv_print_IEI_Cell_Identifier_List(u_int8_t *buf)
{
  struct IEI_Cell_Identifier_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Cell_Identifier_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Cell Identifier List\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  TU3907 Timer  16 */
void tlv_print_IEI_TU3907_Timer(u_int8_t *buf)
{
  struct IEI_TU3907_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU3907_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU3907 Timer\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  GSM RR UTRAN RRC State  17 */
void tlv_print_IEI_GSM_RR_UTRAN_RRC_State(u_int8_t *buf)
{
  struct IEI_GSM_RR_UTRAN_RRC_State *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GSM_RR_UTRAN_RRC_State*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GSM RR UTRAN RRC State\n");
  printf("------------------------------\n");
  printf("GRS = ");
  printf("%02x\n",msg->GRS);
  printf("\n\n");
  
}


/* TLV Print function for  Routing Area Identification  18 */
void tlv_print_IEI_Routing_Area_Identification(u_int8_t *buf)
{
  struct IEI_Routing_Area_Identification *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Routing_Area_Identification*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Routing Area Identification\n");
  printf("------------------------------\n");
  printf("RAI = ");
  pnt = msg->RAI;
  for(i = 0; i < 6; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GAN Band  19 */
void tlv_print_IEI_GAN_Band(u_int8_t *buf)
{
  struct IEI_GAN_Band *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Band*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Band\n");
  printf("------------------------------\n");
  printf("GANBand = ");
  printf("%02x\n",msg->GANBand);
  printf("\n\n");
  
}


/* TLV Print function for  GA RC GA CSR GA PSR State  20 */
void tlv_print_IEI_GA_RC_GA_CSR_GA_PSR_State(u_int8_t *buf)
{
  struct IEI_GA_RC_GA_CSR_GA_PSR_State *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GA_RC_GA_CSR_GA_PSR_State*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GA RC GA CSR GA PSR State\n");
  printf("------------------------------\n");
  printf("URS = ");
  printf("%02x\n",msg->URS);
  printf("UPS = ");
  printf("%02x\n",msg->UPS);
  printf("GA_RRC_CS = ");
  printf("%02x\n",msg->GA_RRC_CS);
  printf("GA_RRC_PS = ");
  printf("%02x\n",msg->GA_RRC_PS);
  printf("\n\n");
  
}


/* TLV Print function for  Register Reject Cause  21 */
void tlv_print_IEI_Register_Reject_Cause(u_int8_t *buf)
{
  struct IEI_Register_Reject_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Register_Reject_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Register Reject Cause\n");
  printf("------------------------------\n");
  printf("RRC = ");
  printf("%02x\n",msg->RRC);
  printf("\n\n");
  
}


/* TLV Print function for  TU3906 Timer  22 */
void tlv_print_IEI_TU3906_Timer(u_int8_t *buf)
{
  struct IEI_TU3906_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU3906_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU3906 Timer\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  TU3910 Timer  23 */
void tlv_print_IEI_TU3910_Timer(u_int8_t *buf)
{
  struct IEI_TU3910_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU3910_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU3910 Timer\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  TU3902 Timer  24 */
void tlv_print_IEI_TU3902_Timer(u_int8_t *buf)
{
  struct IEI_TU3902_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU3902_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU3902 Timer\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  L3 Message  26 */
void tlv_print_IEI_L3_Message(u_int8_t *buf)
{
  struct IEI_L3_Message *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_L3_Message*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("L3 Message\n");
  printf("------------------------------\n");
  printf("l3 = ");
  pnt = msg->l3;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Channel Mode  27 */
void tlv_print_IEI_Channel_Mode(u_int8_t *buf)
{
  struct IEI_Channel_Mode *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Channel_Mode*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Channel Mode\n");
  printf("------------------------------\n");
  printf("chanmode = ");
  pnt = msg->chanmode;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Mobile Station Classmark 2  28 */
void tlv_print_IEI_Mobile_Station_Classmark_2(u_int8_t *buf)
{
  struct IEI_Mobile_Station_Classmark_2 *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Mobile_Station_Classmark_2*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Mobile Station Classmark 2\n");
  printf("------------------------------\n");
  printf("msclass2 = ");
  pnt = msg->msclass2;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  RR Cause  29 */
void tlv_print_IEI_RR_Cause(u_int8_t *buf)
{
  struct IEI_RR_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_RR_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("RR Cause\n");
  printf("------------------------------\n");
  printf("RRCause = ");
  pnt = msg->RRCause;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Cipher Mode Setting  30 */
void tlv_print_IEI_Cipher_Mode_Setting(u_int8_t *buf)
{
  struct IEI_Cipher_Mode_Setting *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Cipher_Mode_Setting*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Cipher Mode Setting\n");
  printf("------------------------------\n");
  printf("SC = ");
  printf("%02x\n",msg->SC);
  printf("algoID = ");
  printf("%02x\n",msg->algoID);
  printf("soare = ");
  printf("%02x\n",msg->soare);
  printf("\n\n");
  
}


/* TLV Print function for  GPRS Resumption  31 */
void tlv_print_IEI_GPRS_Resumption(u_int8_t *buf)
{
  struct IEI_GPRS_Resumption *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GPRS_Resumption*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GPRS Resumption\n");
  printf("------------------------------\n");
  printf("GPRSRes = ");
  pnt = msg->GPRSRes;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Handover From GAN Command  32 */
void tlv_print_IEI_Handover_From_GAN_Command(u_int8_t *buf)
{
  struct IEI_Handover_From_GAN_Command *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Handover_From_GAN_Command*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Handover From GAN Command\n");
  printf("------------------------------\n");
  printf("HoFGComm = ");
  pnt = msg->HoFGComm;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  UL Quality Indication  33 */
void tlv_print_IEI_UL_Quality_Indication(u_int8_t *buf)
{
  struct IEI_UL_Quality_Indication *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_UL_Quality_Indication*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("UL Quality Indication\n");
  printf("------------------------------\n");
  printf("ULQI = ");
  printf("%02x\n",msg->ULQI);
  printf("\n\n");
  
}


/* TLV Print function for  TLLI  34 */
void tlv_print_IEI_TLLI(u_int8_t *buf)
{
  struct IEI_TLLI *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TLLI*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TLLI\n");
  printf("------------------------------\n");
  printf("TLLIm = ");
  pnt = msg->TLLIm;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Packet Flow Identifier  35 */
void tlv_print_IEI_Packet_Flow_Identifier(u_int8_t *buf)
{
  struct IEI_Packet_Flow_Identifier *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Packet_Flow_Identifier*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Packet Flow Identifier\n");
  printf("------------------------------\n");
  printf("PFID = ");
  pnt = msg->PFID;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Suspension Cause  36 */
void tlv_print_IEI_Suspension_Cause(u_int8_t *buf)
{
  struct IEI_Suspension_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Suspension_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Suspension Cause\n");
  printf("------------------------------\n");
  printf("caue = ");
  pnt = msg->caue;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  TU3920 Timer  37 */
void tlv_print_IEI_TU3920_Timer(u_int8_t *buf)
{
  struct IEI_TU3920_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU3920_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU3920 Timer\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  QoS  38 */
void tlv_print_IEI_QoS(u_int8_t *buf)
{
  struct IEI_QoS *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_QoS*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("QoS\n");
  printf("------------------------------\n");
  printf("PEAK_TROUGHPOUT_CLASS = ");
  printf("%02x\n",msg->PEAK_TROUGHPOUT_CLASS);
  printf("RADIO_PRIORITY = ");
  printf("%02x\n",msg->RADIO_PRIORITY);
  printf("RLC_MODE = ");
  printf("%02x\n",msg->RLC_MODE);
  printf("\n\n");
  
}


/* TLV Print function for  GA PSR Cause  39 */
void tlv_print_IEI_GA_PSR_Cause(u_int8_t *buf)
{
  struct IEI_GA_PSR_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GA_PSR_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GA PSR Cause\n");
  printf("------------------------------\n");
  printf("cause = ");
  printf("%02x\n",msg->cause);
  printf("\n\n");
  
}


/* TLV Print function for  User Data Rate  40 */
void tlv_print_IEI_User_Data_Rate(u_int8_t *buf)
{
  struct IEI_User_Data_Rate *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_User_Data_Rate*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("User Data Rate\n");
  printf("------------------------------\n");
  printf("R = ");
  pnt = msg->R;
  for(i = 0; i < 3; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Routing Area Code  41 */
void tlv_print_IEI_Routing_Area_Code(u_int8_t *buf)
{
  struct IEI_Routing_Area_Code *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Routing_Area_Code*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Routing Area Code\n");
  printf("------------------------------\n");
  printf("code = ");
  printf("%02x\n",msg->code);
  printf("\n\n");
  
}


/* TLV Print function for  AP Location  42 */
void tlv_print_IEI_AP_Location(u_int8_t *buf)
{
  struct IEI_AP_Location *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_AP_Location*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("AP Location\n");
  printf("------------------------------\n");
  printf("APLoc = ");
  pnt = msg->APLoc;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  TU4001 Timer  43 */
void tlv_print_IEI_TU4001_Timer(u_int8_t *buf)
{
  struct IEI_TU4001_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU4001_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU4001 Timer\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  Location Status  44 */
void tlv_print_IEI_Location_Status(u_int8_t *buf)
{
  struct IEI_Location_Status *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Location_Status*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Location Status\n");
  printf("------------------------------\n");
  printf("LS = ");
  printf("%02x\n",msg->LS);
  printf("\n\n");
  
}


/* TLV Print function for  Cipher Response  45 */
void tlv_print_IEI_Cipher_Response(u_int8_t *buf)
{
  struct IEI_Cipher_Response *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Cipher_Response*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Cipher Response\n");
  printf("------------------------------\n");
  printf("CR = ");
  printf("%02x\n",msg->CR);
  printf("\n\n");
  
}


/* TLV Print function for  Ciphering Command RAND  46 */
void tlv_print_IEI_Ciphering_Command_RAND(u_int8_t *buf)
{
  struct IEI_Ciphering_Command_RAND *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Ciphering_Command_RAND*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Ciphering Command RAND\n");
  printf("------------------------------\n");
  printf("CipherRand = ");
  pnt = msg->CipherRand;
  for(i = 0; i < 16; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Ciphering Command MAC  47 */
void tlv_print_IEI_Ciphering_Command_MAC(u_int8_t *buf)
{
  struct IEI_Ciphering_Command_MAC *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Ciphering_Command_MAC*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Ciphering Command MAC\n");
  printf("------------------------------\n");
  printf("MAC = ");
  pnt = msg->MAC;
  for(i = 0; i < 12; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Ciphering Key Sequence Number  48 */
void tlv_print_IEI_Ciphering_Key_Sequence_Number(u_int8_t *buf)
{
  struct IEI_Ciphering_Key_Sequence_Number *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Ciphering_Key_Sequence_Number*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Ciphering Key Sequence Number\n");
  printf("------------------------------\n");
  printf("keyseq = ");
  printf("%02x\n",msg->keyseq);
  printf("\n\n");
  
}


/* TLV Print function for  SAPI ID  49 */
void tlv_print_IEI_SAPI_ID(u_int8_t *buf)
{
  struct IEI_SAPI_ID *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_SAPI_ID*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("SAPI ID\n");
  printf("------------------------------\n");
  printf("SapiID = ");
  printf("%02x\n",msg->SapiID);
  printf("\n\n");
  
}


/* TLV Print function for  Establishment Cause  50 */
void tlv_print_IEI_Establishment_Cause(u_int8_t *buf)
{
  struct IEI_Establishment_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Establishment_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Establishment Cause\n");
  printf("------------------------------\n");
  printf("cause = ");
  printf("%02x\n",msg->cause);
  printf("\n\n");
  
}


/* TLV Print function for  Channel Needed  51 */
void tlv_print_IEI_Channel_Needed(u_int8_t *buf)
{
  struct IEI_Channel_Needed *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Channel_Needed*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Channel Needed\n");
  printf("------------------------------\n");
  printf("Chan = ");
  printf("%02x\n",msg->Chan);
  printf("\n\n");
  
}


/* TLV Print function for  PDU in Error  52 */
void tlv_print_IEI_PDU_in_Error(u_int8_t *buf)
{
  struct IEI_PDU_in_Error *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PDU_in_Error*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PDU in Error\n");
  printf("------------------------------\n");
  printf("PDU = ");
  pnt = msg->PDU;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Sample Size  53 */
void tlv_print_IEI_Sample_Size(u_int8_t *buf)
{
  struct IEI_Sample_Size *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Sample_Size*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Sample Size\n");
  printf("------------------------------\n");
  printf("samplesize = ");
  printf("%02x\n",msg->samplesize);
  printf("\n\n");
  
}


/* TLV Print function for  Payload Type  54 */
void tlv_print_IEI_Payload_Type(u_int8_t *buf)
{
  struct IEI_Payload_Type *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Payload_Type*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Payload Type\n");
  printf("------------------------------\n");
  printf("payloadtype = ");
  printf("%02x\n",msg->payloadtype);
  printf("\n\n");
  
}


/* TLV Print function for  Multi rate Configuration  55 */
void tlv_print_IEI_Multi_rate_Configuration(u_int8_t *buf)
{
  struct IEI_Multi_rate_Configuration *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Multi_rate_Configuration*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Multi rate Configuration\n");
  printf("------------------------------\n");
  printf("multiconf = ");
  pnt = msg->multiconf;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Mobile Station Classmar 3  56 */
void tlv_print_IEI_Mobile_Station_Classmar_3(u_int8_t *buf)
{
  struct IEI_Mobile_Station_Classmar_3 *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Mobile_Station_Classmar_3*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Mobile Station Classmar 3\n");
  printf("------------------------------\n");
  printf("ClassMark3 = ");
  printf("%02x\n",msg->ClassMark3);
  printf("\n\n");
  
}


/* TLV Print function for  LLC PDU  57 */
void tlv_print_IEI_LLC_PDU(u_int8_t *buf)
{
  struct IEI_LLC_PDU *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_LLC_PDU*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("LLC PDU\n");
  printf("------------------------------\n");
  printf("llcpdu = ");
  pnt = msg->llcpdu;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Location Black List indicator  58 */
void tlv_print_IEI_Location_Black_List_indicator(u_int8_t *buf)
{
  struct IEI_Location_Black_List_indicator *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Location_Black_List_indicator*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Location Black List indicator\n");
  printf("------------------------------\n");
  printf("LBLI = ");
  printf("%02x\n",msg->LBLI);
  printf("\n\n");
  
}


/* TLV Print function for  Reset Indicator  59 */
void tlv_print_IEI_Reset_Indicator(u_int8_t *buf)
{
  struct IEI_Reset_Indicator *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Reset_Indicator*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Reset Indicator\n");
  printf("------------------------------\n");
  printf("RI = ");
  printf("%02x\n",msg->RI);
  printf("\n\n");
  
}


/* TLV Print function for  TU4003 Timer  60 */
void tlv_print_IEI_TU4003_Timer(u_int8_t *buf)
{
  struct IEI_TU4003_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU4003_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU4003 Timer\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  AP Service Name  61 */
void tlv_print_IEI_AP_Service_Name(u_int8_t *buf)
{
  struct IEI_AP_Service_Name *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_AP_Service_Name*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("AP Service Name\n");
  printf("------------------------------\n");
  printf("AP = ");
  pnt = msg->AP;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GAN Service Zone Information  62 */
void tlv_print_IEI_GAN_Service_Zone_Information(u_int8_t *buf)
{
  struct IEI_GAN_Service_Zone_Information *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Service_Zone_Information*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Service Zone Information\n");
  printf("------------------------------\n");
  printf("GanzoneID = ");
  printf("%02x\n",msg->GanzoneID);
  printf("Len = ");
  printf("%02x\n",msg->Len);
  printf("GANstr = ");
  pnt = msg->GANstr;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  RTP Redundancy Configuration  63 */
void tlv_print_IEI_RTP_Redundancy_Configuration(u_int8_t *buf)
{
  struct IEI_RTP_Redundancy_Configuration *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_RTP_Redundancy_Configuration*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("RTP Redundancy Configuration\n");
  printf("------------------------------\n");
  printf("winsize = ");
  printf("%02x\n",msg->winsize);
  printf("ganlumode = ");
  printf("%02x\n",msg->ganlumode);
  printf("ganmode = ");
  printf("%02x\n",msg->ganmode);
  printf("\n\n");
  
}


/* TLV Print function for  UTRAN Classmark  64 */
void tlv_print_IEI_UTRAN_Classmark(u_int8_t *buf)
{
  struct IEI_UTRAN_Classmark *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_UTRAN_Classmark*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("UTRAN Classmark\n");
  printf("------------------------------\n");
  printf("classmark = ");
  pnt = msg->classmark;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Classmark Enquiry Mask  65 */
void tlv_print_IEI_Classmark_Enquiry_Mask(u_int8_t *buf)
{
  struct IEI_Classmark_Enquiry_Mask *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Classmark_Enquiry_Mask*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Classmark Enquiry Mask\n");
  printf("------------------------------\n");
  printf("mask = ");
  pnt = msg->mask;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  UTRAN Cell Identifier List  66 */
void tlv_print_IEI_UTRAN_Cell_Identifier_List(u_int8_t *buf)
{
  struct IEI_UTRAN_Cell_Identifier_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_UTRAN_Cell_Identifier_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("UTRAN Cell Identifier List\n");
  printf("------------------------------\n");
  printf("celldesc = ");
  printf("%02x\n",msg->celldesc);
  printf("utrancellid = ");
  pnt = msg->utrancellid;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Serving GANC table indicator  67 */
void tlv_print_IEI_Serving_GANC_table_indicator(u_int8_t *buf)
{
  struct IEI_Serving_GANC_table_indicator *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Serving_GANC_table_indicator*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Serving GANC table indicator\n");
  printf("------------------------------\n");
  printf("SUTI = ");
  printf("%02x\n",msg->SUTI);
  printf("\n\n");
  
}


/* TLV Print function for  Registration indicators  68 */
void tlv_print_IEI_Registration_indicators(u_int8_t *buf)
{
  struct IEI_Registration_indicators *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Registration_indicators*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Registration indicators\n");
  printf("------------------------------\n");
  printf("MPS = ");
  printf("%02x\n",msg->MPS);
  printf("\n\n");
  
}


/* TLV Print function for  GAN PLMN List  69 */
void tlv_print_IEI_GAN_PLMN_List(u_int8_t *buf)
{
  struct IEI_GAN_PLMN_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_PLMN_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN PLMN List\n");
  printf("------------------------------\n");
  printf("PLMNnumb = ");
  printf("%02x\n",msg->PLMNnumb);
  printf("PLMN = ");
  pnt = msg->PLMN;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Required GAN Services  71 */
void tlv_print_IEI_Required_GAN_Services(u_int8_t *buf)
{
  struct IEI_Required_GAN_Services *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Required_GAN_Services*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Required GAN Services\n");
  printf("------------------------------\n");
  printf("CBS = ");
  printf("%02x\n",msg->CBS);
  printf("\n\n");
  
}


/* TLV Print function for  Broadcast Container  72 */
void tlv_print_IEI_Broadcast_Container(u_int8_t *buf)
{
  struct IEI_Broadcast_Container *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Broadcast_Container*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Broadcast Container\n");
  printf("------------------------------\n");
  printf("nCBS = ");
  printf("%02x\n",msg->nCBS);
  printf("CBSFrames = ");
  pnt = msg->CBSFrames;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Cell 3G Identity  73 */
void tlv_print_IEI_Cell_3G_Identity(u_int8_t *buf)
{
  struct IEI_Cell_3G_Identity *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Cell_3G_Identity*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Cell 3G Identity\n");
  printf("------------------------------\n");
  printf("CellID = ");
  pnt = msg->CellID;
  for(i = 0; i < 4; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Security Capability 3G  74 */
void tlv_print_IEI_Security_Capability_3G(u_int8_t *buf)
{
  struct IEI_Security_Capability_3G *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Security_Capability_3G*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Security Capability 3G\n");
  printf("------------------------------\n");
  printf("ciph_algo_cap = ");
  printf("%02x\n",msg->ciph_algo_cap);
  printf("ciph_algo_cap2 = ");
  printf("%02x\n",msg->ciph_algo_cap2);
  printf("integ_protec_algo = ");
  printf("%02x\n",msg->integ_protec_algo);
  printf("integ_protec_algo2 = ");
  printf("%02x\n",msg->integ_protec_algo2);
  printf("\n\n");
  
}


/* TLV Print function for  NAS Synchronisation Indicator  75 */
void tlv_print_IEI_NAS_Synchronisation_Indicator(u_int8_t *buf)
{
  struct IEI_NAS_Synchronisation_Indicator *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_NAS_Synchronisation_Indicator*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("NAS Synchronisation Indicator\n");
  printf("------------------------------\n");
  printf("NSI = ");
  printf("%02x\n",msg->NSI);
  printf("\n\n");
  
}


/* TLV Print function for  GANC TEID  76 */
void tlv_print_IEI_GANC_TEID(u_int8_t *buf)
{
  struct IEI_GANC_TEID *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GANC_TEID*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GANC TEID\n");
  printf("------------------------------\n");
  printf("TEID = ");
  pnt = msg->TEID;
  for(i = 0; i < 4; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  MS TEID  77 */
void tlv_print_IEI_MS_TEID(u_int8_t *buf)
{
  struct IEI_MS_TEID *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_MS_TEID*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("MS TEID\n");
  printf("------------------------------\n");
  printf("TEID = ");
  pnt = msg->TEID;
  for(i = 0; i < 4; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  UTRAN RRC Message  78 */
void tlv_print_IEI_UTRAN_RRC_Message(u_int8_t *buf)
{
  struct IEI_UTRAN_RRC_Message *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_UTRAN_RRC_Message*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("UTRAN RRC Message\n");
  printf("------------------------------\n");
  printf("RRCmsg = ");
  pnt = msg->RRCmsg;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GAN Mode Indicator  79 */
void tlv_print_IEI_GAN_Mode_Indicator(u_int8_t *buf)
{
  struct IEI_GAN_Mode_Indicator *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Mode_Indicator*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Mode Indicator\n");
  printf("------------------------------\n");
  printf("GMI = ");
  printf("%02x\n",msg->GMI);
  printf("\n\n");
  
}


/* TLV Print function for  CN Domain Identity  80 */
void tlv_print_IEI_CN_Domain_Identity(u_int8_t *buf)
{
  struct IEI_CN_Domain_Identity *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CN_Domain_Identity*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CN Domain Identity\n");
  printf("------------------------------\n");
  printf("CNDI = ");
  printf("%02x\n",msg->CNDI);
  printf("\n\n");
  
}


/* TLV Print function for  GAN Iu Mode Cell Description  81 */
void tlv_print_IEI_GAN_Iu_Mode_Cell_Description(u_int8_t *buf)
{
  struct IEI_GAN_Iu_Mode_Cell_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GAN_Iu_Mode_Cell_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GAN Iu Mode Cell Description\n");
  printf("------------------------------\n");
  printf("UARFCN = ");
  printf("%02x\n",msg->UARFCN);
  printf("UARFCN2 = ");
  printf("%02x\n",msg->UARFCN2);
  printf("PSC = ");
  printf("%02x\n",msg->PSC);
  printf("PSC2 = ");
  printf("%02x\n",msg->PSC2);
  printf("\n\n");
  
}


/* TLV Print function for  UARFCN 3G  82 */
void tlv_print_IEI_UARFCN_3G(u_int8_t *buf)
{
  struct IEI_UARFCN_3G *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_UARFCN_3G*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("UARFCN 3G\n");
  printf("------------------------------\n");
  printf("UARFCN = ");
  printf("%02x\n",msg->UARFCN);
  printf("UARFCN2 = ");
  printf("%02x\n",msg->UARFCN2);
  printf("\n\n");
  
}


/* TLV Print function for  RAB ID  83 */
void tlv_print_IEI_RAB_ID(u_int8_t *buf)
{
  struct IEI_RAB_ID *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_RAB_ID*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("RAB ID\n");
  printf("------------------------------\n");
  printf("RABID = ");
  printf("%02x\n",msg->RABID);
  printf("\n\n");
  
}


/* TLV Print function for  RAB ID List  84 */
void tlv_print_IEI_RAB_ID_List(u_int8_t *buf)
{
  struct IEI_RAB_ID_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_RAB_ID_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("RAB ID List\n");
  printf("------------------------------\n");
  printf("nRABID = ");
  printf("%02x\n",msg->nRABID);
  printf("RAIDList = ");
  pnt = msg->RAIDList;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GA RRC Establishment Cause  85 */
void tlv_print_IEI_GA_RRC_Establishment_Cause(u_int8_t *buf)
{
  struct IEI_GA_RRC_Establishment_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GA_RRC_Establishment_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GA RRC Establishment Cause\n");
  printf("------------------------------\n");
  printf("cause = ");
  printf("%02x\n",msg->cause);
  printf("\n\n");
  
}


/* TLV Print function for  GA RRC Cause  86 */
void tlv_print_IEI_GA_RRC_Cause(u_int8_t *buf)
{
  struct IEI_GA_RRC_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GA_RRC_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GA RRC Cause\n");
  printf("------------------------------\n");
  printf("cause_MSB = ");
  printf("%02x\n",msg->cause_MSB);
  printf("cause_LSB = ");
  printf("%02x\n",msg->cause_LSB);
  printf("\n\n");
  
}


/* TLV Print function for  GA RRC Paging Cause  87 */
void tlv_print_IEI_GA_RRC_Paging_Cause(u_int8_t *buf)
{
  struct IEI_GA_RRC_Paging_Cause *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GA_RRC_Paging_Cause*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GA RRC Paging Cause\n");
  printf("------------------------------\n");
  printf("pagingcause = ");
  printf("%02x\n",msg->pagingcause);
  printf("\n\n");
  
}


/* TLV Print function for  Intra Domain NAS Node Selector  88 */
void tlv_print_IEI_Intra_Domain_NAS_Node_Selector(u_int8_t *buf)
{
  struct IEI_Intra_Domain_NAS_Node_Selector *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Intra_Domain_NAS_Node_Selector*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Intra Domain NAS Node Selector\n");
  printf("------------------------------\n");
  printf("type = ");
  printf("%02x\n",msg->type);
  printf("routparam = ");
  printf("%02x\n",msg->routparam);
  printf("routparam2 = ");
  printf("%02x\n",msg->routparam2);
  printf("\n\n");
  
}


/* TLV Print function for  CTC Activation List  89 */
void tlv_print_IEI_CTC_Activation_List(u_int8_t *buf)
{
  struct IEI_CTC_Activation_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CTC_Activation_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CTC Activation List\n");
  printf("------------------------------\n");
  printf("nCTC = ");
  printf("%02x\n",msg->nCTC);
  printf("CTCs = ");
  pnt = msg->CTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  CTC Description  90 */
void tlv_print_IEI_CTC_Description(u_int8_t *buf)
{
  struct IEI_CTC_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CTC_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CTC Description\n");
  printf("------------------------------\n");
  printf("RABID = ");
  printf("%02x\n",msg->RABID);
  printf("GARConfig = ");
  printf("%02x\n",msg->GARConfig);
  printf("SampleSize = ");
  printf("%02x\n",msg->SampleSize);
  printf("RTPUDPPort = ");
  printf("%02x\n",msg->RTPUDPPort);
  printf("GanIpAddr = ");
  printf("%02x\n",msg->GanIpAddr);
  printf("PayloadType = ");
  printf("%02x\n",msg->PayloadType);
  printf("MultirateConfig2 = ");
  printf("%02x\n",msg->MultirateConfig2);
  printf("RTPRedundancyConfig = ");
  printf("%02x\n",msg->RTPRedundancyConfig);
  printf("RTCPUDPPort = ");
  printf("%02x\n",msg->RTCPUDPPort);
  printf("NSI = ");
  printf("%02x\n",msg->NSI);
  printf("\n\n");
  
}


/* TLV Print function for  CTC Activation Ack List  91 */
void tlv_print_IEI_CTC_Activation_Ack_List(u_int8_t *buf)
{
  struct IEI_CTC_Activation_Ack_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CTC_Activation_Ack_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CTC Activation Ack List\n");
  printf("------------------------------\n");
  printf("nCTC = ");
  printf("%02x\n",msg->nCTC);
  printf("CTCs = ");
  pnt = msg->CTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  CTC Activation Ack Description  92 */
void tlv_print_IEI_CTC_Activation_Ack_Description(u_int8_t *buf)
{
  struct IEI_CTC_Activation_Ack_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CTC_Activation_Ack_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CTC Activation Ack Description\n");
  printf("------------------------------\n");
  printf("RABID = ");
  printf("%02x\n",msg->RABID);
  printf("GARRCCause = ");
  printf("%02x\n",msg->GARRCCause);
  printf("RTPUDPPort = ");
  printf("%02x\n",msg->RTPUDPPort);
  printf("SampleSize = ");
  printf("%02x\n",msg->SampleSize);
  printf("PAYLoadType = ");
  printf("%02x\n",msg->PAYLoadType);
  printf("RTCPUDPPort = ");
  printf("%02x\n",msg->RTCPUDPPort);
  printf("\n\n");
  
}


/* TLV Print function for  CTC Modification List  93 */
void tlv_print_IEI_CTC_Modification_List(u_int8_t *buf)
{
  struct IEI_CTC_Modification_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CTC_Modification_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CTC Modification List\n");
  printf("------------------------------\n");
  printf("nCTC = ");
  printf("%02x\n",msg->nCTC);
  printf("CTCs = ");
  pnt = msg->CTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  CTC Modification Ack List  94 */
void tlv_print_IEI_CTC_Modification_Ack_List(u_int8_t *buf)
{
  struct IEI_CTC_Modification_Ack_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CTC_Modification_Ack_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CTC Modification Ack List\n");
  printf("------------------------------\n");
  printf("nCTC = ");
  printf("%02x\n",msg->nCTC);
  printf("CTCs = ");
  pnt = msg->CTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  CTC Modification Ack Description  95 */
void tlv_print_IEI_CTC_Modification_Ack_Description(u_int8_t *buf)
{
  struct IEI_CTC_Modification_Ack_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CTC_Modification_Ack_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CTC Modification Ack Description\n");
  printf("------------------------------\n");
  printf("RABID = ");
  printf("%02x\n",msg->RABID);
  printf("GARRCCause = ");
  printf("%02x\n",msg->GARRCCause);
  printf("SampleSize = ");
  printf("%02x\n",msg->SampleSize);
  printf("\n\n");
  
}


/* TLV Print function for  MS Radio Identity  96 */
void tlv_print_IEI_MS_Radio_Identity(u_int8_t *buf)
{
  struct IEI_MS_Radio_Identity *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_MS_Radio_Identity*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("MS Radio Identity\n");
  printf("------------------------------\n");
  printf("type = ");
  printf("%02x\n",msg->type);
  printf("value = ");
  pnt = msg->value;
  for(i = 0; i < 6; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GANC IP Address  97 */
void tlv_print_IEI_GANC_IP_Address(u_int8_t *buf)
{
  struct IEI_GANC_IP_Address *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GANC_IP_Address*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GANC IP Address\n");
  printf("------------------------------\n");
  printf("IPAddr = ");
  pnt = msg->IPAddr;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  GANC Fully Qualified Domain Host Name  98 */
void tlv_print_IEI_GANC_Fully_Qualified_Domain_Host_Name(u_int8_t *buf)
{
  struct IEI_GANC_Fully_Qualified_Domain_Host_Name *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GANC_Fully_Qualified_Domain_Host_Name*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GANC Fully Qualified Domain Host Name\n");
  printf("------------------------------\n");
  printf("fqdn = ");
  pnt = msg->fqdn;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  IP address for GPRS user data transport  99 */
void tlv_print_IEI_IP_address_for_GPRS_user_data_transport(u_int8_t *buf)
{
  struct IEI_IP_address_for_GPRS_user_data_transport *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_IP_address_for_GPRS_user_data_transport*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("IP address for GPRS user data transport\n");
  printf("------------------------------\n");
  printf("IPAddr = ");
  pnt = msg->IPAddr;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  UDP Port for GPRS user data transport  100 */
void tlv_print_IEI_UDP_Port_for_GPRS_user_data_transport(u_int8_t *buf)
{
  struct IEI_UDP_Port_for_GPRS_user_data_transport *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_UDP_Port_for_GPRS_user_data_transport*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("UDP Port for GPRS user data transport\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  GANC TCP port  103 */
void tlv_print_IEI_GANC_TCP_port(u_int8_t *buf)
{
  struct IEI_GANC_TCP_port *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GANC_TCP_port*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GANC TCP port\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  RTP UDP port  104 */
void tlv_print_IEI_RTP_UDP_port(u_int8_t *buf)
{
  struct IEI_RTP_UDP_port *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_RTP_UDP_port*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("RTP UDP port\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  RTCP UDP port  105 */
void tlv_print_IEI_RTCP_UDP_port(u_int8_t *buf)
{
  struct IEI_RTCP_UDP_port *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_RTCP_UDP_port*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("RTCP UDP port\n");
  printf("------------------------------\n");
  printf("MSB = ");
  printf("%02x\n",msg->MSB);
  printf("LSB = ");
  printf("%02x\n",msg->LSB);
  printf("\n\n");
  
}


/* TLV Print function for  GERAN Received Signal Level List  106 */
void tlv_print_IEI_GERAN_Received_Signal_Level_List(u_int8_t *buf)
{
  struct IEI_GERAN_Received_Signal_Level_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_GERAN_Received_Signal_Level_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("GERAN Received Signal Level List\n");
  printf("------------------------------\n");
  printf("RXLEVELs = ");
  pnt = msg->RXLEVELs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  UTRAN Received Signal Level List  107 */
void tlv_print_IEI_UTRAN_Received_Signal_Level_List(u_int8_t *buf)
{
  struct IEI_UTRAN_Received_Signal_Level_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_UTRAN_Received_Signal_Level_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("UTRAN Received Signal Level List\n");
  printf("------------------------------\n");
  printf("RSLL = ");
  pnt = msg->RSLL;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PS Handover to GERAN Command  108 */
void tlv_print_IEI_PS_Handover_to_GERAN_Command(u_int8_t *buf)
{
  struct IEI_PS_Handover_to_GERAN_Command *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PS_Handover_to_GERAN_Command*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PS Handover to GERAN Command\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PS Handover to UTRAN Command  109 */
void tlv_print_IEI_PS_Handover_to_UTRAN_Command(u_int8_t *buf)
{
  struct IEI_PS_Handover_to_UTRAN_Command *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PS_Handover_to_UTRAN_Command*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PS Handover to UTRAN Command\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PS Handover to GERAN PSI  110 */
void tlv_print_IEI_PS_Handover_to_GERAN_PSI(u_int8_t *buf)
{
  struct IEI_PS_Handover_to_GERAN_PSI *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PS_Handover_to_GERAN_PSI*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PS Handover to GERAN PSI\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PS Handover to GERAN SI  111 */
void tlv_print_IEI_PS_Handover_to_GERAN_SI(u_int8_t *buf)
{
  struct IEI_PS_Handover_to_GERAN_SI *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PS_Handover_to_GERAN_SI*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PS Handover to GERAN SI\n");
  printf("------------------------------\n");
  printf("data = ");
  pnt = msg->data;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  TU4004 Timer  112 */
void tlv_print_IEI_TU4004_Timer(u_int8_t *buf)
{
  struct IEI_TU4004_Timer *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_TU4004_Timer*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("TU4004 Timer\n");
  printf("------------------------------\n");
  printf("Tu4004val = ");
  printf("%02x\n",msg->Tu4004val);
  printf("\n\n");
  
}


/* TLV Print function for  PTC Activation List  115 */
void tlv_print_IEI_PTC_Activation_List(u_int8_t *buf)
{
  struct IEI_PTC_Activation_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PTC_Activation_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PTC Activation List\n");
  printf("------------------------------\n");
  printf("nPTCS = ");
  printf("%02x\n",msg->nPTCS);
  printf("PTCs = ");
  pnt = msg->PTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PTC Description  116 */
void tlv_print_IEI_PTC_Description(u_int8_t *buf)
{
  struct IEI_PTC_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PTC_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PTC Description\n");
  printf("------------------------------\n");
  printf("RABID = ");
  printf("%02x\n",msg->RABID);
  printf("RABConf = ");
  printf("%02x\n",msg->RABConf);
  printf("GANCTEID = ");
  printf("%02x\n",msg->GANCTEID);
  printf("MSTEID = ");
  printf("%02x\n",msg->MSTEID);
  printf("GANCUDPPort = ");
  printf("%02x\n",msg->GANCUDPPort);
  printf("GANCIPADDR = ");
  printf("%02x\n",msg->GANCIPADDR);
  printf("\n\n");
  
}


/* TLV Print function for  PTC Activation Ack List  117 */
void tlv_print_IEI_PTC_Activation_Ack_List(u_int8_t *buf)
{
  struct IEI_PTC_Activation_Ack_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PTC_Activation_Ack_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PTC Activation Ack List\n");
  printf("------------------------------\n");
  printf("nPTC = ");
  printf("%02x\n",msg->nPTC);
  printf("PTCs = ");
  pnt = msg->PTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PTC Activation Ack Description  118 */
void tlv_print_IEI_PTC_Activation_Ack_Description(u_int8_t *buf)
{
  struct IEI_PTC_Activation_Ack_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PTC_Activation_Ack_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PTC Activation Ack Description\n");
  printf("------------------------------\n");
  printf("RABID = ");
  printf("%02x\n",msg->RABID);
  printf("GARRCCause = ");
  printf("%02x\n",msg->GARRCCause);
  printf("MSUDPort = ");
  printf("%02x\n",msg->MSUDPort);
  printf("\n\n");
  
}


/* TLV Print function for  PTC Modification List  119 */
void tlv_print_IEI_PTC_Modification_List(u_int8_t *buf)
{
  struct IEI_PTC_Modification_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PTC_Modification_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PTC Modification List\n");
  printf("------------------------------\n");
  printf("nPTC = ");
  printf("%02x\n",msg->nPTC);
  printf("PTCs = ");
  pnt = msg->PTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PTC Modification Ack List  120 */
void tlv_print_IEI_PTC_Modification_Ack_List(u_int8_t *buf)
{
  struct IEI_PTC_Modification_Ack_List *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PTC_Modification_Ack_List*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PTC Modification Ack List\n");
  printf("------------------------------\n");
  printf("nPTC = ");
  printf("%02x\n",msg->nPTC);
  printf("PTCs = ");
  pnt = msg->PTCs;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  PTC Modification Ack Description  121 */
void tlv_print_IEI_PTC_Modification_Ack_Description(u_int8_t *buf)
{
  struct IEI_PTC_Modification_Ack_Description *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_PTC_Modification_Ack_Description*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("PTC Modification Ack Description\n");
  printf("------------------------------\n");
  printf("RABID = ");
  printf("%02x\n",msg->RABID);
  printf("GARRCCause = ");
  printf("%02x\n",msg->GARRCCause);
  printf("RABConfig = ");
  printf("%02x\n",msg->RABConfig);
  printf("GANUDPPort = ");
  printf("%02x\n",msg->GANUDPPort);
  printf("GANCIPAddr = ");
  printf("%02x\n",msg->GANCIPAddr);
  printf("\n\n");
  
}


/* TLV Print function for  RAB Configuration  122 */
void tlv_print_IEI_RAB_Configuration(u_int8_t *buf)
{
  struct IEI_RAB_Configuration *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_RAB_Configuration*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("RAB Configuration\n");
  printf("------------------------------\n");
  printf("TrafficClass = ");
  printf("%02x\n",msg->TrafficClass);
  printf("AI = ");
  printf("%02x\n",msg->AI);
  printf("DO = ");
  printf("%02x\n",msg->DO);
  printf("SSD = ");
  printf("%02x\n",msg->SSD);
  printf("SI = ");
  printf("%02x\n",msg->SI);
  printf("TrafficHandlingPriority = ");
  printf("%02x\n",msg->TrafficHandlingPriority);
  printf("MaxDLBitRate = ");
  pnt = msg->MaxDLBitRate;
  for(i = 0; i < 4; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("MaxUlBitRate = ");
  pnt = msg->MaxUlBitRate;
  for(i = 0; i < 4; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("GuaranteedDlBitRate = ");
  pnt = msg->GuaranteedDlBitRate;
  for(i = 0; i < 4; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("GuaranteedUlBitRate = ");
  pnt = msg->GuaranteedUlBitRate;
  for(i = 0; i < 4; i++)
    printf("%02x ",pnt[i]);
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Multi rate Configuration 2  123 */
void tlv_print_IEI_Multi_rate_Configuration_2(u_int8_t *buf)
{
  struct IEI_Multi_rate_Configuration_2 *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Multi_rate_Configuration_2*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Multi rate Configuration 2\n");
  printf("------------------------------\n");
  printf("MultiRateConf2 = ");
  pnt = msg->MultiRateConf2;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  Selected Integrity Protection Algorithm  124 */
void tlv_print_IEI_Selected_Integrity_Protection_Algorithm(u_int8_t *buf)
{
  struct IEI_Selected_Integrity_Protection_Algorithm *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Selected_Integrity_Protection_Algorithm*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Selected Integrity Protection Algorithm\n");
  printf("------------------------------\n");
  printf("IntegrityProtectionAlgo = ");
  printf("%02x\n",msg->IntegrityProtectionAlgo);
  printf("\n\n");
  
}


/* TLV Print function for  Selected Encryption Algorithm  125 */
void tlv_print_IEI_Selected_Encryption_Algorithm(u_int8_t *buf)
{
  struct IEI_Selected_Encryption_Algorithm *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_Selected_Encryption_Algorithm*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("Selected Encryption Algorithm\n");
  printf("------------------------------\n");
  printf("EncryptProtectionAlgo = ");
  printf("%02x\n",msg->EncryptProtectionAlgo);
  printf("\n\n");
  
}


/* TLV Print function for  CN Domains to Handover  126 */
void tlv_print_IEI_CN_Domains_to_Handover(u_int8_t *buf)
{
  struct IEI_CN_Domains_to_Handover *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_CN_Domains_to_Handover*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("CN Domains to Handover\n");
  printf("------------------------------\n");
  printf("CNDH = ");
  printf("%02x\n",msg->CNDH);
  printf("\n\n");
  
}


/* TLV Print function for  SRNS Relocation Info  127 */
void tlv_print_IEI_SRNS_Relocation_Info(u_int8_t *buf)
{
  struct IEI_SRNS_Relocation_Info *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_SRNS_Relocation_Info*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("SRNS Relocation Info\n");
  printf("------------------------------\n");
  printf("UTRANRRCMsg = ");
  pnt = msg->UTRANRRCMsg;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


/* TLV Print function for  MS Radio Access Capability  128 */
void tlv_print_IEI_MS_Radio_Access_Capability(u_int8_t *buf)
{
  struct IEI_MS_Radio_Access_Capability *msg;
  u_int8_t  len;
  u_int32_t i;
  u_int8_t *pnt;

  msg = (struct IEI_MS_Radio_Access_Capability*)(buf + tlv_get_header_len(buf));
  len = tlv_get_len(buf);

  printf("------------------------------\n");
  printf("MS Radio Access Capability\n");
  printf("------------------------------\n");
  printf("Len = ");
  printf("%02x\n",msg->Len);
  printf("MSRAC = ");
  pnt = msg->MSRAC;
  while(pnt != (u_int8_t*)(msg + len)){
    printf("%02x ",*pnt++);
  }
  printf("\n");
  printf("\n\n");
  
}


