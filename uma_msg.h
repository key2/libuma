/*
   Copyright (C) 2009 Ramtin Amin <keytwo@gmail.com>
   See COPYING file for license details
*/

#ifndef __UMA_MSG_H_
#define __UMA_MSG_H_
#include <sys/types.h>
#define MAX_NTLV 99

struct uma_msg_s {
  u_int16_t len;
  u_int8_t skip;
  u_int8_t pd;
  u_int8_t msgtype;
  u_int8_t *tlv[MAX_NTLV];
  u_int16_t ntlv;
};


struct uma_msg_s *uma_create_msg(u_int8_t type, u_int8_t skip, u_int8_t pd);
struct uma_msg_s *uma_parse_msg(u_int8_t *buf, u_int32_t len);


u_int8_t *create_IEI_Mobile_Identity(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_GAN_Release_Indicator(u_int8_t URI);
u_int8_t *create_IEI_Radio_Identity(u_int8_t type, u_int8_t *value);
u_int8_t *create_IEI_GERAN_Cell_Identity(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_Location_Area_Identification(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_GERAN_UTRAN_coverage_Indicator(u_int8_t CGI);
u_int8_t *create_IEI_GAN_Classmark(u_int8_t TGA, u_int8_t GC, u_int8_t UC, u_int8_t RRS, u_int8_t PS_HA, u_int8_t GMSI);
u_int8_t *create_IEI_Geographical_Location(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_GANC_SEGW_IP_Address(u_int8_t ip_type, u_int8_t *address, u_int32_t address_len);
u_int8_t *create_IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name(u_int8_t *fqdn, u_int32_t fqdn_len);
u_int8_t *create_IEI_Redirection_Counter(u_int8_t redircnt);
u_int8_t *create_IEI_Discovery_Reject_Cause(u_int8_t discrej);
u_int8_t *create_IEI_GAN_Cell_Description(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_GAN_Control_Channel_Description(u_int8_t ECMC, u_int8_t NMO, u_int8_t GPRS, u_int8_t DTM, u_int8_t ATT, u_int8_t MSCR, u_int8_t T3212, u_int8_t RAC, u_int8_t SGSNR, u_int8_t ECMP, u_int8_t RE, u_int8_t PFCFM, u_int8_t _3GECS, u_int8_t PS_HA, u_int8_t ACC8, u_int8_t ACC9, u_int8_t ACC10, u_int8_t ACC11, u_int8_t ACC12, u_int8_t ACC13, u_int8_t ACC14, u_int8_t ACC15, u_int8_t ACC0, u_int8_t ACC1, u_int8_t ACC2, u_int8_t ACC3, u_int8_t ACC4, u_int8_t ACC5, u_int8_t ACC6, u_int8_t ACC7);
u_int8_t *create_IEI_Cell_Identifier_List(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_TU3907_Timer(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_GSM_RR_UTRAN_RRC_State(u_int8_t GRS);
u_int8_t *create_IEI_Routing_Area_Identification(u_int8_t *RAI);
u_int8_t *create_IEI_GAN_Band(u_int8_t GANBand);
u_int8_t *create_IEI_GA_RC_GA_CSR_GA_PSR_State(u_int8_t URS, u_int8_t UPS, u_int8_t GA_RRC_CS, u_int8_t GA_RRC_PS);
u_int8_t *create_IEI_Register_Reject_Cause(u_int8_t RRC);
u_int8_t *create_IEI_TU3906_Timer(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_TU3910_Timer(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_TU3902_Timer(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_L3_Message(u_int8_t *l3, u_int32_t l3_len);
u_int8_t *create_IEI_Channel_Mode(u_int8_t *chanmode, u_int32_t chanmode_len);
u_int8_t *create_IEI_Mobile_Station_Classmark_2(u_int8_t *msclass2, u_int32_t msclass2_len);
u_int8_t *create_IEI_RR_Cause(u_int8_t *RRCause, u_int32_t RRCause_len);
u_int8_t *create_IEI_Cipher_Mode_Setting(u_int8_t SC, u_int8_t algoID, u_int8_t soare);
u_int8_t *create_IEI_GPRS_Resumption(u_int8_t *GPRSRes, u_int32_t GPRSRes_len);
u_int8_t *create_IEI_Handover_From_GAN_Command(u_int8_t *HoFGComm, u_int32_t HoFGComm_len);
u_int8_t *create_IEI_UL_Quality_Indication(u_int8_t ULQI);
u_int8_t *create_IEI_TLLI(u_int8_t *TLLIm, u_int32_t TLLIm_len);
u_int8_t *create_IEI_Packet_Flow_Identifier(u_int8_t *PFID, u_int32_t PFID_len);
u_int8_t *create_IEI_Suspension_Cause(u_int8_t *caue, u_int32_t caue_len);
u_int8_t *create_IEI_TU3920_Timer(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_QoS(u_int8_t PEAK_TROUGHPOUT_CLASS, u_int8_t RADIO_PRIORITY, u_int8_t RLC_MODE);
u_int8_t *create_IEI_GA_PSR_Cause(u_int8_t cause);
u_int8_t *create_IEI_User_Data_Rate(u_int8_t *R);
u_int8_t *create_IEI_Routing_Area_Code(u_int8_t code);
u_int8_t *create_IEI_AP_Location(u_int8_t *APLoc, u_int32_t APLoc_len);
u_int8_t *create_IEI_TU4001_Timer(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_Location_Status(u_int8_t LS);
u_int8_t *create_IEI_Cipher_Response(u_int8_t CR);
u_int8_t *create_IEI_Ciphering_Command_RAND(u_int8_t *CipherRand);
u_int8_t *create_IEI_Ciphering_Command_MAC(u_int8_t *MAC);
u_int8_t *create_IEI_Ciphering_Key_Sequence_Number(u_int8_t keyseq);
u_int8_t *create_IEI_SAPI_ID(u_int8_t SapiID);
u_int8_t *create_IEI_Establishment_Cause(u_int8_t cause);
u_int8_t *create_IEI_Channel_Needed(u_int8_t Chan);
u_int8_t *create_IEI_PDU_in_Error(u_int8_t *PDU, u_int32_t PDU_len);
u_int8_t *create_IEI_Sample_Size(u_int8_t samplesize);
u_int8_t *create_IEI_Payload_Type(u_int8_t payloadtype);
u_int8_t *create_IEI_Multi_rate_Configuration(u_int8_t *multiconf, u_int32_t multiconf_len);
u_int8_t *create_IEI_Mobile_Station_Classmar_3(u_int8_t ClassMark3);
u_int8_t *create_IEI_LLC_PDU(u_int8_t *llcpdu, u_int32_t llcpdu_len);
u_int8_t *create_IEI_Location_Black_List_indicator(u_int8_t LBLI);
u_int8_t *create_IEI_Reset_Indicator(u_int8_t RI);
u_int8_t *create_IEI_TU4003_Timer(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_AP_Service_Name(u_int8_t *AP, u_int32_t AP_len);
u_int8_t *create_IEI_GAN_Service_Zone_Information(u_int8_t GanzoneID, u_int8_t Len, u_int8_t *GANstr, u_int32_t GANstr_len);
u_int8_t *create_IEI_RTP_Redundancy_Configuration(u_int8_t winsize, u_int8_t ganlumode, u_int8_t ganmode);
u_int8_t *create_IEI_UTRAN_Classmark(u_int8_t *classmark, u_int32_t classmark_len);
u_int8_t *create_IEI_Classmark_Enquiry_Mask(u_int8_t *mask, u_int32_t mask_len);
u_int8_t *create_IEI_UTRAN_Cell_Identifier_List(u_int8_t celldesc, u_int8_t *utrancellid, u_int32_t utrancellid_len);
u_int8_t *create_IEI_Serving_GANC_table_indicator(u_int8_t SUTI);
u_int8_t *create_IEI_Registration_indicators(u_int8_t MPS);
u_int8_t *create_IEI_GAN_PLMN_List(u_int8_t PLMNnumb, u_int8_t *PLMN, u_int32_t PLMN_len);
u_int8_t *create_IEI_Required_GAN_Services(u_int8_t CBS);
u_int8_t *create_IEI_Broadcast_Container(u_int8_t nCBS, u_int8_t *CBSFrames, u_int32_t CBSFrames_len);
u_int8_t *create_IEI_Cell_3G_Identity(u_int8_t *CellID);
u_int8_t *create_IEI_Security_Capability_3G(u_int8_t ciph_algo_cap, u_int8_t ciph_algo_cap2, u_int8_t integ_protec_algo, u_int8_t integ_protec_algo2);
u_int8_t *create_IEI_NAS_Synchronisation_Indicator(u_int8_t NSI);
u_int8_t *create_IEI_GANC_TEID(u_int8_t *TEID);
u_int8_t *create_IEI_MS_TEID(u_int8_t *TEID);
u_int8_t *create_IEI_UTRAN_RRC_Message(u_int8_t *RRCmsg, u_int32_t RRCmsg_len);
u_int8_t *create_IEI_GAN_Mode_Indicator(u_int8_t GMI);
u_int8_t *create_IEI_CN_Domain_Identity(u_int8_t CNDI);
u_int8_t *create_IEI_GAN_Iu_Mode_Cell_Description(u_int8_t UARFCN, u_int8_t UARFCN2, u_int8_t PSC, u_int8_t PSC2);
u_int8_t *create_IEI_UARFCN_3G(u_int8_t UARFCN, u_int8_t UARFCN2);
u_int8_t *create_IEI_RAB_ID(u_int8_t RABID);
u_int8_t *create_IEI_RAB_ID_List(u_int8_t nRABID, u_int8_t *RAIDList, u_int32_t RAIDList_len);
u_int8_t *create_IEI_GA_RRC_Establishment_Cause(u_int8_t cause);
u_int8_t *create_IEI_GA_RRC_Cause(u_int8_t cause_MSB, u_int8_t cause_LSB);
u_int8_t *create_IEI_GA_RRC_Paging_Cause(u_int8_t pagingcause);
u_int8_t *create_IEI_Intra_Domain_NAS_Node_Selector(u_int8_t type, u_int8_t routparam, u_int8_t routparam2);
u_int8_t *create_IEI_CTC_Activation_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len);
u_int8_t *create_IEI_CTC_Description(u_int8_t RABID, u_int8_t GARConfig, u_int8_t SampleSize, u_int8_t RTPUDPPort, u_int8_t GanIpAddr, u_int8_t PayloadType, u_int8_t MultirateConfig2, u_int8_t RTPRedundancyConfig, u_int8_t RTCPUDPPort, u_int8_t NSI);
u_int8_t *create_IEI_CTC_Activation_Ack_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len);
u_int8_t *create_IEI_CTC_Activation_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t RTPUDPPort, u_int8_t SampleSize, u_int8_t PAYLoadType, u_int8_t RTCPUDPPort);
u_int8_t *create_IEI_CTC_Modification_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len);
u_int8_t *create_IEI_CTC_Modification_Ack_List(u_int8_t nCTC, u_int8_t *CTCs, u_int32_t CTCs_len);
u_int8_t *create_IEI_CTC_Modification_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t SampleSize);
u_int8_t *create_IEI_MS_Radio_Identity(u_int8_t type, u_int8_t *value);
u_int8_t *create_IEI_GANC_IP_Address(u_int8_t *IPAddr, u_int32_t IPAddr_len);
u_int8_t *create_IEI_GANC_Fully_Qualified_Domain_Host_Name(u_int8_t *fqdn, u_int32_t fqdn_len);
u_int8_t *create_IEI_IP_address_for_GPRS_user_data_transport(u_int8_t *IPAddr, u_int32_t IPAddr_len);
u_int8_t *create_IEI_UDP_Port_for_GPRS_user_data_transport(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_GANC_TCP_port(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_RTP_UDP_port(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_RTCP_UDP_port(u_int8_t MSB, u_int8_t LSB);
u_int8_t *create_IEI_GERAN_Received_Signal_Level_List(u_int8_t *RXLEVELs, u_int32_t RXLEVELs_len);
u_int8_t *create_IEI_UTRAN_Received_Signal_Level_List(u_int8_t *RSLL, u_int32_t RSLL_len);
u_int8_t *create_IEI_PS_Handover_to_GERAN_Command(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_PS_Handover_to_UTRAN_Command(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_PS_Handover_to_GERAN_PSI(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_PS_Handover_to_GERAN_SI(u_int8_t *data, u_int32_t data_len);
u_int8_t *create_IEI_TU4004_Timer(u_int8_t Tu4004val);
u_int8_t *create_IEI_PTC_Activation_List(u_int8_t nPTCS, u_int8_t *PTCs, u_int32_t PTCs_len);
u_int8_t *create_IEI_PTC_Description(u_int8_t RABID, u_int8_t RABConf, u_int8_t GANCTEID, u_int8_t MSTEID, u_int8_t GANCUDPPort, u_int8_t GANCIPADDR);
u_int8_t *create_IEI_PTC_Activation_Ack_List(u_int8_t nPTC, u_int8_t *PTCs, u_int32_t PTCs_len);
u_int8_t *create_IEI_PTC_Activation_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t MSUDPort);
u_int8_t *create_IEI_PTC_Modification_List(u_int8_t nPTC, u_int8_t *PTCs, u_int32_t PTCs_len);
u_int8_t *create_IEI_PTC_Modification_Ack_List(u_int8_t nPTC, u_int8_t *PTCs, u_int32_t PTCs_len);
u_int8_t *create_IEI_PTC_Modification_Ack_Description(u_int8_t RABID, u_int8_t GARRCCause, u_int8_t RABConfig, u_int8_t GANUDPPort, u_int8_t GANCIPAddr);
u_int8_t *create_IEI_RAB_Configuration(u_int8_t TrafficClass, u_int8_t AI, u_int8_t DO, u_int8_t SSD, u_int8_t SI, u_int8_t TrafficHandlingPriority, u_int8_t *MaxDLBitRate, u_int8_t *MaxUlBitRate, u_int8_t *GuaranteedDlBitRate, u_int8_t *GuaranteedUlBitRate);
u_int8_t *create_IEI_Multi_rate_Configuration_2(u_int8_t *MultiRateConf2, u_int32_t MultiRateConf2_len);
u_int8_t *create_IEI_Selected_Integrity_Protection_Algorithm(u_int8_t IntegrityProtectionAlgo);
u_int8_t *create_IEI_Selected_Encryption_Algorithm(u_int8_t EncryptProtectionAlgo);
u_int8_t *create_IEI_CN_Domains_to_Handover(u_int8_t CNDH);
u_int8_t *create_IEI_SRNS_Relocation_Info(u_int8_t *UTRANRRCMsg, u_int32_t UTRANRRCMsg_len);
u_int8_t *create_IEI_MS_Radio_Access_Capability(u_int8_t Len, u_int8_t *MSRAC, u_int32_t MSRAC_len);
#endif //__UMA_MSG_H_

