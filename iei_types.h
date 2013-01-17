/*
  Copyright (C) 2010 Ramtin Amin <keytwo@gmail.com>
  See COPYING file for license details
*/

#ifndef __IEI_H_
#define __IEI_H_

#ifdef _MSC_VER
# pragma pack( push, packing )
# pragma pack( 1 )
# define PACK_STRUCT
#endif
#if defined( __GNUC__ )
# define PACK_STRUCT __attribute__((packed))
#endif


enum iei_type_t {
  Mobile_Identity=1,
  GAN_Release_Indicator=2,
  Radio_Identity=3,
  GERAN_Cell_Identity=4,
  Location_Area_Identification=5,
  GERAN_UTRAN_coverage_Indicator=6,
  GAN_Classmark=7,
  Geographical_Location=8,
  GANC_SEGW_IP_Address=9,
  GANC_SEGW_Fully_Qualified_Domain_Host_Name=10,
  Redirection_Counter=11,
  Discovery_Reject_Cause=12,
  GAN_Cell_Description=13,
  GAN_Control_Channel_Description=14,
  Cell_Identifier_List=15,
  TU3907_Timer=16,
  GSM_RR_UTRAN_RRC_State=17,
  Routing_Area_Identification=18,
  GAN_Band=19,
  GA_RC_GA_CSR_GA_PSR_State=20,
  Register_Reject_Cause=21,
  TU3906_Timer=22,
  TU3910_Timer=23,
  TU3902_Timer=24,
  L3_Message=26,
  Channel_Mode=27,
  Mobile_Station_Classmark_2=28,
  RR_Cause=29,
  Cipher_Mode_Setting=30,
  GPRS_Resumption=31,
  Handover_From_GAN_Command=32,
  UL_Quality_Indication=33,
  TLLI=34,
  Packet_Flow_Identifier=35,
  Suspension_Cause=36,
  TU3920_Timer=37,
  QoS=38,
  GA_PSR_Cause=39,
  User_Data_Rate=40,
  Routing_Area_Code=41,
  AP_Location=42,
  TU4001_Timer=43,
  Location_Status=44,
  Cipher_Response=45,
  Ciphering_Command_RAND=46,
  Ciphering_Command_MAC=47,
  Ciphering_Key_Sequence_Number=48,
  SAPI_ID=49,
  Establishment_Cause=50,
  Channel_Needed=51,
  PDU_in_Error=52,
  Sample_Size=53,
  Payload_Type=54,
  Multi_rate_Configuration=55,
  Mobile_Station_Classmar_3=56,
  LLC_PDU=57,
  Location_Black_List_indicator=58,
  Reset_Indicator=59,
  TU4003_Timer=60,
  AP_Service_Name=61,
  GAN_Service_Zone_Information=62,
  RTP_Redundancy_Configuration=63,
  UTRAN_Classmark=64,
  Classmark_Enquiry_Mask=65,
  UTRAN_Cell_Identifier_List=66,
  Serving_GANC_table_indicator=67,
  Registration_indicators=68,
  GAN_PLMN_List=69,
  Required_GAN_Services=71,
  Broadcast_Container=72,
  Cell_3G_Identity=73,
  MS_Radio_Identity=96,
  GANC_IP_Address=97,
  GANC_Fully_Qualified_Domain_Host_Name=98,
  IP_address_for_GPRS_user_data_transport=99,
  UDP_Port_for_GPRS_user_data_transport=100,
  GANC_TCP_port=103,
  RTP_UDP_port=104,
  RTCP_UDP_port=105,
  GERAN_Received_Signal_Level_List=106,
  UTRAN_Received_Signal_Level_List=107,
  PS_Handover_to_GERAN_Command=108,
  PS_Handover_to_UTRAN_Command=109,
  PS_Handover_to_GERAN_PSI=110,
  PS_Handover_to_GERAN_SI=111,
  TU4004_Timer=112,
  GAN_Mode_Indicator=79,
  CN_Domain_Identity=80,
  GAN_Iu_Mode_Cell_Description=81,
  UARFCN_3G=82,
  RAB_ID=83,
  RAB_ID_List=84,
  GA_RRC_Establishment_Cause=85,
  GA_RRC_Cause=86,
  GA_RRC_Paging_Cause=87,
  Intra_Domain_NAS_Node_Selector=88,
  CTC_Activation_List=89,
  CTC_Description=90,
  CTC_Activation_Ack_List=91,
  CTC_Activation_Ack_Description=92,
  CTC_Modification_List=93,
  CTC_Modification_Ack_List=94,
  CTC_Modification_Ack_Description=95,
  PTC_Activation_List=115,
  PTC_Description=116,
  PTC_Activation_Ack_List=117,
  PTC_Activation_Ack_Description=118,
  PTC_Modification_List=119,
  PTC_Modification_Ack_List=120,
  PTC_Modification_Ack_Description=121,
  RAB_Configuration=122,
  Multi_rate_Configuration_2=123,
  Selected_Integrity_Protection_Algorithm=124,
  Selected_Encryption_Algorithm=125,
  CN_Domains_to_Handover=126,
  Security_Capability_3G=74,
  NAS_Synchronisation_Indicator=75,
  GANC_TEID=76,
  MS_TEID=77,
  UTRAN_RRC_Message=78,
  SRNS_Relocation_Info=127,
  MS_Radio_Access_Capability=128,
};







static unsigned char iei_names[130][50] = {
  "",
  "Mobile Identity",  //1,
  "GAN Release Indicator",  //2,
  "Radio Identity",  //3,
  "GERAN Cell Identity",  //4,
  "Location Area Identification",  //5,
  "GERAN UTRAN coverage Indicator",  //6,
  "GAN Classmark",  //7,
  "Geographical Location",  //8,
  "GANC SEGW IP Address",  //9,
  "GANC SEGW Fully Qualified Domain Host Name",  //10,
  "Redirection Counter",  //11,
  "Discovery Reject Cause",  //12,
  "GAN Cell Description",  //13,
  "GAN Control Channel Description",  //14,
  "Cell Identifier List",  //15,
  "TU3907 Timer",  //16,
  "GSM RR UTRAN RRC State",  //17,
  "Routing Area Identification",  //18,
  "GAN Band",  //19,
  "GA RC GA CSR GA PSR State",  //20,
  "Register Reject Cause",  //21,
  "TU3906 Timer",  //22,
  "TU3910 Timer",  //23,
  "TU3902 Timer",  //24,
  "",
  "L3 Message",  //26,
  "Channel Mode",  //27,
  "Mobile Station Classmark 2",  //28,
  "RR Cause",  //29,
  "Cipher Mode Setting",  //30,
  "GPRS Resumption",  //31,
  "Handover From GAN Command",  //32,
  "UL Quality Indication",  //33,
  "TLLI",  //34,
  "Packet Flow Identifier",  //35,
  "Suspension Cause",  //36,
  "TU3920 Timer",  //37,
  "QoS",  //38,
  "GA PSR Cause",  //39,
  "User Data Rate",  //40,
  "Routing Area Code",  //41,
  "AP Location",  //42,
  "TU4001 Timer",  //43,
  "Location Status",  //44,
  "Cipher Response",  //45,
  "Ciphering Command RAND",  //46,
  "Ciphering Command MAC",  //47,
  "Ciphering Key Sequence Number",  //48,
  "SAPI ID",  //49,
  "Establishment Cause",  //50,
  "Channel Needed",  //51,
  "PDU in Error",  //52,
  "Sample Size",  //53,
  "Payload Type",  //54,
  "Multi rate Configuration",  //55,
  "Mobile Station Classmar 3",  //56,
  "LLC PDU",  //57,
  "Location Black List indicator",  //58,
  "Reset Indicator",  //59,
  "TU4003 Timer",  //60,
  "AP Service Name",  //61,
  "GAN Service Zone Information",  //62,
  "RTP Redundancy Configuration",  //63,
  "UTRAN Classmark",  //64,
  "Classmark Enquiry Mask",  //65,
  "UTRAN Cell Identifier List",  //66,
  "Serving GANC table indicator",  //67,
  "Registration indicators",  //68,
  "GAN PLMN List",  //69,
  "",
  "Required GAN Services",  //71,
  "Broadcast Container",  //72,
  "Cell 3G Identity",  //73,
  "Security Capability 3G",  //74,
  "NAS Synchronisation Indicator",  //75,
  "GANC TEID",  //76,
  "MS TEID",  //77,
  "UTRAN RRC Message",  //78,
  "GAN Mode Indicator",  //79,
  "CN Domain Identity",  //80,
  "GAN Iu Mode Cell Description",  //81,
  "UARFCN 3G",  //82,
  "RAB ID",  //83,
  "RAB ID List",  //84,
  "GA RRC Establishment Cause",  //85,
  "GA RRC Cause",  //86,
  "GA RRC Paging Cause",  //87,
  "Intra Domain NAS Node Selector",  //88,
  "CTC Activation List",  //89,
  "CTC Description",  //90,
  "CTC Activation Ack List",  //91,
  "CTC Activation Ack Description",  //92,
  "CTC Modification List",  //93,
  "CTC Modification Ack List",  //94,
  "CTC Modification Ack Description",  //95,
  "MS Radio Identity",  //96,
  "GANC IP Address",  //97,
  "GANC Fully Qualified Domain Host Name",  //98,
  "IP address for GPRS user data transport",  //99,
  "UDP Port for GPRS user data transport",  //100,
  "","",
  "GANC TCP port",  //103,
  "RTP UDP port",  //104,
  "RTCP UDP port",  //105,
  "GERAN Received Signal Level List",  //106,
  "UTRAN Received Signal Level List",  //107,
  "PS Handover to GERAN Command",  //108,
  "PS Handover to UTRAN Command",  //109,
  "PS Handover to GERAN PSI",  //110,
  "PS Handover to GERAN SI",  //111,
  "TU4004 Timer",  //112,
  "","",
  "PTC Activation List",  //115,
  "PTC Description",  //116,
  "PTC Activation Ack List",  //117,
  "PTC Activation Ack Description",  //118,
  "PTC Modification List",  //119,
  "PTC Modification Ack List",  //120,
  "PTC Modification Ack Description",  //121,
  "RAB Configuration",  //122,
  "Multi rate Configuration 2",  //123,
  "Selected Integrity Protection Algorithm",  //124,
  "Selected Encryption Algorithm",  //125,
  "CN Domains to Handover",  //126,
  "SRNS Relocation Info",  //127,
  "MS Radio Access Capability",  //128,
};







/*  Mobile Identity  1 */
struct IEI_Mobile_Identity {
   u_int8_t data[1];
} PACK_STRUCT;

/*  GAN Release Indicator  2 */
struct IEI_GAN_Release_Indicator {
   u_int8_t URI:3;
   u_int8_t spare:5;
} PACK_STRUCT;

/*  Radio Identity  3 */
struct IEI_Radio_Identity {
   u_int8_t type:4;
   u_int8_t spare:4;
   u_int8_t value[6];
} PACK_STRUCT;

/*  GERAN Cell Identity  4 */
struct IEI_GERAN_Cell_Identity {
   u_int8_t data[1];
} PACK_STRUCT;

/*  Location Area Identification  5 */
struct IEI_Location_Area_Identification {
   u_int8_t data[1];
} PACK_STRUCT;

/*  GERAN UTRAN coverage Indicator  6 */
struct IEI_GERAN_UTRAN_coverage_Indicator {
   u_int8_t CGI;
} PACK_STRUCT;

/*  GAN Classmark  7 */
struct IEI_GAN_Classmark {
   u_int8_t TGA:4;
   u_int8_t GC:1;
   u_int8_t UC:1;
   u_int8_t spare:2;
   u_int8_t RRS:1;
   u_int8_t PS_HA:1;
   u_int8_t GMSI:2;
   u_int8_t spare2:4;
} PACK_STRUCT;

/*  Geographical Location  8 */
struct IEI_Geographical_Location {
   u_int8_t data[1];
} PACK_STRUCT;

/*  GANC SEGW IP Address  9 */
struct IEI_GANC_SEGW_IP_Address {
   u_int8_t ip_type;
   u_int8_t address[1];
} PACK_STRUCT;

/*  GANC SEGW Fully Qualified Domain Host Name  10 */
struct IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name {
   u_int8_t fqdn[1];
} PACK_STRUCT;

/*  Redirection Counter  11 */
struct IEI_Redirection_Counter {
   u_int8_t redircnt;
} PACK_STRUCT;

/*  Discovery Reject Cause  12 */
struct IEI_Discovery_Reject_Cause {
   u_int8_t discrej;
} PACK_STRUCT;

/*  GAN Cell Description  13 */
struct IEI_GAN_Cell_Description {
   u_int8_t data[1];
} PACK_STRUCT;

/*  GAN Control Channel Description  14 */
struct IEI_GAN_Control_Channel_Description {
   u_int8_t spare:1;
   u_int8_t ECMC:1;
   u_int8_t NMO:2;
   u_int8_t GPRS:1;
   u_int8_t DTM:1;
   u_int8_t ATT:1;
   u_int8_t MSCR:1;
   u_int8_t T3212;
   u_int8_t RAC;
   u_int8_t SGSNR:1;
   u_int8_t ECMP:1;
   u_int8_t RE:1;
   u_int8_t PFCFM:1;
   u_int8_t _3GECS:1;
   u_int8_t PS_HA:1;
   u_int8_t spare2:2;
   u_int8_t ACC8:1;
   u_int8_t ACC9:1;
   u_int8_t ACC10:1;
   u_int8_t ACC11:1;
   u_int8_t ACC12:1;
   u_int8_t ACC13:1;
   u_int8_t ACC14:1;
   u_int8_t ACC15:1;
   u_int8_t ACC0:1;
   u_int8_t ACC1:1;
   u_int8_t ACC2:1;
   u_int8_t ACC3:1;
   u_int8_t ACC4:1;
   u_int8_t ACC5:1;
   u_int8_t ACC6:1;
   u_int8_t ACC7:1;
} PACK_STRUCT;

/*  Cell Identifier List  15 */
struct IEI_Cell_Identifier_List {
   u_int8_t data[1];
} PACK_STRUCT;

/*  TU3907 Timer  16 */
struct IEI_TU3907_Timer {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  GSM RR UTRAN RRC State  17 */
struct IEI_GSM_RR_UTRAN_RRC_State {
   u_int8_t GRS:3;
   u_int8_t spare:5;
} PACK_STRUCT;

/*  Routing Area Identification  18 */
struct IEI_Routing_Area_Identification {
   u_int8_t RAI[6];
} PACK_STRUCT;

/*  GAN Band  19 */
struct IEI_GAN_Band {
   u_int8_t GANBand:4;
   u_int8_t spare:4;
} PACK_STRUCT;

/*  GA RC GA CSR GA PSR State  20 */
struct IEI_GA_RC_GA_CSR_GA_PSR_State {
   u_int8_t URS:2;
   u_int8_t UPS:1;
   u_int8_t GA_RRC_CS:1;
   u_int8_t GA_RRC_PS:1;
   u_int8_t spare:3;
} PACK_STRUCT;

/*  Register Reject Cause  21 */
struct IEI_Register_Reject_Cause {
   u_int8_t RRC;
} PACK_STRUCT;

/*  TU3906 Timer  22 */
struct IEI_TU3906_Timer {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  TU3910 Timer  23 */
struct IEI_TU3910_Timer {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  TU3902 Timer  24 */
struct IEI_TU3902_Timer {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  L3 Message  26 */
struct IEI_L3_Message {
   u_int8_t l3[1];
} PACK_STRUCT;

/*  Channel Mode  27 */
struct IEI_Channel_Mode {
   u_int8_t chanmode[1];
} PACK_STRUCT;

/*  Mobile Station Classmark 2  28 */
struct IEI_Mobile_Station_Classmark_2 {
   u_int8_t msclass2[1];
} PACK_STRUCT;

/*  RR Cause  29 */
struct IEI_RR_Cause {
   u_int8_t RRCause[1];
} PACK_STRUCT;

/*  Cipher Mode Setting  30 */
struct IEI_Cipher_Mode_Setting {
   u_int8_t SC:1;
   u_int8_t algoID:3;
   u_int8_t soare:4;
} PACK_STRUCT;

/*  GPRS Resumption  31 */
struct IEI_GPRS_Resumption {
   u_int8_t GPRSRes[1];
} PACK_STRUCT;

/*  Handover From GAN Command  32 */
struct IEI_Handover_From_GAN_Command {
   u_int8_t HoFGComm[1];
} PACK_STRUCT;

/*  UL Quality Indication  33 */
struct IEI_UL_Quality_Indication {
   u_int8_t ULQI:4;
   u_int8_t spare:4;
} PACK_STRUCT;

/*  TLLI  34 */
struct IEI_TLLI {
   u_int8_t TLLIm[1];
} PACK_STRUCT;

/*  Packet Flow Identifier  35 */
struct IEI_Packet_Flow_Identifier {
   u_int8_t PFID[1];
} PACK_STRUCT;

/*  Suspension Cause  36 */
struct IEI_Suspension_Cause {
   u_int8_t caue[1];
} PACK_STRUCT;

/*  TU3920 Timer  37 */
struct IEI_TU3920_Timer {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  QoS  38 */
struct IEI_QoS {
   u_int8_t PEAK_TROUGHPOUT_CLASS:4;
   u_int8_t RADIO_PRIORITY:2;
   u_int8_t RLC_MODE:1;
   u_int8_t spare:1;
} PACK_STRUCT;

/*  GA PSR Cause  39 */
struct IEI_GA_PSR_Cause {
   u_int8_t cause;
} PACK_STRUCT;

/*  User Data Rate  40 */
struct IEI_User_Data_Rate {
   u_int8_t R[3];
} PACK_STRUCT;

/*  Routing Area Code  41 */
struct IEI_Routing_Area_Code {
   u_int8_t code;
} PACK_STRUCT;

/*  AP Location  42 */
struct IEI_AP_Location {
   u_int8_t APLoc[1];
} PACK_STRUCT;

/*  TU4001 Timer  43 */
struct IEI_TU4001_Timer {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  Location Status  44 */
struct IEI_Location_Status {
   u_int8_t LS:2;
   u_int8_t spare:6;
} PACK_STRUCT;

/*  Cipher Response  45 */
struct IEI_Cipher_Response {
   u_int8_t CR:1;
   u_int8_t spare:7;
} PACK_STRUCT;

/*  Ciphering Command RAND  46 */
struct IEI_Ciphering_Command_RAND {
   u_int8_t CipherRand[16];
} PACK_STRUCT;

/*  Ciphering Command MAC  47 */
struct IEI_Ciphering_Command_MAC {
   u_int8_t MAC[12];
} PACK_STRUCT;

/*  Ciphering Key Sequence Number  48 */
struct IEI_Ciphering_Key_Sequence_Number {
   u_int8_t keyseq:3;
   u_int8_t spare:5;
} PACK_STRUCT;

/*  SAPI ID  49 */
struct IEI_SAPI_ID {
   u_int8_t SapiID:3;
   u_int8_t spare:5;
} PACK_STRUCT;

/*  Establishment Cause  50 */
struct IEI_Establishment_Cause {
   u_int8_t cause;
} PACK_STRUCT;

/*  Channel Needed  51 */
struct IEI_Channel_Needed {
   u_int8_t Chan:2;
   u_int8_t spare:6;
} PACK_STRUCT;

/*  PDU in Error  52 */
struct IEI_PDU_in_Error {
   u_int8_t PDU[1];
} PACK_STRUCT;

/*  Sample Size  53 */
struct IEI_Sample_Size {
   u_int8_t samplesize;
} PACK_STRUCT;

/*  Payload Type  54 */
struct IEI_Payload_Type {
   u_int8_t payloadtype;
} PACK_STRUCT;

/*  Multi rate Configuration  55 */
struct IEI_Multi_rate_Configuration {
   u_int8_t multiconf[1];
} PACK_STRUCT;

/*  Mobile Station Classmar 3  56 */
struct IEI_Mobile_Station_Classmar_3 {
   u_int8_t ClassMark3;
} PACK_STRUCT;

/*  LLC PDU  57 */
struct IEI_LLC_PDU {
   u_int8_t llcpdu[1];
} PACK_STRUCT;

/*  Location Black List indicator  58 */
struct IEI_Location_Black_List_indicator {
   u_int8_t LBLI:3;
   u_int8_t spare:5;
} PACK_STRUCT;

/*  Reset Indicator  59 */
struct IEI_Reset_Indicator {
   u_int8_t RI:1;
   u_int8_t spare:7;
} PACK_STRUCT;

/*  TU4003 Timer  60 */
struct IEI_TU4003_Timer {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  AP Service Name  61 */
struct IEI_AP_Service_Name {
   u_int8_t AP[1];
} PACK_STRUCT;

/*  GAN Service Zone Information  62 */
struct IEI_GAN_Service_Zone_Information {
   u_int8_t GanzoneID;
   u_int8_t Len;
   u_int8_t GANstr[1];
} PACK_STRUCT;

/*  RTP Redundancy Configuration  63 */
struct IEI_RTP_Redundancy_Configuration {
   u_int8_t winsize:2;
   u_int8_t ganlumode:4;
   u_int8_t ganmode:2;
} PACK_STRUCT;

/*  UTRAN Classmark  64 */
struct IEI_UTRAN_Classmark {
   u_int8_t classmark[1];
} PACK_STRUCT;

/*  Classmark Enquiry Mask  65 */
struct IEI_Classmark_Enquiry_Mask {
   u_int8_t mask[1];
} PACK_STRUCT;

/*  UTRAN Cell Identifier List  66 */
struct IEI_UTRAN_Cell_Identifier_List {
   u_int8_t celldesc:4;
   u_int8_t spare:4;
   u_int8_t utrancellid[1];
} PACK_STRUCT;

/*  Serving GANC table indicator  67 */
struct IEI_Serving_GANC_table_indicator {
   u_int8_t SUTI:1;
   u_int8_t spare:7;
} PACK_STRUCT;

/*  Registration indicators  68 */
struct IEI_Registration_indicators {
   u_int8_t MPS:2;
   u_int8_t spare:6;
} PACK_STRUCT;

/*  GAN PLMN List  69 */
struct IEI_GAN_PLMN_List {
   u_int8_t PLMNnumb;
   u_int8_t PLMN[1];
} PACK_STRUCT;

/*  Required GAN Services  71 */
struct IEI_Required_GAN_Services {
   u_int8_t CBS:1;
   u_int8_t spare:7;
} PACK_STRUCT;

/*  Broadcast Container  72 */
struct IEI_Broadcast_Container {
   u_int8_t nCBS;
   u_int8_t CBSFrames[1];
} PACK_STRUCT;

/*  Cell 3G Identity  73 */
struct IEI_Cell_3G_Identity {
   u_int8_t CellID[4];
} PACK_STRUCT;

/*  Security Capability 3G  74 */
struct IEI_Security_Capability_3G {
   u_int8_t ciph_algo_cap;
   u_int8_t ciph_algo_cap2;
   u_int8_t integ_protec_algo;
   u_int8_t integ_protec_algo2;
} PACK_STRUCT;

/*  NAS Synchronisation Indicator  75 */
struct IEI_NAS_Synchronisation_Indicator {
   u_int8_t NSI:4;
   u_int8_t spare:4;
} PACK_STRUCT;

/*  GANC TEID  76 */
struct IEI_GANC_TEID {
   u_int8_t TEID[4];
} PACK_STRUCT;

/*  MS TEID  77 */
struct IEI_MS_TEID {
   u_int8_t TEID[4];
} PACK_STRUCT;

/*  UTRAN RRC Message  78 */
struct IEI_UTRAN_RRC_Message {
   u_int8_t RRCmsg[1];
} PACK_STRUCT;

/*  GAN Mode Indicator  79 */
struct IEI_GAN_Mode_Indicator {
   u_int8_t GMI;
} PACK_STRUCT;

/*  CN Domain Identity  80 */
struct IEI_CN_Domain_Identity {
   u_int8_t CNDI;
} PACK_STRUCT;

/*  GAN Iu Mode Cell Description  81 */
struct IEI_GAN_Iu_Mode_Cell_Description {
   u_int8_t UARFCN;
   u_int8_t UARFCN2;
   u_int8_t PSC;
   u_int8_t PSC2;
} PACK_STRUCT;

/*  UARFCN 3G  82 */
struct IEI_UARFCN_3G {
   u_int8_t UARFCN;
   u_int8_t UARFCN2;
} PACK_STRUCT;

/*  RAB ID  83 */
struct IEI_RAB_ID {
   u_int8_t RABID;
} PACK_STRUCT;

/*  RAB ID List  84 */
struct IEI_RAB_ID_List {
   u_int8_t nRABID;
   u_int8_t RAIDList[1];
} PACK_STRUCT;

/*  GA RRC Establishment Cause  85 */
struct IEI_GA_RRC_Establishment_Cause {
   u_int8_t cause;
} PACK_STRUCT;

/*  GA RRC Cause  86 */
struct IEI_GA_RRC_Cause {
   u_int8_t cause_MSB;
   u_int8_t cause_LSB;
} PACK_STRUCT;

/*  GA RRC Paging Cause  87 */
struct IEI_GA_RRC_Paging_Cause {
   u_int8_t pagingcause;
} PACK_STRUCT;

/*  Intra Domain NAS Node Selector  88 */
struct IEI_Intra_Domain_NAS_Node_Selector {
   u_int8_t type;
   u_int8_t routparam;
   u_int8_t routparam2;
} PACK_STRUCT;

/*  CTC Activation List  89 */
struct IEI_CTC_Activation_List {
   u_int8_t nCTC;
   u_int8_t CTCs[1];
} PACK_STRUCT;

/*  CTC Description  90 */
struct IEI_CTC_Description {
   u_int8_t RABID;
   u_int8_t GARConfig;
   u_int8_t SampleSize;
   u_int8_t RTPUDPPort;
   u_int8_t GanIpAddr;
   u_int8_t PayloadType;
   u_int8_t MultirateConfig2;
   u_int8_t RTPRedundancyConfig;
   u_int8_t RTCPUDPPort;
   u_int8_t NSI;
} PACK_STRUCT;

/*  CTC Activation Ack List  91 */
struct IEI_CTC_Activation_Ack_List {
   u_int8_t nCTC;
   u_int8_t CTCs[1];
} PACK_STRUCT;

/*  CTC Activation Ack Description  92 */
struct IEI_CTC_Activation_Ack_Description {
   u_int8_t RABID;
   u_int8_t GARRCCause;
   u_int8_t RTPUDPPort;
   u_int8_t SampleSize;
   u_int8_t PAYLoadType;
   u_int8_t RTCPUDPPort;
} PACK_STRUCT;

/*  CTC Modification List  93 */
struct IEI_CTC_Modification_List {
   u_int8_t nCTC;
   u_int8_t CTCs[1];
} PACK_STRUCT;

/*  CTC Modification Ack List  94 */
struct IEI_CTC_Modification_Ack_List {
   u_int8_t nCTC;
   u_int8_t CTCs[1];
} PACK_STRUCT;

/*  CTC Modification Ack Description  95 */
struct IEI_CTC_Modification_Ack_Description {
   u_int8_t RABID;
   u_int8_t GARRCCause;
   u_int8_t SampleSize;
} PACK_STRUCT;

/*  MS Radio Identity  96 */
struct IEI_MS_Radio_Identity {
   u_int8_t type:4;
   u_int8_t spare:4;
   u_int8_t value[6];
} PACK_STRUCT;

/*  GANC IP Address  97 */
struct IEI_GANC_IP_Address {
   u_int8_t IPAddr[1];
} PACK_STRUCT;

/*  GANC Fully Qualified Domain Host Name  98 */
struct IEI_GANC_Fully_Qualified_Domain_Host_Name {
   u_int8_t fqdn[1];
} PACK_STRUCT;

/*  IP address for GPRS user data transport  99 */
struct IEI_IP_address_for_GPRS_user_data_transport {
   u_int8_t IPAddr[1];
} PACK_STRUCT;

/*  UDP Port for GPRS user data transport  100 */
struct IEI_UDP_Port_for_GPRS_user_data_transport {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  GANC TCP port  103 */
struct IEI_GANC_TCP_port {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  RTP UDP port  104 */
struct IEI_RTP_UDP_port {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  RTCP UDP port  105 */
struct IEI_RTCP_UDP_port {
   u_int8_t MSB;
   u_int8_t LSB;
} PACK_STRUCT;

/*  GERAN Received Signal Level List  106 */
struct IEI_GERAN_Received_Signal_Level_List {
   u_int8_t RXLEVELs[1];
} PACK_STRUCT;

/*  UTRAN Received Signal Level List  107 */
struct IEI_UTRAN_Received_Signal_Level_List {
   u_int8_t RSLL[1];
} PACK_STRUCT;

/*  PS Handover to GERAN Command  108 */
struct IEI_PS_Handover_to_GERAN_Command {
   u_int8_t data[1];
} PACK_STRUCT;

/*  PS Handover to UTRAN Command  109 */
struct IEI_PS_Handover_to_UTRAN_Command {
   u_int8_t data[1];
} PACK_STRUCT;

/*  PS Handover to GERAN PSI  110 */
struct IEI_PS_Handover_to_GERAN_PSI {
   u_int8_t data[1];
} PACK_STRUCT;

/*  PS Handover to GERAN SI  111 */
struct IEI_PS_Handover_to_GERAN_SI {
   u_int8_t data[1];
} PACK_STRUCT;

/*  TU4004 Timer  112 */
struct IEI_TU4004_Timer {
   u_int8_t Tu4004val;
} PACK_STRUCT;

/*  PTC Activation List  115 */
struct IEI_PTC_Activation_List {
   u_int8_t nPTCS;
   u_int8_t PTCs[1];
} PACK_STRUCT;

/*  PTC Description  116 */
struct IEI_PTC_Description {
   u_int8_t RABID;
   u_int8_t RABConf;
   u_int8_t GANCTEID;
   u_int8_t MSTEID;
   u_int8_t GANCUDPPort;
   u_int8_t GANCIPADDR;
} PACK_STRUCT;

/*  PTC Activation Ack List  117 */
struct IEI_PTC_Activation_Ack_List {
   u_int8_t nPTC;
   u_int8_t PTCs[1];
} PACK_STRUCT;

/*  PTC Activation Ack Description  118 */
struct IEI_PTC_Activation_Ack_Description {
   u_int8_t RABID;
   u_int8_t GARRCCause;
   u_int8_t MSUDPort;
} PACK_STRUCT;

/*  PTC Modification List  119 */
struct IEI_PTC_Modification_List {
   u_int8_t nPTC;
   u_int8_t PTCs[1];
} PACK_STRUCT;

/*  PTC Modification Ack List  120 */
struct IEI_PTC_Modification_Ack_List {
   u_int8_t nPTC;
   u_int8_t PTCs[1];
} PACK_STRUCT;

/*  PTC Modification Ack Description  121 */
struct IEI_PTC_Modification_Ack_Description {
   u_int8_t RABID;
   u_int8_t GARRCCause;
   u_int8_t RABConfig;
   u_int8_t GANUDPPort;
   u_int8_t GANCIPAddr;
} PACK_STRUCT;

/*  RAB Configuration  122 */
struct IEI_RAB_Configuration {
   u_int8_t TrafficClass:2;
   u_int8_t AI:2;
   u_int8_t DO:1;
   u_int8_t SSD:1;
   u_int8_t SI:1;
   u_int8_t spare:1;
   u_int8_t spare3:3;
   u_int8_t TrafficHandlingPriority:4;
   u_int8_t spare2:1;
   u_int8_t MaxDLBitRate[4];
   u_int8_t MaxUlBitRate[4];
   u_int8_t GuaranteedDlBitRate[4];
   u_int8_t GuaranteedUlBitRate[4];
} PACK_STRUCT;

/*  Multi rate Configuration 2  123 */
struct IEI_Multi_rate_Configuration_2 {
   u_int8_t MultiRateConf2[1];
} PACK_STRUCT;

/*  Selected Integrity Protection Algorithm  124 */
struct IEI_Selected_Integrity_Protection_Algorithm {
   u_int8_t IntegrityProtectionAlgo;
} PACK_STRUCT;

/*  Selected Encryption Algorithm  125 */
struct IEI_Selected_Encryption_Algorithm {
   u_int8_t EncryptProtectionAlgo;
} PACK_STRUCT;

/*  CN Domains to Handover  126 */
struct IEI_CN_Domains_to_Handover {
   u_int8_t CNDH:2;
   u_int8_t spare:6;
} PACK_STRUCT;

/*  SRNS Relocation Info  127 */
struct IEI_SRNS_Relocation_Info {
   u_int8_t UTRANRRCMsg[1];
} PACK_STRUCT;

/*  MS Radio Access Capability  128 */
struct IEI_MS_Radio_Access_Capability {
   u_int8_t Len;
   u_int8_t MSRAC[1];
} PACK_STRUCT;







#ifdef _MSC_VER
# pragma pack( pop, packing )
#endif














void tlv_print_IEI_Mobile_Identity(u_int8_t *buf);
void tlv_print_IEI_GAN_Release_Indicator(u_int8_t *buf);
void tlv_print_IEI_Radio_Identity(u_int8_t *buf);
void tlv_print_IEI_GERAN_Cell_Identity(u_int8_t *buf);
void tlv_print_IEI_Location_Area_Identification(u_int8_t *buf);
void tlv_print_IEI_GERAN_UTRAN_coverage_Indicator(u_int8_t *buf);
void tlv_print_IEI_GAN_Classmark(u_int8_t *buf);
void tlv_print_IEI_Geographical_Location(u_int8_t *buf);
void tlv_print_IEI_GANC_SEGW_IP_Address(u_int8_t *buf);
void tlv_print_IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name(u_int8_t *buf);
void tlv_print_IEI_Redirection_Counter(u_int8_t *buf);
void tlv_print_IEI_Discovery_Reject_Cause(u_int8_t *buf);
void tlv_print_IEI_GAN_Cell_Description(u_int8_t *buf);
void tlv_print_IEI_GAN_Control_Channel_Description(u_int8_t *buf);
void tlv_print_IEI_Cell_Identifier_List(u_int8_t *buf);
void tlv_print_IEI_TU3907_Timer(u_int8_t *buf);
void tlv_print_IEI_GSM_RR_UTRAN_RRC_State(u_int8_t *buf);
void tlv_print_IEI_Routing_Area_Identification(u_int8_t *buf);
void tlv_print_IEI_GAN_Band(u_int8_t *buf);
void tlv_print_IEI_GA_RC_GA_CSR_GA_PSR_State(u_int8_t *buf);
void tlv_print_IEI_Register_Reject_Cause(u_int8_t *buf);
void tlv_print_IEI_TU3906_Timer(u_int8_t *buf);
void tlv_print_IEI_TU3910_Timer(u_int8_t *buf);
void tlv_print_IEI_TU3902_Timer(u_int8_t *buf);
void tlv_print_IEI_L3_Message(u_int8_t *buf);
void tlv_print_IEI_Channel_Mode(u_int8_t *buf);
void tlv_print_IEI_Mobile_Station_Classmark_2(u_int8_t *buf);
void tlv_print_IEI_RR_Cause(u_int8_t *buf);
void tlv_print_IEI_Cipher_Mode_Setting(u_int8_t *buf);
void tlv_print_IEI_GPRS_Resumption(u_int8_t *buf);
void tlv_print_IEI_Handover_From_GAN_Command(u_int8_t *buf);
void tlv_print_IEI_UL_Quality_Indication(u_int8_t *buf);
void tlv_print_IEI_TLLI(u_int8_t *buf);
void tlv_print_IEI_Packet_Flow_Identifier(u_int8_t *buf);
void tlv_print_IEI_Suspension_Cause(u_int8_t *buf);
void tlv_print_IEI_TU3920_Timer(u_int8_t *buf);
void tlv_print_IEI_QoS(u_int8_t *buf);
void tlv_print_IEI_GA_PSR_Cause(u_int8_t *buf);
void tlv_print_IEI_User_Data_Rate(u_int8_t *buf);
void tlv_print_IEI_Routing_Area_Code(u_int8_t *buf);
void tlv_print_IEI_AP_Location(u_int8_t *buf);
void tlv_print_IEI_TU4001_Timer(u_int8_t *buf);
void tlv_print_IEI_Location_Status(u_int8_t *buf);
void tlv_print_IEI_Cipher_Response(u_int8_t *buf);
void tlv_print_IEI_Ciphering_Command_RAND(u_int8_t *buf);
void tlv_print_IEI_Ciphering_Command_MAC(u_int8_t *buf);
void tlv_print_IEI_Ciphering_Key_Sequence_Number(u_int8_t *buf);
void tlv_print_IEI_SAPI_ID(u_int8_t *buf);
void tlv_print_IEI_Establishment_Cause(u_int8_t *buf);
void tlv_print_IEI_Channel_Needed(u_int8_t *buf);
void tlv_print_IEI_PDU_in_Error(u_int8_t *buf);
void tlv_print_IEI_Sample_Size(u_int8_t *buf);
void tlv_print_IEI_Payload_Type(u_int8_t *buf);
void tlv_print_IEI_Multi_rate_Configuration(u_int8_t *buf);
void tlv_print_IEI_Mobile_Station_Classmar_3(u_int8_t *buf);
void tlv_print_IEI_LLC_PDU(u_int8_t *buf);
void tlv_print_IEI_Location_Black_List_indicator(u_int8_t *buf);
void tlv_print_IEI_Reset_Indicator(u_int8_t *buf);
void tlv_print_IEI_TU4003_Timer(u_int8_t *buf);
void tlv_print_IEI_AP_Service_Name(u_int8_t *buf);
void tlv_print_IEI_GAN_Service_Zone_Information(u_int8_t *buf);
void tlv_print_IEI_RTP_Redundancy_Configuration(u_int8_t *buf);
void tlv_print_IEI_UTRAN_Classmark(u_int8_t *buf);
void tlv_print_IEI_Classmark_Enquiry_Mask(u_int8_t *buf);
void tlv_print_IEI_UTRAN_Cell_Identifier_List(u_int8_t *buf);
void tlv_print_IEI_Serving_GANC_table_indicator(u_int8_t *buf);
void tlv_print_IEI_Registration_indicators(u_int8_t *buf);
void tlv_print_IEI_GAN_PLMN_List(u_int8_t *buf);
void tlv_print_IEI_Required_GAN_Services(u_int8_t *buf);
void tlv_print_IEI_Broadcast_Container(u_int8_t *buf);
void tlv_print_IEI_Cell_3G_Identity(u_int8_t *buf);
void tlv_print_IEI_Security_Capability_3G(u_int8_t *buf);
void tlv_print_IEI_NAS_Synchronisation_Indicator(u_int8_t *buf);
void tlv_print_IEI_GANC_TEID(u_int8_t *buf);
void tlv_print_IEI_MS_TEID(u_int8_t *buf);
void tlv_print_IEI_UTRAN_RRC_Message(u_int8_t *buf);
void tlv_print_IEI_GAN_Mode_Indicator(u_int8_t *buf);
void tlv_print_IEI_CN_Domain_Identity(u_int8_t *buf);
void tlv_print_IEI_GAN_Iu_Mode_Cell_Description(u_int8_t *buf);
void tlv_print_IEI_UARFCN_3G(u_int8_t *buf);
void tlv_print_IEI_RAB_ID(u_int8_t *buf);
void tlv_print_IEI_RAB_ID_List(u_int8_t *buf);
void tlv_print_IEI_GA_RRC_Establishment_Cause(u_int8_t *buf);
void tlv_print_IEI_GA_RRC_Cause(u_int8_t *buf);
void tlv_print_IEI_GA_RRC_Paging_Cause(u_int8_t *buf);
void tlv_print_IEI_Intra_Domain_NAS_Node_Selector(u_int8_t *buf);
void tlv_print_IEI_CTC_Activation_List(u_int8_t *buf);
void tlv_print_IEI_CTC_Description(u_int8_t *buf);
void tlv_print_IEI_CTC_Activation_Ack_List(u_int8_t *buf);
void tlv_print_IEI_CTC_Activation_Ack_Description(u_int8_t *buf);
void tlv_print_IEI_CTC_Modification_List(u_int8_t *buf);
void tlv_print_IEI_CTC_Modification_Ack_List(u_int8_t *buf);
void tlv_print_IEI_CTC_Modification_Ack_Description(u_int8_t *buf);
void tlv_print_IEI_MS_Radio_Identity(u_int8_t *buf);
void tlv_print_IEI_GANC_IP_Address(u_int8_t *buf);
void tlv_print_IEI_GANC_Fully_Qualified_Domain_Host_Name(u_int8_t *buf);
void tlv_print_IEI_IP_address_for_GPRS_user_data_transport(u_int8_t *buf);
void tlv_print_IEI_UDP_Port_for_GPRS_user_data_transport(u_int8_t *buf);
void tlv_print_IEI_GANC_TCP_port(u_int8_t *buf);
void tlv_print_IEI_RTP_UDP_port(u_int8_t *buf);
void tlv_print_IEI_RTCP_UDP_port(u_int8_t *buf);
void tlv_print_IEI_GERAN_Received_Signal_Level_List(u_int8_t *buf);
void tlv_print_IEI_UTRAN_Received_Signal_Level_List(u_int8_t *buf);
void tlv_print_IEI_PS_Handover_to_GERAN_Command(u_int8_t *buf);
void tlv_print_IEI_PS_Handover_to_UTRAN_Command(u_int8_t *buf);
void tlv_print_IEI_PS_Handover_to_GERAN_PSI(u_int8_t *buf);
void tlv_print_IEI_PS_Handover_to_GERAN_SI(u_int8_t *buf);
void tlv_print_IEI_TU4004_Timer(u_int8_t *buf);
void tlv_print_IEI_PTC_Activation_List(u_int8_t *buf);
void tlv_print_IEI_PTC_Description(u_int8_t *buf);
void tlv_print_IEI_PTC_Activation_Ack_List(u_int8_t *buf);
void tlv_print_IEI_PTC_Activation_Ack_Description(u_int8_t *buf);
void tlv_print_IEI_PTC_Modification_List(u_int8_t *buf);
void tlv_print_IEI_PTC_Modification_Ack_List(u_int8_t *buf);
void tlv_print_IEI_PTC_Modification_Ack_Description(u_int8_t *buf);
void tlv_print_IEI_RAB_Configuration(u_int8_t *buf);
void tlv_print_IEI_Multi_rate_Configuration_2(u_int8_t *buf);
void tlv_print_IEI_Selected_Integrity_Protection_Algorithm(u_int8_t *buf);
void tlv_print_IEI_Selected_Encryption_Algorithm(u_int8_t *buf);
void tlv_print_IEI_CN_Domains_to_Handover(u_int8_t *buf);
void tlv_print_IEI_SRNS_Relocation_Info(u_int8_t *buf);
void tlv_print_IEI_MS_Radio_Access_Capability(u_int8_t *buf);



static void *print_table[130] = {
  NULL,
  tlv_print_IEI_Mobile_Identity,
  tlv_print_IEI_GAN_Release_Indicator,
  tlv_print_IEI_Radio_Identity,
  tlv_print_IEI_GERAN_Cell_Identity,
  tlv_print_IEI_Location_Area_Identification,
  tlv_print_IEI_GERAN_UTRAN_coverage_Indicator,
  tlv_print_IEI_GAN_Classmark,
  tlv_print_IEI_Geographical_Location,
  tlv_print_IEI_GANC_SEGW_IP_Address,
  tlv_print_IEI_GANC_SEGW_Fully_Qualified_Domain_Host_Name,
  tlv_print_IEI_Redirection_Counter,
  tlv_print_IEI_Discovery_Reject_Cause,
  tlv_print_IEI_GAN_Cell_Description,
  tlv_print_IEI_GAN_Control_Channel_Description,
  tlv_print_IEI_Cell_Identifier_List,
  tlv_print_IEI_TU3907_Timer,
  tlv_print_IEI_GSM_RR_UTRAN_RRC_State,
  tlv_print_IEI_Routing_Area_Identification,
  tlv_print_IEI_GAN_Band,
  tlv_print_IEI_GA_RC_GA_CSR_GA_PSR_State,
  tlv_print_IEI_Register_Reject_Cause,
  tlv_print_IEI_TU3906_Timer,
  tlv_print_IEI_TU3910_Timer,
  tlv_print_IEI_TU3902_Timer,
  NULL,
  tlv_print_IEI_L3_Message,
  tlv_print_IEI_Channel_Mode,
  tlv_print_IEI_Mobile_Station_Classmark_2,
  tlv_print_IEI_RR_Cause,
  tlv_print_IEI_Cipher_Mode_Setting,
  tlv_print_IEI_GPRS_Resumption,
  tlv_print_IEI_Handover_From_GAN_Command,
  tlv_print_IEI_UL_Quality_Indication,
  tlv_print_IEI_TLLI,
  tlv_print_IEI_Packet_Flow_Identifier,
  tlv_print_IEI_Suspension_Cause,
  tlv_print_IEI_TU3920_Timer,
  tlv_print_IEI_QoS,
  tlv_print_IEI_GA_PSR_Cause,
  tlv_print_IEI_User_Data_Rate,
  tlv_print_IEI_Routing_Area_Code,
  tlv_print_IEI_AP_Location,
  tlv_print_IEI_TU4001_Timer,
  tlv_print_IEI_Location_Status,
  tlv_print_IEI_Cipher_Response,
  tlv_print_IEI_Ciphering_Command_RAND,
  tlv_print_IEI_Ciphering_Command_MAC,
  tlv_print_IEI_Ciphering_Key_Sequence_Number,
  tlv_print_IEI_SAPI_ID,
  tlv_print_IEI_Establishment_Cause,
  tlv_print_IEI_Channel_Needed,
  tlv_print_IEI_PDU_in_Error,
  tlv_print_IEI_Sample_Size,
  tlv_print_IEI_Payload_Type,
  tlv_print_IEI_Multi_rate_Configuration,
  tlv_print_IEI_Mobile_Station_Classmar_3,
  tlv_print_IEI_LLC_PDU,
  tlv_print_IEI_Location_Black_List_indicator,
  tlv_print_IEI_Reset_Indicator,
  tlv_print_IEI_TU4003_Timer,
  tlv_print_IEI_AP_Service_Name,
  tlv_print_IEI_GAN_Service_Zone_Information,
  tlv_print_IEI_RTP_Redundancy_Configuration,
  tlv_print_IEI_UTRAN_Classmark,
  tlv_print_IEI_Classmark_Enquiry_Mask,
  tlv_print_IEI_UTRAN_Cell_Identifier_List,
  tlv_print_IEI_Serving_GANC_table_indicator,
  tlv_print_IEI_Registration_indicators,
  tlv_print_IEI_GAN_PLMN_List,
  NULL,
  tlv_print_IEI_Required_GAN_Services,
  tlv_print_IEI_Broadcast_Container,
  tlv_print_IEI_Cell_3G_Identity,
  tlv_print_IEI_Security_Capability_3G,
  tlv_print_IEI_NAS_Synchronisation_Indicator,
  tlv_print_IEI_GANC_TEID,
  tlv_print_IEI_MS_TEID,
  tlv_print_IEI_UTRAN_RRC_Message,
  tlv_print_IEI_GAN_Mode_Indicator,
  tlv_print_IEI_CN_Domain_Identity,
  tlv_print_IEI_GAN_Iu_Mode_Cell_Description,
  tlv_print_IEI_UARFCN_3G,
  tlv_print_IEI_RAB_ID,
  tlv_print_IEI_RAB_ID_List,
  tlv_print_IEI_GA_RRC_Establishment_Cause,
  tlv_print_IEI_GA_RRC_Cause,
  tlv_print_IEI_GA_RRC_Paging_Cause,
  tlv_print_IEI_Intra_Domain_NAS_Node_Selector,
  tlv_print_IEI_CTC_Activation_List,
  tlv_print_IEI_CTC_Description,
  tlv_print_IEI_CTC_Activation_Ack_List,
  tlv_print_IEI_CTC_Activation_Ack_Description,
  tlv_print_IEI_CTC_Modification_List,
  tlv_print_IEI_CTC_Modification_Ack_List,
  tlv_print_IEI_CTC_Modification_Ack_Description,
  tlv_print_IEI_MS_Radio_Identity,
  tlv_print_IEI_GANC_IP_Address,
  tlv_print_IEI_GANC_Fully_Qualified_Domain_Host_Name,
  tlv_print_IEI_IP_address_for_GPRS_user_data_transport,
  tlv_print_IEI_UDP_Port_for_GPRS_user_data_transport,
  NULL,
  NULL,
  tlv_print_IEI_GANC_TCP_port,
  tlv_print_IEI_RTP_UDP_port,
  tlv_print_IEI_RTCP_UDP_port,
  tlv_print_IEI_GERAN_Received_Signal_Level_List,
  tlv_print_IEI_UTRAN_Received_Signal_Level_List,
  tlv_print_IEI_PS_Handover_to_GERAN_Command,
  tlv_print_IEI_PS_Handover_to_UTRAN_Command,
  tlv_print_IEI_PS_Handover_to_GERAN_PSI,
  tlv_print_IEI_PS_Handover_to_GERAN_SI,
  tlv_print_IEI_TU4004_Timer,
  NULL,
  NULL,
  tlv_print_IEI_PTC_Activation_List,
  tlv_print_IEI_PTC_Description,
  tlv_print_IEI_PTC_Activation_Ack_List,
  tlv_print_IEI_PTC_Activation_Ack_Description,
  tlv_print_IEI_PTC_Modification_List,
  tlv_print_IEI_PTC_Modification_Ack_List,
  tlv_print_IEI_PTC_Modification_Ack_Description,
  tlv_print_IEI_RAB_Configuration,
  tlv_print_IEI_Multi_rate_Configuration_2,
  tlv_print_IEI_Selected_Integrity_Protection_Algorithm,
  tlv_print_IEI_Selected_Encryption_Algorithm,
  tlv_print_IEI_CN_Domains_to_Handover,
  tlv_print_IEI_SRNS_Relocation_Info,
  tlv_print_IEI_MS_Radio_Access_Capability,
};



#endif
