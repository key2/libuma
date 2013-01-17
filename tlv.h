/*
   Copyright (C) 2010 Ramtin Amin <keytwo@gmail.com>
   See COPYING file for license details
*/

#ifndef __TLV_H_
#define __TLV_H_
#include <sys/types.h>


struct tlv_s{
  u_int8_t type;
  u_int32_t len;
  u_int8_t *value;
};

u_int32_t tlv_to_buf(u_int8_t **buf, struct tlv_s *tlv);
struct tlv_s *tlv_create(u_int8_t type, u_int8_t *buf, u_int32_t len);
u_int32_t tlv_get_len(u_int8_t *buf);
void tlv_printf(u_int8_t *buf);
u_int32_t tlv_get_header_len(u_int8_t *buf);
#endif
