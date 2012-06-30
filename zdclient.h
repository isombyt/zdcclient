/*
 * =====================================================================================
 *
 *       Filename:  zdclient.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  06/06/2009 03:47:25 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *        Company:
 *
 * =====================================================================================
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>


#ifndef __linux
//------bsd/apple mac
    #include <net/if_var.h>
    #include <net/if_dl.h>
    #include <net/if_types.h>
#endif

#include <getopt.h>
#include <iconv.h>
#include "md5.h"

/* ZDClient Version */
#define ZDC_VER "0.13"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

struct eap_header {
    uint8_t eapol_v;
    uint8_t eapol_t;
    uint16_t eapol_length;
    uint8_t eap_t;
    uint8_t eap_id;
    uint16_t eap_length;
    uint8_t eap_op;
    uint8_t eap_v_length;
    uint8_t eap_md5_challenge[16];
};

struct dcba_tailer {
    bpf_u_int32     local_ip;
    bpf_u_int32     local_mask;
    bpf_u_int32     local_gateway;
    bpf_u_int32     local_dns;
    uint8_t          username_md5[16];
    uint8_t          client_ver[13];
};

enum EAPType {
    EAPOL_START,
    EAPOL_LOGOFF,
    EAP_REQUEST_IDENTITY,
    EAP_RESPONSE_IDENTITY,
    EAP_REQUEST_IDENTITY_KEEP_ALIVE,
    EAP_RESPONSE_IDENTITY_KEEP_ALIVE,
    EAP_REQUETS_MD5_CHALLENGE,
    EAP_RESPONSE_MD5_CHALLENGE,
    EAP_SUCCESS,
    EAP_FAILURE,
    ERROR,
    EAP_REQUEST_MD5_KEEP_ALIVE=250
};

enum STATE {
   READY,
   STARTED,
   ID_AUTHED,
   ONLINE
};

void    send_eap_packet(enum EAPType send_type);
void    show_usage();
char*   get_md5_digest(const char* str, size_t len);
void    action_by_eap_type(enum EAPType pType,
                        const struct eap_header *header,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet);
void    send_eap_packet(enum EAPType send_type);
void    init_frames();
void    init_info();
void    init_device();
void    init_arguments(int *argc, char ***argv);
int     set_device_new_ip();
void    fill_password_md5(uint8_t attach_key[], uint8_t eap_id);
void    fill_uname_md5(uint8_t attach_key[], uint8_t eap_id);
int     program_running_check();
void    daemon_init(void);
void    show_local_info();
void    print_server_info (const uint8_t *packet, uint16_t packetlength);
int     code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen);


void
get_packet(uint8_t *args, const struct pcap_pkthdr *header,
    const uint8_t *packet);


