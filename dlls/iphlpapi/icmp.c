/*
 * ICMP
 *
 * Francois Gouget, 1999, based on the work of
 *   RW Hall, 1999, based on public domain code PING.C by Mike Muus (1983)
 *   and later works (c) 1989 Regents of Univ. of California - see copyright
 *   notice at end of source-code.
 * Copyright 2015 Sebastian Lackner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Future work:
 * - Systems like FreeBSD don't seem to support the IP_TTL option and maybe others.
 *   But using IP_HDRINCL and building the IP header by hand might work.
 * - Not all IP options are supported.
 * - Are ICMP handles real handles, i.e. inheritable and all? There might be some
 *   more work to do here, including server side stuff with synchronization.
 * - This API should probably be thread safe. Is it really?
 * - Using the winsock functions has not been tested.
 */

#include "config.h"
#include "wine/port.h"

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#endif
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#if defined(__linux__)
# include <linux/errqueue.h>
#endif

#define USE_WS_PREFIX

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winternl.h"
#include "ipexport.h"
#include "icmpapi.h"
#include "wine/debug.h"

/* Set up endianness macros for the ip and ip_icmp BSD headers */
#ifndef BIG_ENDIAN
#define BIG_ENDIAN       4321
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN    1234
#endif
#ifndef BYTE_ORDER
#ifdef WORDS_BIGENDIAN
#define BYTE_ORDER       BIG_ENDIAN
#else
#define BYTE_ORDER       LITTLE_ENDIAN
#endif
#endif /* BYTE_ORDER */

#define u_int16_t  WORD
#define u_int32_t  DWORD

/* These are BSD headers. We use these here because they are needed on
 * libc5 Linux systems. On other platforms they are usually simply more
 * complete than the native stuff, and cause less portability problems
 * so we use them anyway.
 */
#include "ip.h"
#include "ip_icmp.h"


WINE_DEFAULT_DEBUG_CHANNEL(icmp);
WINE_DECLARE_DEBUG_CHANNEL(winediag);


typedef struct {
    int sid;
    IP_OPTION_INFORMATION default_opts;
    BOOL unprivileged;
} icmp_t;

#define IP_OPTS_UNKNOWN     0
#define IP_OPTS_DEFAULT     1
#define IP_OPTS_CUSTOM      2

#define MAXIPLEN            60
#define MAXICMPLEN          76

/* The sequence number is unique process wide, so that all threads
 * have a distinct sequence number.
 */
static LONG icmp_sequence=0;

static int in_cksum(u_short *addr, int len)
{
    int nleft=len;
    u_short *w = addr;
    int sum = 0;
    u_short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum  += (sum >> 16);
    answer = ~sum;
    return(answer);
}

/* Receive a reply (IPv4); this function uses, takes ownership of and will always free `buffer` */
static DWORD icmp_get_reply(int sid, unsigned char *buffer, DWORD send_time, void *reply_buf, DWORD reply_size, DWORD timeout, BOOL unprivileged)
{
    int repsize = MAXIPLEN + MAXICMPLEN + min(65535, reply_size);
    struct icmp *icmp_header = (struct icmp*)buffer;
    char *endbuf = (char*)reply_buf + reply_size;
    struct ip *ip_header = (struct ip*)buffer;
    struct icmp_echo_reply *ier = reply_buf;
    unsigned short id, seq, cksum;
    struct sockaddr_in addr;
    int ip_header_len = 0;
    struct pollfd fdr;
    DWORD recv_time;
    struct msghdr msg;
    struct iovec iov;
    char cbuf[512];
    int res;

    id = icmp_header->icmp_id;
    seq = icmp_header->icmp_seq;
    cksum = icmp_header->icmp_cksum;
    fdr.fd = sid;
    fdr.events = POLLIN;

    while (poll(&fdr,1,timeout)>0) {
        recv_time = GetTickCount();

        iov.iov_base = buffer;
        iov.iov_len = repsize;
        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_flags = 0;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        res=recvmsg(sid, &msg, MSG_DONTWAIT);
        TRACE("received %d bytes from %s\n",res, inet_ntoa(addr.sin_addr));
        ier->Status=IP_REQ_TIMED_OUT;
#if defined(__linux__)
        if (unprivileged) {
            if (res < 0) {
                res = recvmsg(sid, &msg, MSG_DONTWAIT | MSG_ERRQUEUE);
            }
            /* What recvmsg() gave us for:
             * - Linux's unprivileged ICMP sockets:
             *    - On success:                 | reply's ICMP            | reply's payload               |
             *    - MSG_ERRQUEUE:               | offending packet's ICMP | offending packet's payload    |
             *                                   with some of the ICMP reply's data in the ancillary data
             * - Everything else:
             *    - On success:    | reply's IP | reply's ICMP            | reply's payload               |
             *    - On error:      | reply's IP | reply's ICMP            | offending IP | offending ICMP |
             *                                                            ----often found in payload-------
             *
             * So for Linux's parody implementation, we generate some semblance of the reply's IP header,
             * and for errors, ICMP header, from the recvmsg() ancillary data, but ignore the offending
             * packet's data for ICMP errors, as it's hard to reconstruct, and Windows doesn't seem to
             * provide any ICMP error data anyway:
             *     On FreeBSD router: route add -host 1.2.3.4 127.0.0.1 -reject
             *     Ping 1.2.3.4 from Windows 7, the reply is ICMP host unreachable, IcmpSendEcho() returns 1
             *     with:
             *         ICMP_ECHO_REPLY: {
             *             Status: 11003 (IP_DEST_HOST_UNREACHABLE)
             *             DataSize: 0   <----- NO ICMP error data!!!
             *             Options: {
             *                 Ttl: 64
             *                 Tos: 0
             *                 Flags: 0
             *             }
             *         }
             */
            if (res >= 0) {
                struct cmsghdr *cmsg;
                int ttl = 0;
                u_char tos = 0;
                struct in_addr ip_dst = { 0 };
                u_char *options = NULL;
                int options_len = 0;
                int err_type = 0;
                int err_code = 0;
                int err_info = 0;
                int icmp_err_size = 0;
                for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                    if (cmsg->cmsg_level == SOL_IP) {
                        if (cmsg->cmsg_type == IP_OPTIONS) {
                            struct ip_opts *opts;
                            u_char *option;
                            opts = (struct ip_opts*) CMSG_DATA(cmsg);
                            option = (u_char*) opts->ip_opts;
                            while (IPOPT_NUMBER(*option) != IPOPT_EOL) {
                                option += 1 + option[1];
                            }
                            options = (u_char*) opts->ip_opts;
                            options_len = option - (u_char*)CMSG_DATA(cmsg);
                        } else if (cmsg->cmsg_type == IP_PKTINFO) {
                            struct in_pktinfo pktinfo;
                            memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
                            ip_dst = pktinfo.ipi_addr;
                        } else if (cmsg->cmsg_type == IP_TTL) {
                            memcpy(&ttl, CMSG_DATA(cmsg), sizeof(int));
                        } else if (cmsg->cmsg_type == IP_TOS) {
                            tos = *(u_char*)CMSG_DATA(cmsg);
                        } else if (cmsg->cmsg_type == IP_RECVERR) {
                            struct sock_extended_err *err = (struct sock_extended_err*) CMSG_DATA(cmsg);
                            res = 0; /* on error, trim all reply data, like Windows seems to */
                            if (err->ee_origin == SO_EE_ORIGIN_ICMP) {
                                err_type = err->ee_type;
                                err_code = err->ee_code;
                                err_info = err->ee_info;
                                icmp_err_size = ICMP_MINLEN;
                            } else {
                                FIXME("unsupported ee_origin %d\n", err->ee_origin);
                                break;
                            }
                        }
                    }
                }
                memmove(&buffer[sizeof(struct ip) + options_len + icmp_err_size], buffer, res);
                ip_header->ip_v = 4;
                ip_header->ip_hl = (sizeof(struct ip) + options_len) >> 2;
                ip_header->ip_tos = tos;
                ip_header->ip_len = sizeof(struct ip) + options_len + icmp_err_size + res;
                ip_header->ip_id = 0;
                ip_header->ip_off = 0;
                ip_header->ip_ttl = ttl;
                ip_header->ip_p = IPPROTO_ICMP;
                ip_header->ip_src = addr.sin_addr;
                ip_header->ip_dst = ip_dst;
                if (options)
                    memcpy(&buffer[sizeof(struct ip)], options, options_len);
                icmp_header = (struct icmp*)(((char*)ip_header) + (ip_header->ip_hl << 2));
                if (icmp_err_size) {
                    icmp_header->icmp_type = err_type;
                    icmp_header->icmp_code = err_code;
                    icmp_header->icmp_hun.ih_void = err_info; /* FIXME: check */
                } else {
                    /* Linux kernel overwrites the icmp_id with its own one, but only gives us replies that match it:
                     * https://lwn.net/Articles/443051/
                     * Rewrite it back so it matches what we expect later: */
                    icmp_header->icmp_id = id;
                }
                res += sizeof(struct ip) + options_len + icmp_err_size;
            }
        }
#endif

        /* Check whether we should ignore this packet */
        if ((ip_header->ip_p==IPPROTO_ICMP) && (res>=sizeof(struct ip)+ICMP_MINLEN)) {
            ip_header_len=ip_header->ip_hl << 2;
            icmp_header=(struct icmp*)(((char*)ip_header)+ip_header_len);
            TRACE("received an ICMP packet of type,code=%d,%d\n",icmp_header->icmp_type,icmp_header->icmp_code);
            if (icmp_header->icmp_type==ICMP_ECHOREPLY) {
                if ((icmp_header->icmp_id==id) && (icmp_header->icmp_seq==seq))
                {
                    ier->Status=IP_SUCCESS;
                    SetLastError(NO_ERROR);
                }
            } else {
                switch (icmp_header->icmp_type) {
                case ICMP_UNREACH:
                    switch (icmp_header->icmp_code) {
                    case ICMP_UNREACH_HOST:
#ifdef ICMP_UNREACH_HOST_UNKNOWN
                    case ICMP_UNREACH_HOST_UNKNOWN:
#endif
#ifdef ICMP_UNREACH_ISOLATED
                    case ICMP_UNREACH_ISOLATED:
#endif
#ifdef ICMP_UNREACH_HOST_PROHIB
		    case ICMP_UNREACH_HOST_PROHIB:
#endif
#ifdef ICMP_UNREACH_TOSHOST
                    case ICMP_UNREACH_TOSHOST:
#endif
                        ier->Status=IP_DEST_HOST_UNREACHABLE;
                        break;
                    case ICMP_UNREACH_PORT:
                        ier->Status=IP_DEST_PORT_UNREACHABLE;
                        break;
                    case ICMP_UNREACH_PROTOCOL:
                        ier->Status=IP_DEST_PROT_UNREACHABLE;
                        break;
                    case ICMP_UNREACH_SRCFAIL:
                        ier->Status=IP_BAD_ROUTE;
                        break;
                    default:
                        ier->Status=IP_DEST_NET_UNREACHABLE;
                    }
                    break;
                case ICMP_TIMXCEED:
                    if (icmp_header->icmp_code==ICMP_TIMXCEED_REASS)
                        ier->Status=IP_TTL_EXPIRED_REASSEM;
                    else
                        ier->Status=IP_TTL_EXPIRED_TRANSIT;
                    break;
                case ICMP_PARAMPROB:
                    ier->Status=IP_PARAM_PROBLEM;
                    break;
                case ICMP_SOURCEQUENCH:
                    ier->Status=IP_SOURCE_QUENCH;
                    break;
                }
#if defined(__linux__)
                if (!unprivileged && ier->Status!=IP_REQ_TIMED_OUT) {
#else
                if (ier->Status!=IP_REQ_TIMED_OUT) {
#endif
                    struct ip* rep_ip_header;
                    struct icmp* rep_icmp_header;
                    /* The ICMP header size of all the packets we accept is the same */
                    rep_ip_header=(struct ip*)(((char*)icmp_header)+ICMP_MINLEN);
                    rep_icmp_header=(struct icmp*)(((char*)rep_ip_header)+(rep_ip_header->ip_hl << 2));

		    /* Make sure that this is really a reply to our packet */
                    if (ip_header_len+ICMP_MINLEN+(rep_ip_header->ip_hl << 2)+ICMP_MINLEN>ip_header->ip_len) {
			ier->Status=IP_REQ_TIMED_OUT;
                    } else if ((rep_icmp_header->icmp_type!=ICMP_ECHO) ||
                        (rep_icmp_header->icmp_code!=0) ||
                        (rep_icmp_header->icmp_id!=id) ||
                        /* windows doesn't check this checksum, else tracert */
                        /* behind a Linux 2.2 masquerading firewall would fail*/
                        /* (rep_icmp_header->icmp_cksum!=cksum) || */
                        (rep_icmp_header->icmp_seq!=seq)) {
                        /* This was not a reply to one of our packets after all */
                        TRACE("skipping type,code=%d,%d id,seq=%d,%d cksum=%d\n",
                            rep_icmp_header->icmp_type,rep_icmp_header->icmp_code,
                            rep_icmp_header->icmp_id,rep_icmp_header->icmp_seq,
                            rep_icmp_header->icmp_cksum);
                        TRACE("expected type,code=8,0 id,seq=%d,%d cksum=%d\n",
                            id,seq,
                            cksum);
			ier->Status=IP_REQ_TIMED_OUT;
		    }
                }
	    }
	}

        if (ier->Status==IP_REQ_TIMED_OUT) {
            /* This packet was not for us.
             * Decrease the timeout so that we don't enter an endless loop even
             * if we get flooded with ICMP packets that are not for us.
             */
            DWORD t = (recv_time - send_time);
            if (timeout > t) timeout -= t;
            else             timeout = 0;
            continue;
        } else {
            /* Check free space, should be large enough for an ICMP_ECHO_REPLY and remainning icmp data */
            if (endbuf-(char *)ier < sizeof(struct icmp_echo_reply)+(res-ip_header_len-ICMP_MINLEN)) {
                res=ier-(ICMP_ECHO_REPLY *)reply_buf;
                SetLastError(IP_GENERAL_FAILURE);
                goto done;
            }
            /* This is a reply to our packet */
            memcpy(&ier->Address,&ip_header->ip_src,sizeof(IPAddr));
            /* Status is already set */
            ier->RoundTripTime= recv_time - send_time;
            ier->DataSize=res-ip_header_len-ICMP_MINLEN;
            ier->Reserved=0;
            ier->Data=endbuf-ier->DataSize;
            memcpy(ier->Data, ((char *)ip_header)+ip_header_len+ICMP_MINLEN, ier->DataSize);
            ier->Options.Ttl=ip_header->ip_ttl;
            ier->Options.Tos=ip_header->ip_tos;
            ier->Options.Flags=ip_header->ip_off >> 13;
            ier->Options.OptionsSize=ip_header_len-sizeof(struct ip);
            if (ier->Options.OptionsSize!=0) {
                ier->Options.OptionsData=(unsigned char *) ier->Data-ier->Options.OptionsSize;
                /* FIXME: We are supposed to rearrange the option's 'source route' data */
                memcpy(ier->Options.OptionsData, ((char *)ip_header)+ip_header_len, ier->Options.OptionsSize);
                endbuf=(char*)ier->Options.OptionsData;
            } else {
                ier->Options.OptionsData=NULL;
                endbuf=ier->Data;
            }

            /* Prepare for the next packet */
            ier++;

            /* Check out whether there is more but don't wait this time */
            timeout=0;
        }
    }
    res=ier-(ICMP_ECHO_REPLY*)reply_buf;
    if (res==0)
        SetLastError(IP_REQ_TIMED_OUT);
done:
    if (res)
    {
        /* Move the data so there's no gap between it and the ICMP_ECHO_REPLY array */
        DWORD gap_size = endbuf - (char*)ier;

        if (gap_size)
        {
            memmove(ier, endbuf, ((char*)reply_buf + reply_size) - endbuf);

            /* Fix the pointers */
            while (ier-- != reply_buf)
            {
                ier->Data = (char*)ier->Data - gap_size;
                if (ier->Options.OptionsData)
                    ier->Options.OptionsData -= gap_size;
            }

            /* According to MSDN, the reply buffer needs to hold space for a IO_STATUS_BLOCK,
               found at the very end of the reply. This is confirmed on Windows XP, but Vista
               and later do not store it anywhere and in fact don't even require it at all.

               However, in case old apps analyze this IO_STATUS_BLOCK and expect it, we mimic
               it and write it out if there's enough space available in the buffer. */
            if (gap_size >= sizeof(IO_STATUS_BLOCK))
            {
                IO_STATUS_BLOCK *io = (IO_STATUS_BLOCK*)((char*)reply_buf + reply_size - sizeof(IO_STATUS_BLOCK));

                io->Pointer = NULL;  /* Always NULL or STATUS_SUCCESS */
                io->Information = reply_size - gap_size;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, buffer);
    TRACE("received %d replies\n",res);
    return res;
}



/*
 * Exported Routines.
 */

/***********************************************************************
 *		Icmp6CreateFile (IPHLPAPI.@)
 */
HANDLE WINAPI Icmp6CreateFile(VOID)
{
    icmp_t* icp;
    BOOL unprivileged = FALSE;

    int sid=socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6);
    if (sid < 0)
    {
        /* Some systems (e.g. Linux 3.0+ and Mac OS X) support
           non-privileged ICMP via SOCK_DGRAM type. */
        sid=socket(AF_INET6,SOCK_DGRAM,IPPROTO_ICMPV6);
        if (sid >= 0)
        {
#if defined(__linux__)
            int on = 1;
            if (setsockopt(sid, SOL_IP, IP_PKTINFO, &on, sizeof(on)))
                ERR("setsockopt IP_PKTINFO failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVERR, &on, sizeof(on)))
                ERR("setsockopt IP_RECVERR failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVOPTS, &on, sizeof(on)))
                ERR("setsockopt IP_RECVOPTS failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVTOS, &on, sizeof(on)))
                ERR("setsockopt IP_RECVTOS failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVTTL, &on, sizeof(on)))
                ERR("setsockopt IP_RECVTTL failed, errno %d\n", errno);
#endif
            unprivileged = TRUE;
        }
    }
    if (sid < 0) {
        ERR_(winediag)("Failed to use ICMPV6 (network ping), this requires special permissions.\n");
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }

    icp=HeapAlloc(GetProcessHeap(), 0, sizeof(*icp));
    if (icp==NULL) {
        close(sid);
        SetLastError(IP_NO_RESOURCES);
        return INVALID_HANDLE_VALUE;
    }
    icp->sid=sid;
    icp->default_opts.OptionsSize=IP_OPTS_UNKNOWN;
    icp->unprivileged = unprivileged;
    return (HANDLE)icp;
}


/***********************************************************************
 *		Icmp6SendEcho2 (IPHLPAPI.@)
 */
DWORD WINAPI Icmp6SendEcho2(
    HANDLE                   IcmpHandle,
    HANDLE                   Event,
    PIO_APC_ROUTINE          ApcRoutine,
    PVOID                    ApcContext,
    struct sockaddr_in6*     SourceAddress,
    struct sockaddr_in6*     DestinationAddress,
    LPVOID                   RequestData,
    WORD                     RequestSize,
    PIP_OPTION_INFORMATION   RequestOptions,
    LPVOID                   ReplyBuffer,
    DWORD                    ReplySize,
    DWORD                    Timeout
    )
{
    FIXME("(%p, %p, %p, %p, %p, %p, %p, %d, %p, %p, %d, %d): stub\n", IcmpHandle, Event,
            ApcRoutine, ApcContext, SourceAddress, DestinationAddress, RequestData,
            RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}


/***********************************************************************
 *		IcmpCreateFile (IPHLPAPI.@)
 */
HANDLE WINAPI IcmpCreateFile(VOID)
{
    static int once;
    icmp_t* icp;
    BOOL unprivileged = FALSE;

    int sid=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if (sid < 0)
    {
        /* Some systems (e.g. Linux 3.0+ and Mac OS X) support
           non-privileged ICMP via SOCK_DGRAM type. */
        sid=socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP);
        if (sid >= 0)
        {
#if defined(__linux__)
            int on = 1;
            if (setsockopt(sid, SOL_IP, IP_PKTINFO, &on, sizeof(on)))
                ERR("setsockopt IP_PKTINFO failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVERR, &on, sizeof(on)))
                ERR("setsockopt IP_RECVERR failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVOPTS, &on, sizeof(on)))
                ERR("setsockopt IP_RECVOPTS failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVTOS, &on, sizeof(on)))
                ERR("setsockopt IP_RECVTOS failed, errno %d\n", errno);
            if (setsockopt(sid, SOL_IP, IP_RECVTTL, &on, sizeof(on)))
                ERR("setsockopt IP_RECVTTL failed, errno %d\n", errno);
#endif
            unprivileged = TRUE;
        }
    }
    if (sid < 0 && !once++) {
        FIXME_(winediag)("Failed to use ICMP (network ping), this requires special permissions.\n");
        FIXME_(winediag)("Falling back to system 'ping' command as a workaround.\n");
    }

    icp=HeapAlloc(GetProcessHeap(), 0, sizeof(*icp));
    if (icp==NULL) {
        if (sid >= 0) close(sid);
        SetLastError(IP_NO_RESOURCES);
        return INVALID_HANDLE_VALUE;
    }
    icp->sid=sid;
    icp->default_opts.OptionsSize=IP_OPTS_UNKNOWN;
    icp->unprivileged = unprivileged;
    return (HANDLE)icp;
}


/***********************************************************************
 *		IcmpCloseHandle (IPHLPAPI.@)
 */
BOOL WINAPI IcmpCloseHandle(HANDLE  IcmpHandle)
{
    icmp_t* icp=(icmp_t*)IcmpHandle;
    if (IcmpHandle==INVALID_HANDLE_VALUE) {
        /* FIXME: in fact win98 seems to ignore the handle value !!! */
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (icp->sid >= 0) close(icp->sid);
    HeapFree(GetProcessHeap (), 0, icp);
    return TRUE;
}

static DWORD system_icmp(
    IPAddr                   DestinationAddress,
    LPVOID                   RequestData,
    WORD                     RequestSize,
    PIP_OPTION_INFORMATION   RequestOptions,
    LPVOID                   ReplyBuffer,
    DWORD                    ReplySize,
    DWORD                    Timeout
    )
{
#ifdef HAVE_FORK
    ICMP_ECHO_REPLY *reply = ReplyBuffer;
    char ntoa_buffer[16]; /* 4*3 digits + 3 '.' + 1 '\0' */
    char size_buffer[6];  /* 5 digits + '\0' */
    char tos_buffer[4];   /* 3 digits + '\0' */
    char ttl_buffer[4];   /* 3 digits + '\0' */
    char time_buffer[11]; /* 10 digits + '\0' */
    int i, pos, res, status, argc;
    const char *argv[20];
    struct in_addr addr;
    int pipe_out[2];
    pid_t pid, wpid;
    char *ptr, *eol;
    char buf[127];

    /* Assemble the ping commandline */
    argc = 0;
    argv[argc++] = "ping";
    argv[argc++] = "-c";    /* only send a single ping */
    argv[argc++] = "1";
    argv[argc++] = "-n";    /* numeric output only */
    argv[argc++] = "-s";    /* request size */
    sprintf(size_buffer, "%u", (RequestSize >= 16) ? RequestSize : 16);
    argv[argc++] = size_buffer;
    argv[argc++] = "-W";    /* timeout */
#ifdef __linux__
    /* The linux 'ping' utlity expects a time in seconds */
    Timeout = (Timeout + 999) / 1000;
#endif
    sprintf(time_buffer, "%u", Timeout);
    argv[argc++] = time_buffer;

    if (RequestOptions)
    {
    #ifdef __linux__
        argv[argc++] = "-Q";    /* tos option */
    #else
        argv[argc++] = "-z";    /* tos option */
    #endif
        sprintf(tos_buffer, "%u", RequestOptions->Tos);
        argv[argc++] = tos_buffer;
    #ifdef __linux__
        /* TTL can only be specified for multicast addresses on FreeBSD/MacOS */
        argv[argc++] = "-t";    /* ttl option */
        sprintf(ttl_buffer, "%u", RequestOptions->Ttl);
        argv[argc++] = ttl_buffer;
    #endif
    }

    addr.s_addr = DestinationAddress;
    if (!(ptr = inet_ntoa(addr)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    strcpy(ntoa_buffer, ptr);
    argv[argc++] = ntoa_buffer;
    argv[argc] = NULL;

    /* Dump commandline for debugging purposes */
    TRACE("Ping commandline: ");
    for (i = 0; i < argc; i++)
    {
        TRACE("%s ", debugstr_a(argv[i]));
    }
    TRACE("\n");

    /* Prefill the reply struct with fallback values */
    memset(reply, 0, sizeof(*reply));
    reply->Address       = DestinationAddress;
    reply->RoundTripTime = 40;
    reply->Options.Ttl   = 120;

    /* Create communication pipes */
#ifdef HAVE_PIPE2
    if (pipe2(pipe_out, O_CLOEXEC) < 0)
#endif
    {
        if (pipe(pipe_out) < 0)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return 0;
        }
        fcntl(pipe_out[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipe_out[1], F_SETFD, FD_CLOEXEC);
    }

    /* Fork child process */
    pid = fork();
    if (pid == -1)
    {
        close(pipe_out[0]);
        close(pipe_out[1]);
        SetLastError(ERROR_OUTOFMEMORY);
        return 0;
    }

    /* Child process */
    if (pid == 0)
    {
        static char lang_env[] = "LANG=C";

        dup2(pipe_out[1], 1);
        close(pipe_out[0]);
        close(pipe_out[1]);
        close(0);
        close(2);

        putenv(lang_env);
        execvp(argv[0], (char **)argv);
        _exit(1);
    }

    close(pipe_out[1]);

    /* Wait for child and read output */
    pos = 0;
    do
    {
        if (pos >= sizeof(buf) - 1)
        {
            ERR("line too long, dropping buffer\n");
            pos = 0;
        }

        /* read next block */
        do
        {
            res = read(pipe_out[0], &buf[pos], (sizeof(buf) - 1) - pos);
        }
        while (res < 0 && errno == EINTR);
        if (res < 0)
        {
            ERR("read failed: %s\n", strerror(errno));
            break;
        }

        pos += res;
        while (pos)
        {
            eol = memchr(buf, '\n', pos);
            if (!eol) break;
            *eol = 0;

            TRACE("Received line: %s\n", debugstr_a(buf));

            /* Interpret address */
            if ((ptr = strstr(buf, "from ")))
            {
                int a, b, c, d;
                if (sscanf(ptr + 5, "%u.%u.%u.%u", &a, &b, &c, &d) >= 4)
                {
                    reply->Address = a | (b << 8) | (c << 16) | (d << 24);
                    addr.s_addr = reply->Address;
                    TRACE("Got address %s\n", inet_ntoa(addr));
                }
            }

            /* Interpret ttl */
            if ((ptr = strstr(buf, "ttl=")))
            {
                int val;
                if (sscanf(ptr + 4, "%u", &val) >= 1)
                {
                    reply->Options.Ttl = val;
                    TRACE("Got ttl %u\n", val);
                }
            }

            /* Interpret time */
            if ((ptr = strstr(buf, "time=")))
            {
                float val;
                if (sscanf(ptr + 5, "%f", &val) >= 1)
                {
                    reply->RoundTripTime = (unsigned int)(val + 0.5);
                    TRACE("Got rtt = %u\n", reply->RoundTripTime);
                }
            }

            memmove(buf, eol + 1, pos - (eol + 1 - buf));
            pos -= (eol + 1 - buf);
        }
    }
    while (res > 0);
    close(pipe_out[0]);

    /* reap the child process */
    do
    {
        wpid = waitpid(pid, &status, 0);
    }
    while (wpid < 0 && errno == EINTR);

    /* fill out remaining struct fields */
    if (wpid >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
    {
        if (ReplySize < RequestSize + sizeof(*reply))
        {
            reply->Status   = IP_BUF_TOO_SMALL;
            reply->DataSize = 0;
            reply->Data     = NULL;
        }
        else
        {
            reply->Status   = 0;
            reply->DataSize = RequestSize;
            reply->Data     = (char *)reply + sizeof(*reply);
            memcpy(reply->Data, RequestData, RequestSize);
        }
        return 1;
    }

    SetLastError(IP_REQ_TIMED_OUT);
    return 0;
#else
    ERR("no fork support on this platform\n");
    SetLastError(ERROR_NOT_SUPPORTED);
    return 0;
#endif
}

/***********************************************************************
 *		IcmpSendEcho (IPHLPAPI.@)
 */
DWORD WINAPI IcmpSendEcho(
    HANDLE                   IcmpHandle,
    IPAddr                   DestinationAddress,
    LPVOID                   RequestData,
    WORD                     RequestSize,
    PIP_OPTION_INFORMATION   RequestOptions,
    LPVOID                   ReplyBuffer,
    DWORD                    ReplySize,
    DWORD                    Timeout
    )
{
    return IcmpSendEcho2Ex(IcmpHandle, NULL, NULL, NULL, 0, DestinationAddress,
            RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
}

/***********************************************************************
 *		IcmpSendEcho2 (IPHLPAPI.@)
 */
DWORD WINAPI IcmpSendEcho2(
    HANDLE                   IcmpHandle,
    HANDLE                   Event,
    PIO_APC_ROUTINE          ApcRoutine,
    PVOID                    ApcContext,
    IPAddr                   DestinationAddress,
    LPVOID                   RequestData,
    WORD                     RequestSize,
    PIP_OPTION_INFORMATION   RequestOptions,
    LPVOID                   ReplyBuffer,
    DWORD                    ReplySize,
    DWORD                    Timeout
    )
{
    return IcmpSendEcho2Ex(IcmpHandle, Event, ApcRoutine, ApcContext, 0,
            DestinationAddress, RequestData, RequestSize, RequestOptions,
            ReplyBuffer, ReplySize, Timeout);
}

/***********************************************************************
 *		IcmpSendEcho2Ex (IPHLPAPI.@)
 */
DWORD WINAPI IcmpSendEcho2Ex(
    HANDLE                   IcmpHandle,
    HANDLE                   Event,
    PIO_APC_ROUTINE          ApcRoutine,
    PVOID                    ApcContext,
    IPAddr                   SourceAddress,
    IPAddr                   DestinationAddress,
    LPVOID                   RequestData,
    WORD                     RequestSize,
    PIP_OPTION_INFORMATION   RequestOptions,
    LPVOID                   ReplyBuffer,
    DWORD                    ReplySize,
    DWORD                    Timeout
    )
{
    icmp_t* icp=(icmp_t*)IcmpHandle;
    struct icmp* icmp_header;
    struct sockaddr_in addr;
    unsigned short id, seq;
    unsigned char *buffer;
    int reqsize, repsize;
    DWORD send_time;

    TRACE("(%p, %p, %p, %p, %08x, %08x, %p, %d, %p, %p, %d, %d)\n", IcmpHandle,
            Event, ApcRoutine, ApcContext, SourceAddress, DestinationAddress, RequestData,
            RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);

    if (IcmpHandle==INVALID_HANDLE_VALUE) {
        /* FIXME: in fact win98 seems to ignore the handle value !!! */
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (!ReplyBuffer||!ReplySize) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (ReplySize<sizeof(ICMP_ECHO_REPLY)) {
        SetLastError(IP_BUF_TOO_SMALL);
        return 0;
    }
    /* check the request size against SO_MAX_MSG_SIZE using getsockopt */

    if (!DestinationAddress) {
        SetLastError(ERROR_INVALID_NETNAME);
        return 0;
    }

    if (Event)
    {
        FIXME("unsupported for events\n");
        return 0;
    }
    if (ApcRoutine)
    {
        FIXME("unsupported for APCs\n");
        return 0;
    }
    if (SourceAddress)
    {
        FIXME("unsupported for source addresses\n");
        return 0;
    }

    if (icp->sid < 0) {
        WARN("using system ping command since SOCK_RAW was not supported.\n");
        return system_icmp(DestinationAddress, RequestData, RequestSize,
                           RequestOptions, ReplyBuffer, ReplySize, Timeout);
    }

    /* Prepare the request */
    id=getpid() & 0xFFFF;
    seq=InterlockedIncrement(&icmp_sequence) & 0xFFFF;

    reqsize=ICMP_MINLEN+RequestSize;
    /* max ip header + max icmp header and error data + reply size(max 65535 on Windows) */
    /* FIXME: request size of 65535 is not supported yet because max buffer size of raw socket on linux is 32767 */
    repsize = MAXIPLEN + MAXICMPLEN + min( 65535, ReplySize );
    buffer = HeapAlloc(GetProcessHeap(), 0, max( repsize, reqsize ));
    if (buffer == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return 0;
    }

    icmp_header=(struct icmp*)buffer;
    icmp_header->icmp_type=ICMP_ECHO;
    icmp_header->icmp_code=0;
    icmp_header->icmp_cksum=0;
    icmp_header->icmp_id=id;
    icmp_header->icmp_seq=seq;
    memcpy(buffer+ICMP_MINLEN, RequestData, RequestSize);
    icmp_header->icmp_cksum=in_cksum((u_short*)buffer,reqsize);

    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=DestinationAddress;
    addr.sin_port=0;

    if (RequestOptions!=NULL) {
        int val;
        if (icp->default_opts.OptionsSize==IP_OPTS_UNKNOWN) {
            socklen_t len;
            /* Before we mess with the options, get the default values */
            len=sizeof(val);
            getsockopt(icp->sid,IPPROTO_IP,IP_TTL,(char *)&val,&len);
            icp->default_opts.Ttl=val;

            len=sizeof(val);
            getsockopt(icp->sid,IPPROTO_IP,IP_TOS,(char *)&val,&len);
            icp->default_opts.Tos=val;
            /* FIXME: missing: handling of IP 'flags', and all the other options */
        }

        val=RequestOptions->Ttl;
        setsockopt(icp->sid,IPPROTO_IP,IP_TTL,(char *)&val,sizeof(val));
        val=RequestOptions->Tos;
        setsockopt(icp->sid,IPPROTO_IP,IP_TOS,(char *)&val,sizeof(val));
        /* FIXME:  missing: handling of IP 'flags', and all the other options */

        icp->default_opts.OptionsSize=IP_OPTS_CUSTOM;
    } else if (icp->default_opts.OptionsSize==IP_OPTS_CUSTOM) {
        int val;

        /* Restore the default options */
        val=icp->default_opts.Ttl;
        setsockopt(icp->sid,IPPROTO_IP,IP_TTL,(char *)&val,sizeof(val));
        val=icp->default_opts.Tos;
        setsockopt(icp->sid,IPPROTO_IP,IP_TOS,(char *)&val,sizeof(val));
        /* FIXME: missing: handling of IP 'flags', and all the other options */

        icp->default_opts.OptionsSize=IP_OPTS_DEFAULT;
    }

    /* Send the packet */
    TRACE("Sending %d bytes (RequestSize=%d) to %s\n", reqsize, RequestSize, inet_ntoa(addr.sin_addr));
#if 0
    if (TRACE_ON(icmp)){
        int i;
        printf("Output buffer:\n");
        for (i=0;i<reqsize;i++)
            printf("%2x,", buffer[i]);
        printf("\n");
    }
#endif

    send_time = GetTickCount();
    if (sendto(icp->sid, buffer, reqsize, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        if (errno==EMSGSIZE)
            SetLastError(IP_PACKET_TOO_BIG);
        else {
            switch (errno) {
            case ENETUNREACH:
                SetLastError(IP_DEST_NET_UNREACHABLE);
                break;
            case EHOSTUNREACH:
                SetLastError(IP_DEST_HOST_UNREACHABLE);
                break;
            default:
                TRACE("unknown error: errno=%d\n",errno);
                SetLastError(IP_GENERAL_FAILURE);
            }
        }
        HeapFree(GetProcessHeap(), 0, buffer);
        return 0;
    }

    return icmp_get_reply(icp->sid, buffer, send_time, ReplyBuffer, ReplySize, Timeout, icp->unprivileged);
}

/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
