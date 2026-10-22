"""First-party absolute timer functions embedded unchanged in the external client.

Times are CLOCK_BOOTTIME nanoseconds. Tests compile this very C implementation;
this module is not a Python simulation of the client timer.
"""
C_TIMERS = r'''
#include <stdint.h>
#include <stddef.h>
#define UL_SECOND 1000000000ULL
struct ul_timers {
    uint64_t origin, t1, t2, expiry, next;
    unsigned active, phase, attempts;
};
static int ul_read(const unsigned char *p, size_t n, uint32_t *out) {
    if (!p || n != 4) return 0;
    *out = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
    return 1;
}
static int ul_schedule(struct ul_timers *s, uint64_t origin, uint64_t received,
    const unsigned char *lease, size_t ln, const unsigned char *a, size_t an,
    const unsigned char *b, size_t bn) {
    uint32_t seconds, v;
    uint64_t duration, t1, t2;
    struct ul_timers candidate;
    if (!ul_read(lease,ln,&seconds) || seconds<1 || seconds>86400) return 0;
    duration=(uint64_t)seconds*UL_SECOND;
    t1=duration/2; t2=duration*7/8;
    if (a) { if (!ul_read(a,an,&v)) return 0; t1=(uint64_t)v*UL_SECOND; }
    if (b) { if (!ul_read(b,bn,&v)) return 0; t2=(uint64_t)v*UL_SECOND; }
    if (!(0<t1 && t1<t2 && t2<duration) || origin>UINT64_MAX-duration) return 0;
    if (received<origin || received>=origin+duration) return 0;
    candidate.origin=origin; candidate.t1=origin+t1; candidate.t2=origin+t2;
    candidate.expiry=origin+duration; candidate.next=candidate.t1;
    candidate.active=1; candidate.phase=0; candidate.attempts=0;
    *s=candidate; return 1;
}
/* 0 wait, 1 unicast renew, 2 broadcast rebind, 3 expire. */
static unsigned ul_action(struct ul_timers *s, uint64_t now) {
    unsigned phase;
    if (now>=s->expiry) return 3;
    phase=now>=s->t2?2:(now>=s->t1?1:0);
    if (phase>s->phase) { s->phase=phase; s->next=now; s->attempts=0; }
    return phase && now>=s->next?phase:0;
}
static void ul_sent(struct ul_timers *s, uint64_t now) {
    uint64_t boundary=s->phase==1?s->t2:s->expiry, interval;
    if (s->attempts<UINT32_MAX) s->attempts++;
    if (now>=boundary) {s->next=boundary;return;}
    interval=(boundary-now)/2;
    if (interval<60*UL_SECOND) interval=60*UL_SECOND;
    s->next=interval>=boundary-now?boundary:now+interval;
}
static int ul_wait_ms(const struct ul_timers *s, uint64_t now) {
    uint64_t boundary=s->phase==0?s->t1:(s->phase==1?s->t2:s->expiry);
    uint64_t next=s->next<boundary?s->next:boundary;
    if (now>=next) return 0;
    return (int)((next-now+999999)/1000000);
}
'''

C_LINUX = r'''
#include <time.h>
static uint64_t ul_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME,&t)) bb_simple_perror_msg_and_die("CLOCK_BOOTTIME");
    return (uint64_t)t.tv_sec*UL_SECOND+t.tv_nsec;
}
static void ul_log(const char *event, const struct ul_timers *s) {
    bb_info_msg("uplinkstead_timer if=%s pid=%u event=%s xid=%u origin=%llu t1=%llu t2=%llu expiry=%llu at=%llu attempts=%u",
        client_data.interface,(unsigned)getpid(),event,(unsigned)ntohl(client_data.xid),
        (unsigned long long)s->origin,(unsigned long long)s->t1,(unsigned long long)s->t2,
        (unsigned long long)s->expiry,(unsigned long long)ul_now(),s->attempts);
    fflush(NULL);
}
static void ul_export(uint64_t origin) {
    char a[32],b[32];
    snprintf(a,sizeof(a),"%llu",(unsigned long long)origin);
    snprintf(b,sizeof(b),"%u",(unsigned)ntohl(client_data.xid));
    if (setenv("UPLINKSTEAD_CLIENT_ORIGIN_NS",a,1) || setenv("UPLINKSTEAD_CLIENT_XID",b,1))
        bb_simple_perror_msg_and_die("timer environment");
}
'''

LOOP = r'''
        if (ul.active) {
            uint64_t current=ul_now();
            unsigned action=ul_action(&ul,current);
            if (action==3) {
                ul_log("expire",&ul); ul.active=0;
                change_listen_mode(LISTEN_NONE);
                d4_run_script_deconfig();
                client_data.state=INIT_SELECTING; client_data.first_secs=0;
                packet_num=0; timeout=0; continue;
            }
            if (action==1 || action==2) {
                int target=action==1?RENEWING:REBINDING;
                if (client_data.state!=target) {
                    client_data.xid=random_xid(); client_data.first_secs=0;
                    /* Capture may quarantine the old local address before the hook.
                     * Receive DHCP at L2 so that cannot discard its own ACK. */
                    change_listen_mode(LISTEN_RAW);
                    client_data.state=target;
                }
                if (!ul_have_request || ul_request_xid!=client_data.xid) {
                    ul_request_origin=ul_now(); ul_request_xid=client_data.xid; ul_have_request=1;
                }
                send_renew(action==1?server_id:0,requested_ip);
                ul_sent(&ul,ul_now()); ul_log(action==1?"renew":"rebind",&ul); continue;
            }
        }
'''

ACK = r'''
                {
                    struct ul_timers candidate;
                    uint8_t *l=udhcp_get_option(&packet,51);
                    uint8_t *a=udhcp_get_option(&packet,58);
                    uint8_t *b=udhcp_get_option(&packet,59);
                    if (!ul_have_request || ul_request_xid!=client_data.xid ||
                        !ul_schedule(&candidate,ul_request_origin,ul_now(),l,l?l[-1]:0,a,a?a[-1]:0,b,b?b[-1]:0)) {
                        bb_simple_info_msg("invalid/expired lease timers; ACK ignored"); ul_log("reject",&ul);
                        continue;
                    }
                    ul=candidate;
                    {
                        uint8_t *server=udhcp_get_option32(&packet,DHCP_SERVER_ID);
                        if (server) move_from_unaligned32(server_id,server);
                    }
                }
'''


def replace_once(text, old, new):
    if text.count(old)!=1:raise ValueError('Unexpected upstream timer boundary: '+old[:60])
    return text.replace(old,new)


def apply(source):
    source=replace_once(source,'static ALWAYS_INLINE uint32_t random_xid(void)',C_TIMERS+C_LINUX+'\nstatic ALWAYS_INLINE uint32_t random_xid(void)')
    source=replace_once(source,'\tint lease_remaining; /* must be signed */','\tint lease_remaining; /* must be signed */\n    struct ul_timers ul={0};\n    uint64_t ul_request_origin=0;\n    uint32_t ul_request_xid=0;\n    int ul_have_request=0;')
    source=replace_once(source,'\t\tudhcp_sp_fd_set(pfds, client_data.sockfd);',LOOP+'\n\t\tudhcp_sp_fd_set(pfds, client_data.sockfd);')
    source=replace_once(source,'if (timeout > 0) {','if (timeout > 0 || ul.active) {')
    source=replace_once(source,'poll(pfds, 2, timeout * 1000)','poll(pfds, 2, ul.active?ul_wait_ms(&ul,ul_now()):timeout * 1000)')
    source=replace_once(source,'\t\tif (retval == 0) {','\t\tif (ul.active && (retval==0 || ul_now()>=ul.expiry)) continue;\n\t\tif (retval == 0) {')
    source=replace_once(source,'\t\t\t\tsend_select(server_id, requested_ip);','''                if (!ul_have_request || ul_request_xid!=client_data.xid) {
                    ul_request_origin=ul_now(); ul_request_xid=client_data.xid; ul_have_request=1;
                }
                send_select(server_id, requested_ip);''')
    source=replace_once(source,'\t\tcase SIGUSR1:','''        case SIGUSR1:
            if (ul.active) {
                if (ul.phase==0) ul.t1=ul_now();
                ul.next=ul_now(); continue;
            }''')
    source=replace_once(source,'\t\tcase SIGUSR2:\n','\t\tcase SIGUSR2:\n            ul.active=0;\n')
    source=replace_once(source,'\t\t\tif (*message == DHCPACK) {','\t\t\tif (*message == DHCPACK) {\n'+ACK)
    source=replace_once(source,'\t\t\t\t/* enter bound state */','\t\t\t\t/* enter bound state */\n                ul_export(ul.origin); ul_log("ack",&ul);')
    source=replace_once(source,'\t\t\t\ttimeout = (unsigned)lease_remaining / 2;','\t\t\t\ttimeout = 0; /* absolute scheduler owns all live lease timers */')
    source=replace_once(source,'\t\t\t\tclient_data.state = BOUND;','\t\t\t\tclient_data.state = BOUND; ul_log("bound",&ul);')
    source=replace_once(source,'\t\t\t\tclient_data.xid = random_xid(); /* Uplinkstead transaction boundary */','\t\t\t\t/* xid advances on the next absolute timer phase transition */')
    source=replace_once(source,'\t\t\t\tbb_info_msg("received %s", "DHCP NAK");','\t\t\t\tbb_info_msg("received %s", "DHCP NAK");\n                ul.active=0;')
    return source
