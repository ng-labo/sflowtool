#ifndef LIBFILTER_H
#define LIBFILTER_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <regex.h>

//#include "sflow.h"

static const char *proto_alias[] = {
           "icmp",    "1",
           "tcp",     "6",
           "udp",    "17",
           "icmp6",  "58" };

#define MAX_COND_PROTO 16
#define MAX_COND_IPADDR 64
#define MAX_COND_IP_SET 16

#define MAX_COND_AGENT 64
#define MAX_COND_AGENT_SET 1


static inline void MASK_IPV4(uint8_t *p, const int masklen){
    for(int i=0;i<(32-masklen);i++){
        p[3 - (i >> 3)] &= ~(1<<(i % 8));
    }
}

static inline void MASK_IPV6(uint8_t *p, const int masklen){
    for(int i=0;i<(128-masklen);i++){
        p[15 - (i >> 3)] &= ~(1<<(i % 8));
    }
}

static inline int IPV6ADDRCMP(const uint32_t *s1, const uint32_t *s2){
    for(int i=0;i<4;i++) if (*s1++!=*s2++) return 1;
    return 0;
}

typedef struct {
    uint8_t addr[16];
    uint32_t mask;
    uint32_t ver;
} IPADDR;

typedef struct {
    int count;
    int ipv4_count;
    int ipv6_count;
    int ipaddr_count;
    IPADDR *ipaddr;
    int proto_count;
    int *proto;
} COND_IP;

typedef struct {
    int agent_count;
    uint32_t *agent; // allocating 3 items of tupple, last one shall (0, 0, 0)
} COND_AGENT;

static COND_IP *cond_ip_list[MAX_COND_IP_SET];
static COND_AGENT *cond_agent_list[MAX_COND_AGENT_SET];
static int number_of_condip = 0;
static int number_of_condagent = 0;

static void initialize_cond_ip(COND_IP *c) {
    c->count = 0;
    c->ipv4_count = 0;
    c->ipv6_count = 0;
    c->ipaddr_count = 0;
    c->proto_count = 0;
    c->ipaddr = 0;
    c->proto = 0;
}

static void allocate_cond_ip(COND_IP *c) {
    if(c->ipaddr_count>0){
        c->ipaddr = malloc(sizeof(IPADDR) * c->ipaddr_count);
        memset(c->ipaddr, 0, sizeof(IPADDR) * c->ipaddr_count);
    }
    if(c->proto_count>0){
        c->proto = malloc(sizeof(int) * c->proto_count);
        memset(c->proto, 0, sizeof(int) * c->proto_count);
    }
    c->count = 0;
    c->ipv4_count = 0;
    c->ipv6_count = 0;
    c->ipaddr_count = 0;
    c->proto_count = 0;
}

static void initialize_cond_agent(COND_AGENT *c) {
    c->agent_count = 0;
    c->agent = 0;
}

static void allocate_cond_agent(COND_AGENT *c) {
    if(c->agent_count>0){
        c->agent = malloc(sizeof(int) * (c->agent_count + 1) * 3);
        memset(c->agent, 0, sizeof(int) * (c->agent_count + 1) * 3);
    }
    c->agent_count = 0;
}

/*

 */
static int ismatch_condition_proto(SFSample *s, COND_IP *condition) {
    const int proto_count = condition->proto_count;
    if(proto_count==0){
        return 0;
    }

    int nomatch = 1;
    const int* proto = condition->proto;
    for(int i=0;i<proto_count;i++){
        if(s->s.dcd_ipProtocol == proto[i]){
            nomatch = 0;
            break;
        }
    }

    return nomatch;
}

static int ismatch_condition_ipaddr(SFSample *s, COND_IP *condition) {
    const int ipaddr_count = condition->ipaddr_count;
    if(ipaddr_count==0)return 0;

    int nomatch = 1;

    if(s->s.gotIPV4){
        if(condition->ipv4_count>0){
            for(int i=0;i<ipaddr_count;i++){
                if(condition->ipaddr[i].ver!=4)continue;
                const uint32_t faddr = *((uint32_t*) condition->ipaddr[i].addr);
                const uint32_t fmask = condition->ipaddr[i].mask;

                uint32_t masked = s->s.ipsrc.address.ip_v4.addr;
                MASK_IPV4((uint8_t*) &masked, fmask);
                if(masked==faddr){
                    nomatch = 0;
                    break;
                }else{
                    masked = s->s.ipdst.address.ip_v4.addr;
                    MASK_IPV4((uint8_t*) &masked, fmask);
                    if(masked==faddr){
                        nomatch = 0;
                        break;
                    }
                }
            }
        }
        return nomatch;
    }

    if(s->s.gotIPV6){
        if(condition->ipv6_count>0){
            for(int i=0;i<ipaddr_count;i++){
                if(condition->ipaddr[i].ver!=6)continue;
                const uint32_t* faddr = (const uint32_t*) condition->ipaddr[i].addr;
                const uint32_t fmask = condition->ipaddr[i].mask;

                uint8_t* masked = s->s.ipsrc.address.ip_v6.addr;
                MASK_IPV6(masked, fmask);
                if(IPV6ADDRCMP((const uint32_t*) masked, faddr)==0){
                    nomatch = 0;
                    break;
                } else {
                    masked = s->s.ipdst.address.ip_v6.addr;
                    MASK_IPV6(masked, fmask);
                    if(IPV6ADDRCMP((const uint32_t*) masked, faddr)==0){
                        nomatch = 0;
                        break;
                    }
                }
            }
        }
        return nomatch;
    }

    return nomatch; // unreachable
}

/*
  @ret 0 : be enable to print for user(matched with condition or no filters)
  @ret 1 : not matched with condition
 */
static int ismatch_condition(SFSample *s, COND_IP *condition) {
    if(ismatch_condition_proto(s, condition)==0){
        return ismatch_condition_ipaddr(s, condition);
    }
    return 1;
}

static void dump_cond_ip(const int n, const COND_IP *c){
    fprintf(stderr, "number = %d filter.count = %d\n", n, c->count);
    fprintf(stderr, "filters.ipaddr_count = %d(4:%d,6:%d)\n",
        c->ipaddr_count, c->ipv4_count, c->ipv6_count);
    if(c->ipaddr){
        for(int i=0;i<c->ipaddr_count;i++){
            char p[48];
            if(c->ipaddr[i].ver==4){
                inet_ntop(AF_INET, &c->ipaddr[i].addr, p, 47);
            }else{
                inet_ntop(AF_INET6, c->ipaddr[i].addr, p, 47);
            }
            fprintf(stderr, "(%d) %s/%d\n", i, p, c->ipaddr[i].mask);
        }
    }else{
        fprintf(stderr,"not allocated\n");
    }
    fprintf(stderr, "filters.proto_count = %d\n", c->proto_count);
    if(c->proto){
        for(int i=0;i<c->proto_count;i++){
            fprintf(stderr, "(%d) %d\n", i, c->proto[i]);
        }
    }else{
        fprintf(stderr,"not allocated\n");
    }
}

static void dump_cond_agent(const COND_AGENT *c){
    fprintf(stderr, "agent_count = %d\n", c->agent_count);
    if(c->agent){
        for(int i=0;i<=c->agent_count;i++){
            const size_t idx = i * 3;
            char s1[64];
            char s2[64];
            if(agents){
                if(c->agent[idx+1]>0){
                    if(lookup_agentifindex(htonl(c->agent[idx]), c->agent[idx+1], s1, s2)==1){
                        sprintf(s1, "%u", c->agent[idx]);
                        sprintf(s2, "%u", c->agent[idx+1]);
                    }
                }else{
                    if(lookup_agent(htonl(c->agent[idx]), s1)==1){
                        sprintf(s1, "%u", c->agent[idx]);
                    }
                    strcpy(s2, "0");
                }
            }
            fprintf(stderr, "(%d) %u(%s)/%u(%s)/%u\n", i, ntohl(c->agent[idx]), s1, c->agent[idx+1], s2, c->agent[idx+2]);
        }
    }
}

static void _add_cond_agent(COND_AGENT* cond, const uint32_t agent_id, const uint32_t ifind, const uint32_t reserved) {
    if(cond->agent_count<MAX_COND_AGENT){
        if(cond->agent){
            const size_t idx = cond->agent_count * 3;
            cond->agent[idx  ] = agent_id;
            cond->agent[idx+1] = ifind;
            cond->agent[idx+2] = reserved; // reserved for output port index
        }
        cond->agent_count++;
    }else{
    }
}

static void _search_and_add(COND_AGENT* c, const char *name, const regex_t *regex_name){
    for(struct lookup_agent* rp = agents;rp != NULL;rp = rp->next){
        if(strcmp(rp->name, name)==0){
            _add_cond_agent(c, htonl(rp->id), 0, 0);
            if(regex_name==0){
                return;
            }
            continue;
        }
        if(regex_name&&regexec(regex_name, rp->name, 0, NULL, 0)==0){
            _add_cond_agent(c, htonl(rp->id), 0, 0);
        }
    }
}

static void _search_and_add_ifalias(COND_AGENT* c, const char *name, const char *ifalias, const regex_t *regex_name, const regex_t *regex_ifalias){
    for(struct lookup_agent* rp = agents;rp != NULL;rp = rp->next){
        // match to name
        // not match to name and match regex_name
        // empty regex_name
        int e = strcmp(rp->name, name);
        int r = (e!=0&&regex_name)
                    ? regexec(regex_name, rp->name, 0, NULL, 0) : 1;
        if(e==0||r==0||regex_name==0){
            for(struct lookup_ifalias* ip = rp->first; ip != NULL; ip = ip->next){
                // match to ifalias
                // not match to ifalias and match regex_ifalias
                if(strcmp(ip->ifalias, ifalias)==0){
                    _add_cond_agent(c, htonl(rp->id), ip->ifind, 0);
                }else if(regex_ifalias&&regexec(regex_ifalias, ip->ifalias, 0 , NULL, 0)==0){
                    _add_cond_agent(c, htonl(rp->id), ip->ifind, 0);
                }
            }
        }
    }
}

static int parse_cond_agent_impl(const char* arg, COND_AGENT* cond) {
    const char *p = arg;
    while(1){
        if(*p=='\0')break;
        if(*p==','){p++;continue;};
        char buf[128];
        size_t bufidx = 0;
        while(*p!='\0'&&*p!=',') buf[bufidx++] = *p++;
        buf[bufidx] = '\0';
        if(buf[0]=='\0')break;

        char *w[] = { buf, "", "" };
        char *q = buf;
        size_t _i = 1;
        while(*q!='\0'&&_i<3){ // sizeof(w)/sizeof(char*)
            if(*q=='/'){
                *q = 0;
                w[_i++] = q + 1;
            }
            q++;
        }
        // w[0] is empty or exact string or regular expression
        // w[1] is empty or exact string or regular expression
        // w[2] now ignores
        //fprintf(stderr, "[%s][%s][%s]\n", w[0], w[1], w[2]);

        if(w[0][0]=='\0'&&w[1][0]=='\0'){
            fprintf(stderr, "empty anyone in '%s'\n", arg);
            return 1;
        }

        int before_count = cond->agent_count;
        uint32_t agent_id = (uint32_t) atol(w[0]); // agent_id is uint32_t
        while(agent_id==0 && agents){
            // try lookup in lookup_agent ( libifindexlookup.h )
            regex_t regex_name;
            regex_t regex_ifalias;
            int regex_name_initialized = 0;
            int regex_ifalias_initialized = 0;
            if(w[0][0]!='\0'){
                if(regcomp(&regex_name, w[0], 0)==0){
                    regex_name_initialized = 1;
                }else{
                    fprintf(stderr, "failed regcomp(%s)\n", w[0]);
                }
            }
            if(w[1][0]!='\0'){
                if(regcomp(&regex_ifalias, w[1], 0)==0){
                    regex_ifalias_initialized = 1;
                }else{
                    fprintf(stderr, "failed regcomp(%s)\n", w[1]);
                }
            }

            if(w[0][0]!='\0'&&w[1][0]=='\0'){
                regex_t *r1 = (regex_name_initialized==1) ? &regex_name : 0;
                _search_and_add(cond, w[0], r1);
            }
            if(w[1][0]!='\0'){
                regex_t *r1 = (regex_name_initialized==1) ? &regex_name : 0;
                regex_t *r2 = (regex_ifalias_initialized==1) ? &regex_ifalias : 0;
                _search_and_add_ifalias(cond, w[0], w[1], r1, r2);
            }
            if(regex_name_initialized) regfree(&regex_name);
            if(regex_ifalias_initialized) regfree(&regex_ifalias);
            break;
        }
        if(before_count==cond->agent_count){
            fprintf(stderr, "no effective expression '%s/%s/%s'\n", w[0], w[1], w[2]);
            return 2;
        }
    }
    return 0;
}

/*
 just set counts if called before allocate_condition
 set values aif called after allocate_condition
 */
static int parse_cond_ip_impl(const char* arg, COND_IP* cond) {
    const char *p = arg;
    while(1){
        if(*p=='\0')break;
        if(*p==','){p++;continue;};
        char buf[40 + 1 + 3 + 1];
        size_t bufidx = 0;
        while(*p!='\0'&&*p!=',') buf[bufidx++] = *p++;
        buf[bufidx] = '\0';
        if(buf[0]=='\0')break;

        int ip_masklen = -1;
        int ip_ver = -1;

        int before_count = cond->proto_count + cond->ipaddr_count;

        char *q = buf;
        while(*q!='\0'){
            if(*q=='.'){
                ip_masklen = 0;
                ip_ver = 4;
            }
            else if(*q==':'){
                ip_masklen = 0;
                ip_ver = 6;
            }
            else if(ip_masklen==0&&*q=='/'){
                *q = '\0';
                ip_masklen = atoi(q + 1);
                break;
            }
            else if(ip_masklen==0&&*q=='/'){
                *q = '\0';
                ip_masklen = atoi(q +1 );
                break;
            }
            q++;
        }

        if(ip_ver==4){
            uint32_t addr;
            int rc = inet_pton(AF_INET, buf, (void*) &addr);
            if(rc==1){
                if((ip_masklen==0&&addr>0)||ip_masklen>32){
                    ip_masklen=32;
                }
                MASK_IPV4((uint8_t*) &addr, ip_masklen);
                if(cond->ipaddr_count<MAX_COND_IPADDR){
                    if(cond->ipaddr>0){
                        *((uint32_t*)cond->ipaddr[cond->ipaddr_count].addr) = addr;
                        cond->ipaddr[cond->ipaddr_count].mask = ip_masklen;
                        cond->ipaddr[cond->ipaddr_count].ver = 4;
                    }
                    cond->ipaddr_count++;
                    cond->ipv4_count++;
                }else{
                    fprintf(stderr, "%s is not set(over number of limitation)\n", buf);
                }
            }
        }

        if(ip_ver==6){
            uint8_t addr[16];
            int rc = inet_pton(AF_INET6, buf, (void*) addr);
            if(rc==1){
                int biton = 0;
                for(int i=0;i<16;i++) if (addr[i]>0) { biton = 1;break; }
                if((ip_masklen==0&&biton==1)||ip_masklen>128){
                    ip_masklen=128;
                }
                MASK_IPV6((uint8_t*) &addr, ip_masklen);
                if(cond->ipaddr_count<MAX_COND_IPADDR){
                    if(cond->ipaddr>0){
                        memcpy(cond->ipaddr[cond->ipaddr_count].addr, addr, 16);
                        cond->ipaddr[cond->ipaddr_count].mask = ip_masklen;
                        cond->ipaddr[cond->ipaddr_count].ver = 6;
                    }
                    cond->ipaddr_count++;
                    cond->ipv6_count++;
                }else{
                    fprintf(stderr, "%s is not set(over number of limitation)\n", buf);
                }
            }
        }

        int ipprotocol = -1;
        if(ip_ver==-1){
            ipprotocol = atoi(buf);
            if(ipprotocol==0){
                for(int i=0;i<sizeof(proto_alias)/sizeof(const char*);i+=2){
                    const char *name = proto_alias[i];
                    int value = atoi(proto_alias[i+1]);
                    if(strcmp(name, buf)==0){
                        ipprotocol = value;
                    }
                }
            }
        }

        if(ipprotocol>0){
            if(cond->proto_count<MAX_COND_PROTO){
                if(cond->proto>0){
                    cond->proto[cond->proto_count] = ipprotocol;
                }
                cond->proto_count++;
            }
        }

        if(before_count==cond->proto_count + cond->ipaddr_count){
            fprintf(stderr, "invalid param '%s'\n", buf);
            return 1;
        }
    }
    cond->count = cond->proto_count + cond->ipaddr_count;
    assert(cond->ipv4_count+cond->ipv6_count==cond->ipaddr_count);
    return 0;
}

/*
 parse condition passed by argument.
 input form shall following,
 - separated by ',',
 - each element shall be IPv4-address , IPv6-address, or IPProtocol

 x.x.x.x/yy
 or
 xx:xx::xx/yy
 or
 number(defined some alias , 'tcp','udp','icmp','icmp6','gre')

 given string for IP-address  shall separate by '/'.
 first string is IP that inet_pton() can parse.
 second string is masklen that atoi() can parse.

 @param[in] arg passed string
 @ret pointer to filter data(maybe not referenced)
 */
int parse_cond_ip(const char* arg) {
    if(number_of_condip==MAX_COND_IP_SET){
        fprintf(stderr, "too many -T argument\n");
        return 1;
    }
    cond_ip_list[number_of_condip] = malloc(sizeof(COND_IP));
    COND_IP *cond_ip = cond_ip_list[number_of_condip];
    initialize_cond_ip(cond_ip);
    // dump_cond_ip(number_of_condip, cond_ip);
    if(parse_cond_ip_impl(arg, cond_ip)!=0){
        return 2;
    }
    if(cond_ip->count==0){
        free(cond_ip_list[number_of_condip]);
        return 0;
    }
    allocate_cond_ip(cond_ip);
    parse_cond_ip_impl(arg, cond_ip);

    dump_cond_ip(number_of_condip, cond_ip);
    number_of_condip++;
    return 0;
}

const void *parse_cond_agent(const char* arg) {
    if(number_of_condagent==MAX_COND_AGENT_SET){
        return arg;
    }
    cond_agent_list[number_of_condagent] = malloc(sizeof(COND_AGENT));
    COND_AGENT *cond_agent = cond_agent_list[number_of_condagent];
    initialize_cond_agent(cond_agent);
    // dump_cond_agent(cond_agent);
    if(parse_cond_agent_impl(arg, cond_agent)){
        return 0;
    }
    if(cond_agent->agent_count==0){
        free(cond_agent_list[number_of_condagent]);
        return arg;
    }
    allocate_cond_agent(cond_agent);
    parse_cond_agent_impl(arg, cond_agent);

    dump_cond_agent(cond_agent);
    number_of_condagent++;
    return arg;
}

int ismatch_conditions(SFSample *s) {
    if(number_of_condagent==0&&number_of_condip==0)return 0;

    int ok_agent = 1;
    if(number_of_condagent==1){
        ok_agent = 0;
        const uint32_t aid = s->agent_addr.address.ip_v4.addr;
        const uint32_t inp = s->s.inputPort;
        for(uint32_t *p = cond_agent_list[0]->agent;*p>0;p+=3) {
            if(aid==*p){
                if(*(p+1)==0 || *(p+1)==inp) {
                    ok_agent = 1;
                    break;
                }
            }
        }
    }
    if(ok_agent==0) return 1;
    if(number_of_condip==0) return 0;

    for(int i=0;i<number_of_condip;i++){
        if(ismatch_condition(s, cond_ip_list[i])==0) return 0;
    }
    return 1;
}

#endif // LIBFILTER_H
