#ifndef LIBIFINDEXLOOKUP
#define LIBIFINDEXLOOKUP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>

struct lookup_ifalias {
    unsigned int ifind;
    char ifalias[64];
    struct lookup_ifalias *next;
};

struct lookup_agent {
    unsigned int id;
    int num_ifind;
    char name[20];
    struct lookup_ifalias *first;
    struct lookup_agent *next;
};

static struct lookup_agent* agents = NULL;
static struct lookup_agent* standbytbl = NULL;
static time_t lookup_agent_file_ts = 0; // last modified ts on looking_filepath
static char looking_filepath[256];

int lookup_isenable() {
    return (agents!=NULL);
}

int free_ifindexlookup_impl(struct lookup_agent* tbl) {
    for(struct lookup_agent* rp = tbl;rp!=NULL;){
        for(struct lookup_ifalias* ip = rp->first;ip!=NULL;){
            struct lookup_ifalias* p = ip;
            ip = ip->next;
            free(p);
        }
        struct lookup_agent* p = rp;
        rp=rp->next;
        free(p);
    }
    return 0;
}

int free_ifindexlookupl() {
    if(agents){
        free_ifindexlookup_impl(agents);
        agents = NULL;
    }
}

int load_ifindexlookup_impl(struct lookup_agent** tbl) {
    struct lookup_agent* ptr = NULL;
    FILE* fp = fopen(looking_filepath, "r");
    if(fp==NULL){
        return 1;
    }
    while(!feof(fp)){
        unsigned int id, ifind;
        char r[20], p[64];
        int ignore;
        ignore = fscanf(fp, "%u", &id);
        ignore = fscanf(fp, "%u", &ifind);
        ignore = fscanf(fp, "%s", &r[0]);
        ignore = fscanf(fp, "%s", &p[0]);
        if(feof(fp))break;
        struct lookup_agent* agent_ptr = NULL;
        struct lookup_agent* prev_agent_ptr = NULL;
        for(struct lookup_agent* rp = ptr;rp!=NULL;rp = rp->next){
            if(rp->id==id){
                agent_ptr = rp;
                break;
            }
            prev_agent_ptr = rp;
        }

        if(agent_ptr==NULL){
            agent_ptr = malloc(sizeof(struct lookup_agent));
            memset(agent_ptr, 0, sizeof(struct lookup_agent));
            agent_ptr->id = id;
            agent_ptr->num_ifind = 0;
            strncpy(agent_ptr->name, r, 20);
            if(ptr==NULL){
                ptr = agent_ptr;
            }
            if(prev_agent_ptr){
                prev_agent_ptr->next = agent_ptr;
            }
        }

        for(struct lookup_ifalias* ip = agent_ptr->first;; ip = ip->next){
            if(ip&&ip->next!=NULL)continue;
            struct lookup_ifalias* ifalias_ptr = NULL;
            ifalias_ptr = malloc(sizeof(struct lookup_ifalias));
            memset(ifalias_ptr, 0, sizeof(struct lookup_ifalias));
            agent_ptr->num_ifind++;

            if(ip==NULL){
                agent_ptr->first = ifalias_ptr;
                ip = ifalias_ptr;
            }else{
                ip->next = ifalias_ptr;
            }
            ifalias_ptr->ifind = ifind;
            strncpy(ifalias_ptr->ifalias, p, 64);
            ifalias_ptr->next = NULL;
            break;
        }

    }
    fclose(fp);
    *tbl = ptr;

    struct stat buf;
    if(stat(looking_filepath, &buf)==0){
        lookup_agent_file_ts = buf.st_mtim.tv_sec;
    }

    fprintf(stderr, "load ifalias information from %s\n", looking_filepath);
    return 0;
}

static int monitor_ifindexlookup_alive = 0;
static pthread_t monitor_thread = 0;
void* monitor_ifindexlookup_file(void *unused) {
    fprintf(stderr, "start monitor_ifindexlookup_file()\n");
    while(monitor_ifindexlookup_alive){
        struct stat buf;
        if(standbytbl==NULL && stat(looking_filepath, &buf)==0){
            if(buf.st_mtim.tv_sec != lookup_agent_file_ts){
                lookup_agent_file_ts = buf.st_mtim.tv_sec;
                int r = load_ifindexlookup_impl(&standbytbl);
                if(r!=0){
                    standbytbl = NULL;
                    fprintf(stderr, "failed load_ifindexlookup_impl()\n");
                }else{
                    fprintf(stderr, "success load_ifindexlookup_impl()\n");
                }
            }
        }
        sleep(10);
    }
}

int start_monotor_ifindexlookup_file() {
    pthread_create(&monitor_thread, NULL, monitor_ifindexlookup_file, NULL);
}

int load_ifindexlookup(const char *filename) {
    char path[256];
    strncpy(path, filename, 256);
    if(access(path, R_OK)!=0){
        snprintf(path, 256, "%s/.sflowtool/%s", getenv("HOME"), filename);
        if(access(path, R_OK)!=0){
            return 1;
        }
    }

    strncpy(looking_filepath, path, 256);
    int r = load_ifindexlookup_impl(&standbytbl);
    if (r==0 && standbytbl){
        agents = standbytbl;
        standbytbl = NULL;
        monitor_ifindexlookup_alive = 1;
        start_monotor_ifindexlookup_file();
        return 0;
    }

    return 1;
}

int update_ifindexlookup() {
    if(standbytbl){
        struct lookup_agent* old = agents;
        agents = standbytbl;
        standbytbl = NULL;
        free_ifindexlookup_impl(old);
        fprintf(stderr, "lookup table was changed.\n");
    }
}

int lookup_agentifindex(const unsigned int agent, const unsigned int ifind, char *name, char *ifalias) {
    for(struct lookup_agent* rp = agents;rp != NULL ;rp = rp->next){
        if(rp->id!=agent)continue;
        for(struct lookup_ifalias* ip = rp->first; ip != NULL; ip = ip->next){
            if(ip->ifind!=ifind)continue;
            strncpy(name, rp->name, 20);
            strncpy(ifalias, ip->ifalias, 64);
            return 0;
        }
    }
    return 1;
}

int lookup_agent(const unsigned int agent, char *name) {
    for(struct lookup_agent* rp = agents;rp != NULL;rp = rp->next){
        if(rp->id!=agent)continue;
        strncpy(name, rp->name, 20);
        return 0;
    }
    return 1;
}

int lookup_ifalias(const unsigned int agent, const unsigned int ifind, char *ifalias) {
    for(struct lookup_agent* rp = agents;rp != NULL;rp = rp->next){
        if(rp->id!=agent)continue;
        for(struct lookup_ifalias* ip = rp->first; ip != NULL; ip = ip->next){
            if(ip->ifind!=ifind)continue;
            strncpy(ifalias, ip->ifalias, 64);
            return 0;
        }
    }
    return 1;
}
#endif // LIBIFINDEXLOOKUP
