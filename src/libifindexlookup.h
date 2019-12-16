#ifndef LIBIFINDEXLOOKUP
#define LIBIFINDEXLOOKUP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int lookup_isenable() {
    return (agents!=NULL);
}

int free_ifindexlookup() {
    for(struct lookup_agent* rp = agents;rp!=NULL;){
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

int load_ifindexlookup(const char *filename) {
    char path[256];
    strncpy(path, filename, 256);
    if(access(path, R_OK)!=0){
        snprintf(path, 256, "%s/.sflowtool/%s", getenv("HOME"), filename);
        if(access(path, R_OK)!=0){
            return 1;
        }
    }

    agents = NULL;
    FILE* fp = fopen(path, "r");
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

        for(struct lookup_agent* rp = agents;rp!=NULL;rp = rp->next){
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
            if(agents==NULL){
                agents = agent_ptr;
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
    fprintf(stderr, "load ifalias information from %s\n", path);
    return 0;
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
