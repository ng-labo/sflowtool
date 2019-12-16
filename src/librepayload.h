#ifndef LIBREPAYLOAD
#define LIBREPAYLOAD

#include <sys/types.h>
#include <regex.h>

static regex_t* regex_compiled = NULL;
static int num_of_pattern = 0;

int init_regex_t(const int ac, const char **av) {
    num_of_pattern = ac;
    regex_compiled = malloc(sizeof(regex_t) * ac);

    for(int i=0; i<ac; i++){
        int val = regcomp(&regex_compiled[i], av[i], REG_EXTENDED);
        if (val != 0) {
            return 1;
        }
    }
    return 0;
}

void defer_regex_t() {
    for(int i=0; i<num_of_pattern; i++){
        regfree(&regex_compiled[i]);
    }
    free(regex_compiled);
    regex_compiled = NULL;
}

int inspect_pattern(const char *buf) {
    if(num_of_pattern==0) return -1;
    if(buf==NULL) return 0;
    if(*buf=='\0') return 0;

    int ret = 0;
    int index = 1;
    for(int i=0; i<num_of_pattern; i++, index<<=1) {
        int val = regexec(&regex_compiled[i], buf, 0, NULL, 0);
        if(!val){
            ret |= index;
        }
    }
    return ret;
}

#endif // LIBREPAYLOAD
