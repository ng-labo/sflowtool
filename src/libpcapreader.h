#ifndef LIBPCAPREADER_H
#define LIBPCAPREADER_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bzlib.h>
#define __USE_GNU
#include <pthread.h>

#define PCAP_BUFFER_LENGTH 32768
#define PCAP_BUFFER_NUMBER 2

#define PCAP_BUFSTAT_FREE 0
#define PCAP_BUFSTAT_LOADED 1
#define PCAP_BUFSTAT_CLOSED 2

static struct {
    char *data[PCAP_BUFFER_LENGTH];
    size_t length[PCAP_BUFFER_NUMBER];
    volatile int status[PCAP_BUFFER_NUMBER];
} pcap_buffer;

static int pcap_finished;
static BZFILE* pcap_bzfile;
static FILE* pcap_fp;
static pthread_t pcap_thread_id;

static void *pcap_bz2_reader();
static void *pcap_raw_reader();

static void release_buffers() {
    for(int i=0;i<PCAP_BUFFER_NUMBER;i++){
        if(pcap_buffer.data[i]) {
            free(pcap_buffer.data[i]);
            pcap_buffer.data[i] = 0;
        }
    }
}

static inline void DBG(char* fmt, ...) {
    va_list alst;
    va_start(alst, fmt);
    vfprintf(stderr, fmt, alst);
    va_end(alst);
}

static inline void waiting(volatile int *ptr, const int status) {
    // XXX
    if(*ptr != status) while(*ptr != status) {
        pthread_yield();
    }
}

static inline void waiting2(volatile int *ptr, const int status1, const int status2) {
    if(*ptr != status1 && *ptr != status2) while(*ptr != status1 && *ptr != status2) {
        pthread_yield();
    }
}

static int pcap_bz2_read_and_rotate(const int loading_bufindex) {
    int libbzerr;
    pcap_buffer.length[loading_bufindex] = BZ2_bzRead(&libbzerr, pcap_bzfile, pcap_buffer.data[loading_bufindex], PCAP_BUFFER_LENGTH);
    pcap_buffer.status[loading_bufindex] = PCAP_BUFSTAT_LOADED;

    if(libbzerr==BZ_STREAM_END||libbzerr!=BZ_OK){
        int notread;
        BZ2_bzReadClose(&notread, pcap_bzfile);
        return 1;
    }
    return 0;
}

static int pcap_raw_read_and_rotate(const int loading_bufindex) {
    size_t read_len = 0;
    char *ptr = pcap_buffer.data[loading_bufindex];
    for(int i=0;i<PCAP_BUFFER_LENGTH;i++){
        if(fread(ptr++, 1, 1, pcap_fp)==1) read_len++;
        else break;
    }
    pcap_buffer.length[loading_bufindex] = read_len;
    pcap_buffer.status[loading_bufindex] = PCAP_BUFSTAT_LOADED;
    if(feof(pcap_fp)){
        return 1;
    }
    return 0;
}

static void *pcap_reader(void *arg) {
    const int (*read_and_rotate)(const int) = arg;
    int loading_bufindex = 0;
    while(1){
        waiting(&pcap_buffer.status[loading_bufindex], PCAP_BUFSTAT_FREE);

        if(read_and_rotate(loading_bufindex)==1){
            // read_and_rotate return 1 when reaching on end
            if(pcap_buffer.length[loading_bufindex]==0){
                pcap_buffer.status[loading_bufindex] = PCAP_BUFSTAT_CLOSED;
            }else{
                if(++loading_bufindex==PCAP_BUFFER_NUMBER){
                    loading_bufindex = 0;
                }
                waiting(&pcap_buffer.status[loading_bufindex], PCAP_BUFSTAT_FREE);
                pcap_buffer.status[loading_bufindex] = PCAP_BUFSTAT_CLOSED;
            }
            break;
        }

        if(++loading_bufindex==PCAP_BUFFER_NUMBER){
            loading_bufindex = 0;
        }
    }
}

FILE *pcap_open(const char *path, const char *mode) {
    if(strcmp(path, "-")==0){
        pcap_fp = stdin;
    }else{
        pcap_fp = fopen(path, mode);
    }
    if(pcap_fp==NULL){
        return pcap_fp;
    }

    for(int i=0;i<PCAP_BUFFER_NUMBER;i++) {
        pcap_buffer.data[i] = 0;
        pcap_buffer.length[i] = 0;
        pcap_buffer.status[i] = PCAP_BUFSTAT_FREE;
    }
    for(int i=0;i<PCAP_BUFFER_NUMBER;i++){
        pcap_buffer.data[i] = malloc(PCAP_BUFFER_LENGTH);
        if(pcap_buffer.data[i]==NULL){
            release_buffers();
            fclose(pcap_fp);
            return NULL;
        }
    }

    pcap_finished = 0;

    int (*func_read_and_rotate)(const int);

    const size_t l = strlen(path);
    const char *p = path;
    if(l>4 && p[l-4]=='.' && p[l-3]=='b' && p[l-2]=='z' && p[l-1]=='2'){
        // initialize libbz2
        int libbzerr;
        pcap_bzfile = BZ2_bzReadOpen(&libbzerr, pcap_fp, 0, 0, NULL, 0);
        if(libbzerr != BZ_OK){
            pcap_bzfile = NULL;
            release_buffers();
            fclose(pcap_fp);
            return NULL;
        }

        // specific function in pcap_reader
        func_read_and_rotate = pcap_bz2_read_and_rotate;
    }else{
        // specific function in pcap_reader
        func_read_and_rotate = pcap_raw_read_and_rotate;
    }
    // start to load pcap into buffer
    pthread_create(&pcap_thread_id, NULL, pcap_reader, func_read_and_rotate);

    return pcap_fp;
}

int pcap_read(void *ptr, size_t size, int nmemb, void *stream) {
    static int reading_bufindex = 0;
    static char *curptr = 0;

    curptr = (curptr==0) ? pcap_buffer.data[0] : curptr;
    int ret = 0;
    while(size>0){
        // wait for LOADED at reading_bufindex on pcap_buffer[n].status
	// it will be possible to get CLOSED
        waiting2(&pcap_buffer.status[reading_bufindex], PCAP_BUFSTAT_LOADED, PCAP_BUFSTAT_CLOSED);
        if(pcap_buffer.status[reading_bufindex]==PCAP_BUFSTAT_CLOSED){
            pcap_finished = 1;
            // XXX
            pthread_join(pcap_thread_id, NULL);
            release_buffers();
            break;
        }

        size_t dlen = pcap_buffer.length[reading_bufindex] - (curptr - pcap_buffer.data[reading_bufindex]);
        if(dlen==0){
            pcap_buffer.status[reading_bufindex] = PCAP_BUFSTAT_FREE;
            pcap_buffer.length[reading_bufindex] = 0;
            if(++reading_bufindex==PCAP_BUFFER_NUMBER){
                reading_bufindex = 0;
            }
            curptr = pcap_buffer.data[reading_bufindex];
            dlen = pcap_buffer.length[reading_bufindex];
        }
        if(size<=dlen){
            memcpy(ptr, curptr, size);
            curptr += size;
            size = 0;
            ret = 1;
            break;
        }else{
            memcpy(ptr, curptr, dlen);
            ptr += dlen;
            size -= dlen;
            curptr += dlen;
            // now curptr-pcap_buffer == PCAP_BUFFER_LENGTH
        }
    }
    return ret;
}

int pcap_feof(FILE *fp) {
    return pcap_finished;
}

#endif // LIBPCAPREADER_H
