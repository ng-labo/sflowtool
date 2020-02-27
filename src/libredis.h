#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hiredis.h"

static redisContext *redisctx;
#define REDISSERVER "127.0.0.1"
#define REDISPORT  6379

static int stat_error = 0;

int init_libhiredis() {

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisctx = redisConnectWithTimeout(REDISSERVER, REDISPORT, timeout);
    if (redisctx == NULL || redisctx->err) {
        if (redisctx) {
            fprintf(stderr, "Connection error: %s\n", redisctx->errstr);
            redisFree(redisctx);
        } else {
            fprintf(stderr, "Connection error: can't allocate redis context\n");
        }
        return 1;
    }

    redisReply *reply = redisCommand(redisctx, "DEL sflow");
    freeReplyObject(reply);

    return 0;
}

void lpush_libhiredis(const char *buf) {
    if(redisctx==NULL){
        fprintf(stderr, "be not connected to redis-server\n");
        return;
    }
    redisReply *reply = redisCommand(redisctx, "LPUSH sflow %s", buf);
    if(reply->type==REDIS_REPLY_ERROR){
        fprintf(stderr, "redisCommand return back REDIS_REPLY_ERROR\n");
    }
    if(redisctx->err){
        fprintf(stderr, "redis connection return back error:%s\n", redisctx->errstr);
        freeReplyObject(reply);
        redisFree(redisctx);
        redisctx==NULL;
        return;
    }
    freeReplyObject(reply);
}

void free_libhiredis() {
    redisFree(redisctx);
    redisctx==NULL;
}
