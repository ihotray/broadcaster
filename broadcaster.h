#ifndef __BROADCASTER_H__
#define __BROADCASTER_H__

#include <iot/mongoose.h>


struct broadcaster_option {
    const char *service;
    const char *udp_listening_address;  //udp 监听端口
    const char *callback_lua;
    const char *key;
    int debug_level;
};

struct broadcaster_config {
    struct broadcaster_option *opts;
};

struct broadcaster_private {

    struct broadcaster_config cfg;
    struct mg_mgr mgr;

};

int broadcaster_main(void *user_options);


#endif