#include <lualib.h>
#include <lauxlib.h>
#include <iot/mongoose.h>
#include <iot/cJSON.h>
#include "broadcaster.h"

static void udp_payload_read_cb(struct mg_connection *c, cJSON *request, cJSON *address) {

    struct broadcaster_private *priv = (struct broadcaster_private *)c->mgr->userdata;
    const char *ret = NULL;
    const char *response = NULL;
    cJSON *root = NULL;
    lua_State *L = luaL_newstate();

    luaL_openlibs(L);

    if ( luaL_dofile(L, priv->cfg.opts->callback_lua) ) {
        MG_ERROR(("lua dofile failed"));
        goto done;
    }

    lua_getfield(L, -1, "on_message");
    if (!lua_isfunction(L, -1)) {
        MG_ERROR(("method on_message is not a function"));
        goto done;
    }

    lua_pushstring(L, request->valuestring);
    lua_pushstring(L, address->valuestring);

    if (lua_pcall(L, 2, 1, 0)) {//two param, one return values, zero error func
        MG_ERROR(("callback failed"));
        goto done;
    }

    ret = lua_tostring(L, -1);
    if (!ret) {
        MG_ERROR(("lua call no ret"));
        goto done;
    }

    MG_INFO(("ret: %s", ret));

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "service", priv->cfg.opts->service);
    cJSON_AddStringToObject(root, "payload", ret);
    response = cJSON_Print(root);

    mg_send(c, response, strlen(response));

done:
    if (response)
        cJSON_free((void*)response);
    if (root)
        cJSON_Delete(root);

    if (L)
        lua_close(L);
}

static void udp_ev_read_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (c->recv.len > 0) {
        MG_INFO(("udp_ev_read_cb: %.*s",  c->recv.len, (char *)c->recv.buf));
        struct broadcaster_private *priv = (struct broadcaster_private *)c->mgr->userdata;
        cJSON *root = cJSON_ParseWithLength((char *)c->recv.buf, c->recv.len);
        cJSON *service = cJSON_GetObjectItem(root, "service");
        cJSON *payload = cJSON_GetObjectItem(root, "payload");
        cJSON *address = cJSON_GetObjectItem(root, "address");
        if ( cJSON_IsString(service) && mg_casecmp(service->valuestring, priv->cfg.opts->service) == 0 \
            && cJSON_IsString(payload) && cJSON_IsString(address)) {
            udp_payload_read_cb(c, payload, address);
        } else {
            MG_ERROR(("service name not match"));
        }
        cJSON_Delete(root);
    }
    c->recv.len = 0;
}

// Event handler for the listening connection.
static void udp_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    switch (ev) {
        case MG_EV_READ:
            udp_ev_read_cb(c, ev, ev_data, fn_data);
            break;
    }
}

static int s_signo;
static void signal_handler(int signo) {
    s_signo = signo;
}

int broadcaster_init(void **priv, void *opts) {

    struct broadcaster_private *p;
    struct mg_connection *c;

    signal(SIGINT, signal_handler);   // Setup signal handlers - exist event
    signal(SIGTERM, signal_handler);  // manager loop on SIGINT and SIGTERM

    *priv = NULL;
    p = calloc(1, sizeof(struct broadcaster_private));
    if (!p)
        return -1;

    p->cfg.opts = opts;
    mg_log_set(p->cfg.opts->debug_level);

    mg_mgr_init(&p->mgr);

    p->mgr.userdata = p;

    *priv = p;

    c = mg_listen(&p->mgr, p->cfg.opts->udp_listening_address, udp_cb, NULL);
    if (!c) {
        MG_ERROR(("Cannot listen on %s. Use udp://ADDR:PORT or :PORT", p->cfg.opts->udp_listening_address));
        goto out_err;
    }

    return 0;

out_err:
    free(p);
    return -1;
}


void broadcaster_run(void *handle) {
    struct broadcaster_private *priv = (struct broadcaster_private *)handle;
    while (s_signo == 0) mg_mgr_poll(&priv->mgr, 10000);  // Event loop, 10s timeout
}

void broadcaster_exit(void *handle) {
    struct broadcaster_private *priv = (struct broadcaster_private *)handle;
    mg_mgr_free(&priv->mgr);
    free(handle);
}

int broadcaster_main(void *user_options) {

    struct broadcaster_option *opts = (struct broadcaster_option *)user_options;
    void *broadcaster_handle;
    int ret;

    ret = broadcaster_init(&broadcaster_handle, opts);
    if (ret)
        exit(EXIT_FAILURE);

    broadcaster_run(broadcaster_handle);

    broadcaster_exit(broadcaster_handle);

    return 0;

}