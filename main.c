#include <iot/mongoose.h>
#include "broadcaster.h"


static void usage(const char *prog) {
    fprintf(stderr,
            "IoT-SDK v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -n SERVICE  - service name for different product, default: '%s'\n"
            "  -l ADDR     - udp listening address, default: '%s'\n"
            "  -x PATH     - broadcaster callback lua script, default: '%s'\n"
            "  -v LEVEL    - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, "iot-device", "udp://0.0.0.0:5858", "/www/iot/handler/broadcaster.lua", MG_LL_INFO);

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    struct broadcaster_option opts = {
        .service = "iot-device",
        .udp_listening_address = "udp://0.0.0.0:5858",
        .callback_lua = "/www/iot/handler/broadcaster.lua",
        .debug_level = MG_LL_INFO
    };

    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0) {
            opts.service = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0) {
            opts.udp_listening_address = argv[++i];
        } else if (strcmp(argv[i], "-x") == 0) {
            opts.callback_lua = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            opts.debug_level = atoi(argv[++i]);
        } else {
            usage(argv[0]);
        }
    }

    MG_INFO(("IoT-SDK version  : v%s", MG_VERSION));
    MG_INFO(("udp listening on : %s", opts.udp_listening_address));
    MG_INFO(("callback lua     : %s", opts.callback_lua));

    broadcaster_main(&opts);
    return 0;
}