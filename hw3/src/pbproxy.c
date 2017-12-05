#include "pbproxy.h"
#include "debug.h"

#include "args.h"
#include "client.h"
#include "server.h"

extern state_t * p_state;

int main(int argc, char *argv[]) {
    
    // 1 Parse Argument
    parse_args(argc, argv);
    
    // 2 Run Server or Client
    if (p_state->is_server) {
        run_server(p_state->dest, p_state->proxy_port, &(p_state->key));
    } else {
        run_client(p_state->dest, &(p_state->key));
    }
    
    exit(EXIT_SUCCESS);
}
