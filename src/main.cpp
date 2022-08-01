#include "include.h"

#include "server.h"

#include "callbacks.h"

#define PORT "4646"
#define BIND_IP "0.0.0.0"

int main( ) {
    server_context_t server_ctx;

    server_ctx.loop = uv_default_loop( );

    int res = server::setup_ssl( "ssl/server-cer.pem", "ssl/server-prk.pem", &server_ctx );
    if ( res != 0 ) {
        return 0;
    }

    res = mbedtls_net_bind( &server_ctx.net_ctx, BIND_IP, PORT, MBEDTLS_NET_PROTO_TCP );
    if ( res != 0 ) {
        spdlog::error( "failed to bind port, code 0x{:X}", res );
        return 0;
    }

    spdlog::info( "listening on port {}", PORT );

    uv_poll_init_socket( server_ctx.loop, &server_ctx.handle, server_ctx.net_ctx.fd );
    server_ctx.handle.data = &server_ctx;

    uv_poll_start( &server_ctx.handle, UV_READABLE, callbacks::on_poll_server );

    return uv_run( server_ctx.loop, UV_RUN_DEFAULT );
}