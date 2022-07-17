#include "include.h"

#include <uv.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <spdlog/spdlog.h>

struct context_t {
    uv_loop_t *loop;

    uv_poll_t handle;

    mbedtls_net_context net_ctx_;

	mbedtls_ssl_context ssl_ctx_;
	mbedtls_ssl_config ssl_config_;

    mbedtls_x509_crt srvcert_;
	mbedtls_pk_context pkey_;
	mbedtls_entropy_context entropy_;
	mbedtls_ctr_drbg_context ctr_drbg_;

    context_t( ) {
        mbedtls_x509_crt_init( &srvcert_ );
		mbedtls_pk_init( &pkey_ );
		mbedtls_entropy_init( &entropy_ );
		mbedtls_ctr_drbg_init( &ctr_drbg_ );

        mbedtls_net_init( &net_ctx_ );
		mbedtls_ssl_init( &ssl_ctx_ );
		mbedtls_ssl_config_init( &ssl_config_ );
    }

} g_ctx;

int setup_ssl( const std::string_view cert_path, const std::string_view key_path ) {
    int ret = mbedtls_ctr_drbg_seed( &g_ctx.ctr_drbg_, mbedtls_entropy_func, &g_ctx.entropy_, NULL, 0 );
	if ( ret != 0 ) {
		spdlog::error( "failed to seed the number generator, code 0x{:X}", -ret );
		return ret;
	}

	ret = mbedtls_x509_crt_parse_file( &g_ctx.srvcert_, cert_path.data( ) );
	if ( ret != 0 ) {
		spdlog::error( "failed to parse certificate, code 0x{:X}", -ret );
		return ret;
	}

	ret = mbedtls_pk_parse_keyfile( &g_ctx.pkey_, key_path.data( ), NULL, mbedtls_ctr_drbg_random, &g_ctx.ctr_drbg_ );
	if ( ret != 0 ) {
		spdlog::error( "failed to parse key, code 0x{:X}", ret );
		return ret;
	}

	ret = mbedtls_ssl_config_defaults( &g_ctx.ssl_config_, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT );
	if ( ret != 0 ) {
		spdlog::error( "failed to bind port, code 0x{:X}", ret );
		return ret;
	}

	mbedtls_ssl_conf_rng( &g_ctx.ssl_config_, mbedtls_ctr_drbg_random, &g_ctx.ctr_drbg_ );

	ret = mbedtls_ssl_conf_own_cert( &g_ctx.ssl_config_, &g_ctx.srvcert_, &g_ctx.pkey_ );
	if ( ret != 0 ) {
		spdlog::error( "failed to setup key and cert, code 0x{:X}", ret );
		return ret;
	}

    return ret;
}

struct client_context_t {
    uv_poll_t handle;

    mbedtls_net_context net_ctx_;
	mbedtls_ssl_context ssl_ctx_;
};

void on_close( uv_handle_t *handle ) {
    auto client = ( client_context_t * )handle->data;

    mbedtls_net_free( &client->net_ctx_ );
    mbedtls_ssl_free( &client->ssl_ctx_ );
    free( client );
}

void on_poll_client( uv_poll_t *handle, int status, int events ) {
    auto client = ( client_context_t * )handle->data;

    if( events & UV_DISCONNECT ) {

        spdlog::warn( "client disconnected" );
        

        uv_close( ( uv_handle_t * )handle, on_close );

        return;
    }


    if( events & UV_READABLE ) {
        unsigned char buf[ 1024 ];
        int ret = mbedtls_net_recv( &client->net_ctx_, buf, 1024 );

        spdlog::info( "read {} bytes from {}", ret, client->net_ctx_.fd );

        return;
    }

    
}

void on_poll_server( uv_poll_t *handle, int status, int events ) {
    const auto ctx = ( context_t * )handle->data;

    auto c = ( client_context_t * )malloc( sizeof( client_context_t ) );
    
    size_t ip_len;
	u8 client_ip[ 16 ] = { 0 };

	int ret = mbedtls_net_accept( &ctx->net_ctx_, &c->net_ctx_, &client_ip[ 0 ], sizeof( client_ip ), &ip_len );
	if ( ret != 0 ) {
		spdlog::error( "failed to accept new client, code {:x}", ret );
		return;
	}

    spdlog::info( "new client connected" );

    uv_poll_init_socket( ctx->loop, &c->handle, c->net_ctx_.fd );
    c->handle.data = c;
    
    uv_poll_start( &c->handle, UV_READABLE | UV_DISCONNECT, on_poll_client );
}

int main( ) {
    g_ctx.loop = uv_default_loop( );

    int res = setup_ssl( "ssl/server-cer.pem", "ssl/server-prk.pem" );
    if( res != 0 ) {
        return 0;
    }

    res = mbedtls_net_bind( &g_ctx.net_ctx_, "0.0.0.0", "4646", MBEDTLS_NET_PROTO_TCP );
	if ( res != 0 ) {
		spdlog::error( "failed to bind port, code 0x{:X}", res );
		return 0;
	}

    spdlog::info( "listening on {}", 4646 );
    spdlog::info( "socket {}", g_ctx.net_ctx_.fd );

    uv_poll_init_socket( g_ctx.loop, &g_ctx.handle, g_ctx.net_ctx_.fd );
    g_ctx.handle.data = &g_ctx;

    uv_poll_start( &g_ctx.handle, UV_READABLE, on_poll_server );

    return uv_run( g_ctx.loop, UV_RUN_DEFAULT );
}