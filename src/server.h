#pragma once

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

struct client_context_t {
    uv_poll_t handle;

    u8 ip[ 4 ];
    mbedtls_net_context net_ctx;
    mbedtls_ssl_context ssl_ctx;

    std::string get_ip( ) {
        return fmt::format( "{}.{}.{}.{}", ip[ 0 ], ip[ 1 ], ip[ 2 ], ip[ 3 ] );
    }
};

struct server_context_t {
    uv_loop_t *loop;

    uv_poll_t handle;

    mbedtls_net_context net_ctx;

    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_config;

    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    server_context_t( ) {
        mbedtls_x509_crt_init( &srvcert );
        mbedtls_pk_init( &pkey );
        mbedtls_entropy_init( &entropy );
        mbedtls_ctr_drbg_init( &ctr_drbg );

        mbedtls_net_init( &net_ctx );
        mbedtls_ssl_init( &ssl_ctx );
        mbedtls_ssl_config_init( &ssl_config );
    }
};

namespace server {
    int setup_ssl( const std::string_view cert_path, const std::string_view key_path, server_context_t *ctx ) {
        int ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func,
                                         &ctx->entropy, NULL, 0 );
        if ( ret != 0 ) {
            spdlog::error( "failed to seed the number generator, code 0x{:X}",
                           -ret );
            return ret;
        }

        ret = mbedtls_x509_crt_parse_file( &ctx->srvcert, cert_path.data( ) );
        if ( ret != 0 ) {
            spdlog::error( "failed to parse certificate, code 0x{:X}", -ret );
            return ret;
        }

        ret = mbedtls_pk_parse_keyfile( &ctx->pkey, key_path.data( ), NULL,
                                        mbedtls_ctr_drbg_random, &ctx->ctr_drbg );
        if ( ret != 0 ) {
            spdlog::error( "failed to parse key, code 0x{:X}", ret );
            return ret;
        }

        ret = mbedtls_ssl_config_defaults( &ctx->ssl_config, MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT );
        if ( ret != 0 ) {
            spdlog::error( "failed to bind port, code 0x{:X}", ret );
            return ret;
        }

        mbedtls_ssl_conf_rng( &ctx->ssl_config, mbedtls_ctr_drbg_random,
                              &ctx->ctr_drbg );

        ret = mbedtls_ssl_conf_own_cert( &ctx->ssl_config, &ctx->srvcert,
                                         &ctx->pkey );
        if ( ret != 0 ) {
            spdlog::error( "failed to setup key and cert, code 0x{:X}", ret );
            return ret;
        }

        return ret;
    }

}; // namespace server