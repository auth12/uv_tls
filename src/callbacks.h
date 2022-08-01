#pragma once

namespace callbacks {
    
    void on_close( uv_handle_t *handle ) {
        auto client = ( client_context_t * )handle->data;

        mbedtls_net_free( &client->net_ctx );
        mbedtls_ssl_free( &client->ssl_ctx );
        free( client );
    }

    void on_poll_client( uv_poll_t *handle, int status, int events ) {
        const auto client = ( client_context_t * )handle->data;

        if ( events & UV_DISCONNECT ) {

            spdlog::warn( "client disconnected" );

            uv_close( ( uv_handle_t * )handle, on_close );

            return;
        }

        if ( events & UV_READABLE ) {
            unsigned char buf[ 1024 ];
            int ret = mbedtls_ssl_read( &client->ssl_ctx, buf, sizeof( buf ) - 1 );

            spdlog::info( "read {} bytes from {}", ret, client->get_ip( ) );

            return;
        }
    }

    void on_poll_server( uv_poll_t *handle, int status, int events ) {
        auto server_ctx = ( server_context_t * )handle->data;

        auto client = ( client_context_t * )malloc( sizeof( client_context_t ) );

        mbedtls_ssl_init( &client->ssl_ctx );

        size_t ip_len;
        int ret = mbedtls_net_accept( &server_ctx->net_ctx, &client->net_ctx, client->ip,
                                      sizeof( client->ip ), &ip_len );
        if ( ret != 0 ) {
            spdlog::error( "failed to accept new client, code {:x}", ret );
            free( client );

            return;
        }

        ret = mbedtls_ssl_setup( &client->ssl_ctx, &server_ctx->ssl_config );
        if ( ret != 0 ) {
            spdlog::error( "SSL setup failed on client {}, code {:x}", client->get_ip( ), ret );
            free( client );

            return;
        }

        mbedtls_ssl_set_bio( &client->ssl_ctx, &client->net_ctx, mbedtls_net_send, mbedtls_net_recv, NULL );

        while ( ( ret = mbedtls_ssl_handshake( &client->ssl_ctx ) ) != 0 ) {
            if ( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                spdlog::critical( "SSL handshake failed on client {}, code {:x}", client->get_ip( ), ret );
                free( client );
                return;
            }
        }

        uv_poll_init_socket( server_ctx->loop, &client->handle, client->net_ctx.fd );
        client->handle.data = client;

        uv_poll_start( &client->handle, UV_READABLE | UV_DISCONNECT, on_poll_client );

        spdlog::info( "new client connected" );
    }

}; // namespace callbacks