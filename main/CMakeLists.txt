idf_component_register(
    SRCS "main.c"
         "totp_app.c"
         "totp_core.c"
         "totp_store.c"
         "totp_net.c"
         "totp_ap_proto.c"
         "totp_dns.c"
         "totp_http.c"
         "totp_http_proto.c"
         "totp_console.c"
         "totp_cjk_16.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES "totp_http_page.html"
    REQUIRES bsp esp_event esp_http_server esp_netif esp_timer esp_wifi json lwip nvs_flash mbedtls
)
