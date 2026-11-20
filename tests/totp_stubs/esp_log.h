#pragma once
/* host 测试用最小日志桩（与 tests/bsp_stubs/esp_log.h 保持一致）。 */
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGD(tag, ...) ((void)(tag))
