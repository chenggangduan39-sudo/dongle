#ifndef USB_CRYPTO_H
#define USB_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 检查 USB 加密许可
 * @return 0 表示验证通过，非 0 表示失败
 */
int usb_crypto_verify(void);

#ifdef __cplusplus
}
#endif

#endif 
