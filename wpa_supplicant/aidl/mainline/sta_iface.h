/*
 * WPA Supplicant - Station mode interface
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_STA_IFACE_H
#define MAINLINE_SUPPLICANT_STA_IFACE_H

#include <aidl/android/system/wifi/mainline_supplicant/BnStaInterface.h>
#include <aidl/android/system/wifi/mainline_supplicant/IStaInterfaceCallback.h>

using ::aidl::android::system::wifi::mainline_supplicant::BnStaInterface;
using ::aidl::android::system::wifi::mainline_supplicant::IStaInterfaceCallback;
using ::aidl::android::system::wifi::mainline_supplicant::UsdMessageInfo;

class StaIface : public BnStaInterface {
    public:
        StaIface(struct wpa_global* wpa_global, std::string iface_name);
        ::ndk::ScopedAStatus registerCallback(
            const std::shared_ptr<IStaInterfaceCallback>& in_callback) override;
        ::ndk::ScopedAStatus getUsdCapabilities(UsdCapabilities* _aidl_return) override;
        ::ndk::ScopedAStatus startUsdPublish(int32_t in_cmdId,
            const UsdPublishConfig& in_publishConfig) override;
        ::ndk::ScopedAStatus startUsdSubscribe(int32_t in_cmdId,
            const UsdSubscribeConfig& in_subscribeConfig) override;
        ::ndk::ScopedAStatus updateUsdPublish(int32_t in_publishId,
            const std::vector<uint8_t>& in_serviceSpecificInfo) override;
        ::ndk::ScopedAStatus cancelUsdPublish(int32_t in_publishId) override;
        ::ndk::ScopedAStatus cancelUsdSubscribe(int32_t in_subscribeId) override;
        ::ndk::ScopedAStatus sendUsdMessage(const UsdMessageInfo& in_messageInfo) override;

    private:
        wpa_global* wpa_global_;
        std::string iface_name_;

        struct wpa_supplicant* retrieveIfacePtr();
};

#endif // MAINLINE_SUPPLICANT_STA_IFACE_H
