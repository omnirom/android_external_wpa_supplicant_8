/*
 * WPA Supplicant - Manager for callback objects
 * Copyright (c) 2025, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_CALLBACK_MANAGER_H
#define MAINLINE_SUPPLICANT_CALLBACK_MANAGER_H

#include <map>
#include <mutex>
#include <string>

#include <aidl/android/system/wifi/mainline_supplicant/IStaInterfaceCallback.h>

using ::aidl::android::system::wifi::mainline_supplicant::IStaInterfaceCallback;

/**
 * Class to manage all registered callback objects.
 *
 * On startup, a singleton instance should be created using initialize().
 * Subsequent callers should retrieve the singleton using getInstance().
 */
class CallbackManager {
    public:
        // Singleton access
        static void initialize(struct wpa_global* wpa_global);
        static CallbackManager* getInstance();

        // Member functions
        bool registerStaIfaceCallback(std::string ifaceName,
            const std::shared_ptr<IStaInterfaceCallback>& callback);
        void unregisterStaIfaceCallback(std::string ifaceName);
        std::shared_ptr<IStaInterfaceCallback> getStaIfaceCallback(std::string ifaceName);

    private:
        inline bool callbackRegisteredForStaIface(std::string ifaceName) {
            return sta_iface_callbacks_.find(ifaceName) != sta_iface_callbacks_.end();
        }

        // Singleton instance of this class
        static CallbackManager* instance_;

        // Member variables
        std::mutex mutex_;
        AIBinder_DeathRecipient* death_notifier_;
        std::map<std::string, std::shared_ptr<IStaInterfaceCallback>> sta_iface_callbacks_;
};

#endif // MAINLINE_SUPPLICANT_CALLBACK_MANAGER_H
