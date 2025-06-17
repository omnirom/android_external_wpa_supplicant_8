/*
 * WPA Supplicant - Manager for callback objects
 * Copyright (c) 2025, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "callback_manager.h"

extern "C"
{
#include "utils/common.h"
#include "wpa_supplicant_i.h"
}

// Raw pointer to the global structure maintained by the core
// Declared here to be accessible to onDeath()
struct wpa_global* wpa_global_;

void onDeath(void* cookie) {
    wpa_printf(MSG_ERROR, "Client died. Terminating...");
    wpa_supplicant_terminate_proc(wpa_global_);
}

CallbackManager* CallbackManager::instance_ = NULL;

void CallbackManager::initialize(struct wpa_global* wpa_global) {
    wpa_printf(MSG_INFO, "Initializing the callback manager");
    wpa_global_ = wpa_global;
    instance_ = new CallbackManager();
    instance_->death_notifier_ = AIBinder_DeathRecipient_new(onDeath);
}

CallbackManager* CallbackManager::getInstance() {
    return instance_;
}

bool CallbackManager::registerStaIfaceCallback(std::string ifaceName,
        const std::shared_ptr<IStaInterfaceCallback>& callback) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!callback) {
         wpa_printf(MSG_ERROR, "Attempted to register a null callback for STA iface %s",
            ifaceName.c_str());
        return false;
    }
    if (callbackRegisteredForStaIface(ifaceName)) {
        wpa_printf(MSG_ERROR, "Callback is already registered for STA iface %s",
            ifaceName.c_str());
        return false;
    }
    binder_status_t status = AIBinder_linkToDeath(callback->asBinder().get(),
        death_notifier_, nullptr /* cookie */);
    if (status != STATUS_OK) {
        wpa_printf(MSG_ERROR, "Received code %d when linking death recipient"
            " for callback on STA iface %s", status, ifaceName.c_str());
        return false;
    }
    wpa_printf(MSG_INFO, "Registered callback for STA iface %s", ifaceName.c_str());
    sta_iface_callbacks_[ifaceName] = callback;
    return true;
}

void CallbackManager::unregisterStaIfaceCallback(std::string ifaceName) {
    std::lock_guard<std::mutex> guard(mutex_);
    wpa_printf(MSG_INFO, "Unregistering callback for STA iface %s",
        ifaceName.c_str());
    if (!callbackRegisteredForStaIface(ifaceName)) {
        wpa_printf(MSG_INFO, "Callback does not need to be unregistered"
            " for STA iface %s", ifaceName.c_str());
        return;
    }
    auto callback = sta_iface_callbacks_[ifaceName];
    binder_status_t status = AIBinder_unlinkToDeath(callback->asBinder().get(),
        death_notifier_, nullptr /* cookie */);
    if (status != STATUS_OK) {
        wpa_printf(MSG_ERROR, "Received code %d when unlinking death recipient"
            " for callback on STA iface %s", status, ifaceName.c_str());
    }
    sta_iface_callbacks_.erase(ifaceName);
}

std::shared_ptr<IStaInterfaceCallback> CallbackManager::getStaIfaceCallback(
        std::string ifaceName) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!callbackRegisteredForStaIface(ifaceName)) {
        return nullptr;
    }
    return sta_iface_callbacks_[ifaceName];
}
