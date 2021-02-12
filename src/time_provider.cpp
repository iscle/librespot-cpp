//
// Created by Iscle on 08/02/2021.
//

#include <chrono>
#include <spdlog/spdlog.h>
#include "time_provider.h"

TimeProvider::TimeProvider() : offset(0) {
}

TimeProvider &TimeProvider::get_instance() {
    static TimeProvider instance;
    return instance;
}

void TimeProvider::update(unsigned long millis) {
    std::lock_guard<std::mutex> mutex(time_mutex);
    auto now = system_current_time_millis();
    offset = (long) (millis - now);

    SPDLOG_DEBUG("Loaded time offset from ping: {}ms", offset);
}

unsigned long TimeProvider::current_time_millis() {
    return system_current_time_millis() + offset;
}

unsigned long TimeProvider::system_current_time_millis() {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}
