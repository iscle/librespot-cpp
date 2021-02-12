//
// Created by Iscle on 08/02/2021.
//

#ifndef LIBRESPOT_CPP_TIME_PROVIDER_H
#define LIBRESPOT_CPP_TIME_PROVIDER_H

#include <mutex>

class TimeProvider {
public:
    static TimeProvider &get_instance();

    void update(unsigned long millis);

    unsigned long current_time_millis();

private:
    std::mutex time_mutex;
    long offset;

    TimeProvider();

    static unsigned long system_current_time_millis();
};


#endif //LIBRESPOT_CPP_TIME_PROVIDER_H
