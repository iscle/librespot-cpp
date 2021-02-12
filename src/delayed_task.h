//
// Created by Iscle on 08/02/2021.
//

#ifndef LIBRESPOT_CPP_DELAYED_TASK_H
#define LIBRESPOT_CPP_DELAYED_TASK_H

#include <chrono>
#include <functional>
#include <thread>

class DelayedTask {
public:
    DelayedTask(std::chrono::seconds interval, std::function<void()> callback);

    void reset();

    void cancel();

private:
    bool is_running;
    std::thread thread;
    std::chrono::seconds interval;
    std::function<void()> callback;
};


#endif //LIBRESPOT_CPP_DELAYED_TASK_H
