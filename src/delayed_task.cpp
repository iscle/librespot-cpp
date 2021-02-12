//
// Created by Iscle on 08/02/2021.
//

#include "delayed_task.h"

#include <utility>

DelayedTask::DelayedTask(std::chrono::seconds interval, std::function<void()> callback) {
    this->interval = interval;
    this->callback = std::move(callback);
}

void DelayedTask::reset() {

}

void DelayedTask::cancel() {

}
