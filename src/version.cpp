//
// Created by Iscle on 30/01/2021.
//

#include "version.h"
#include "utils.h"

spotify::Platform Version::platform() {
    return spotify::PLATFORM_LINUX_X86;
}

spotify::BuildInfo *Version::build_info() {
    auto *build_info = new spotify::BuildInfo;

    build_info->set_product(spotify::PRODUCT_CLIENT);
    build_info->add_product_flags(spotify::PRODUCT_FLAG_NONE);
    build_info->set_platform(platform());
    build_info->set_version(112800721);

    return build_info;
}

std::string Version::version_string() {
    return "librespot-c++ 0.0.1";
}

spotify::SystemInfo Version::system_info() {
    spotify::SystemInfo system_info;

    system_info.set_os(spotify::OS_LINUX);
    system_info.set_cpu_family(spotify::CPU_X86_64);
    system_info.set_system_information_string(version_string() + " 0.0.1; C++11; Linux");
    system_info.set_device_id(utils::generate_device_id());


}