//
// Created by Iscle on 30/01/2021.
//

#include "version.h"

spotify::Platform Version::platform() {
    return spotify::PLATFORM_LINUX_X86;
}

spotify::BuildInfo Version::standard_build_info() {
    spotify::BuildInfo build_info;

    build_info.Clear();
    build_info.set_product(spotify::PRODUCT_CLIENT);
    build_info.add_product_flags(spotify::PRODUCT_FLAG_NONE);
    build_info.set_platform(platform());
    build_info.set_version(112800721);

    return build_info;
}
