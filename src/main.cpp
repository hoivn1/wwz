#include <cstdio>
#include <cstdint>

#include "wwz/Sandbox/SyscallResolver.h"

int main() {
    auto& resolver = wwz::sandbox::SyscallResolver::Instance();
    if (!resolver.Initialize()) {
        std::fprintf(stderr, "Syscall resolver initialization failed.\n");
        return 1;
    }

    for (std::uint8_t raw = 0;
         raw < static_cast<std::uint8_t>(wwz::sandbox::SyscallId::Count);
         ++raw) {
        const auto* info = resolver.Get(static_cast<wwz::sandbox::SyscallId>(raw));
        if (info == nullptr || !info->resolved) {
            std::fprintf(stderr, "Syscall resolver returned an incomplete entry.\n");
            return 1;
        }
        std::printf("%s address=%p syscall_number=%u\n",
                    info->name,
                    info->address,
                    info->number);
    }

    return 0;
}
