// CLI implementation: usage stub (Plan 3 Task 1). Real subcommands replace
// this file's body task by task; the exit-code contract (0 handled, 2 usage
// error) stays.
#include "server/cli.hpp"

#include <cstdio>

namespace server {

auto runCli(int argc, char **argv) -> int {
    static_cast<void>(argc);
    static_cast<void>(argv);
    std::fputs("usage: linko-server <command>\n", stderr);
    return 2;
}

} // namespace server
