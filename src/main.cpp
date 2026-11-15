// linko-server entry point: dispatches to the CLI and exits with its code.
#include "server/cli.hpp"

// Trailing return on main keeps the clang-tidy check (modernize-*) uniform;
// the signature stays the standard one.
auto main(int argc, char **argv) -> int { return server::runCli(argc, argv); }
