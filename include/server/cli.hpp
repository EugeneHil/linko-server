// linko-server command-line interface (design spec 4.5): invite/user/device
// administration against the server's data directory. Secrets - the invite
// code, generated certificates - are printed exactly once, to stdout.
// Subcommands grow with the plan (`run` in Task 4, calls in Task 9, cert in
// Task 10). Exit codes: 0 handled, 1 runtime error, 2 usage error.
#pragma once

namespace server {

// Runs one CLI invocation (without the program name). Returns the process
// exit code.
auto runCli(int argc, char **argv) -> int;

} // namespace server
