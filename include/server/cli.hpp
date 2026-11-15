// linko-server command-line interface: the single entry point the main
// executable dispatches to. Subcommands grow with the plan (invite/device/
// user management in Plan 3 Task 3, `run` in Task 4, calls analytics in
// Task 9, cert generate in Task 10); until then everything prints usage.
#pragma once

namespace server {

// Runs one CLI invocation (without the program name). Returns the process
// exit code: 0 on a handled command, 2 on usage errors - the documented
// "bad arguments" exit code for this program.
auto runCli(int argc, char **argv) -> int;

} // namespace server
