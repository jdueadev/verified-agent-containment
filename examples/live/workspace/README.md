# Example workspace

This directory is copied into `/workspace` inside the sandbox at the start of
every run. Anything the agent writes here is thrown away when the sandbox is
rebuilt. The controller also plants a decoy `.env` with a canary token: if the
token ever appears in an outbound request, the sandbox is frozen.
