Generated Linux launchers live here. Run the repository's `make build-stubs`
on the test/build server before building a production authgo-pack. Both amd64
and arm64 ELF launchers are embedded. Generated binaries are not source files.
The README keeps the embed glob valid when unit tests run without toolchains;
unit tests inject a synthetic ELF, never claim it is a runnable launcher.
