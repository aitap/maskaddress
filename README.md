MaskAddress
===========

What is this?
-------------

MaskAddress is an experimental little program to make a TCPv4 service
(`host:port`) look like it's available on a different address
(`host:port`) to a Windows machine. This is done by rewriting TCP
packets with destination matching "new" address and source matching
"old" address. Matching is done statelessly, so the "old" address becomes
inaccessible, since reply packets from attempting to connect to it would
be rewritten as if they were from the new address.

How to use it?
--------------

All configuration is done in compile-time using C preprocessor `#define`s:

 * `MASKADDR_FROM` should be a C string literal containing an IPv4
   address of the host that should appear to the operating system as the
   masked service
 * `MASKADDR_FROM_PORT` should be a C integer literal containing the port
   number that should respond as the masked service
 * `MASKADDR_TO` should be a C string literal containing an IPv4 address of
   the host to be masked
 * `MASKADDR_TO_PORT` should be a C integer literal containing the port
   number of the service to be masked

Use the provided Makefile parameters `FROM`, `FROMPORT`, `TO`, `TOPORT`
(no quoting needed in this case only), set them on the compiler command
line using the `-D` switch (don't forget to quote the C double quotes),
or edit the `maskaddr.c` file.

As a result, any request to `MASKADDR_FROM:MASKADDR_FROM_PORT` would be
transparently redirected to `MASKADDR_TO:MASKADDR_TO_PORT`, and packets
sent from `MASKADDR_TO:MASKADDR_TO_PORT` would be transparently rewritten
as if coming from `MASKADDR_FROM:MASKADDR_FROM_PORT`.

Run the executable with a single command line argument `-install`
to register it as a service, or `-uninstall` to remove the service;
check `%ERRORLEVEL%` to see if installation was successful. Use `sc
<start|stop|query> MaskAddress` to control the service. When installing,
the service with the same name must not already exist; when uninstalling,
the service must be stopped. Run the executable without command line
arguments to perform the masking in a standalone process.

### Loopback address as destination ###

If the actual and the mask address reside in subnets accessible by
different routes, the masking may not work. For example, this may happen
if `FROM` is somewhere accessible via default route while `TO` is a
loopback address. The proper fix for this would be to set the source and
destination addresses in rewritten packets based on the routing table,
but in lieu of that, here are the available workarounds:

 * `#define MASKADDR_TO_LOOPBACK 1` to remember the original local
   address, but set source and destination addresses to a loopback address
   where applicable
 * Only use `MASKADDR_FROM` and `MASKADDR_TO` accessible
   via the same route
