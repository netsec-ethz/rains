# Integration test framework
----------------------------

This binary provides an automated way to run integration tests on a RAINS
system.

It will automatically generate the required configuration files, put them in a
temporary folder along with the required binaries, and run the system. The
system will then be checked for functionality by attempting to publish records
to the servers, and then use rainsdig to query for those records. At the end a
pass/fail is output for easy integration into other testing systems such as CI.
