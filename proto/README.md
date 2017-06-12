1) Make sure that the GOPATH variable is set. (you can check that with the command: echo $GOPATH)
1.b) To change or set the GOPATH variable use the command: export GOPATH=$(go env GOPATH)
2) To compile the capnproto schema: 
2a) change to the ~/go/rains/ directory 
2b) type cmd: capnp compile -I$GOPATH/src/zombiezen.com/go/capnproto2/std -ogo proto/rainsMsg.capnp