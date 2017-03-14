package rainsd

type cipherSuite string
type publicKey []byte

//zoneKeyCache contains a set of zone public keys
//TODO CFE use a proper cache
var zoneKeyCache map[string]string

//queryCache contains a mapping from all self issued active queries to the set of go routines waiting for it.
var queryCache map[string][]string

//Verify verifies an assertion and strips away all signatures that do not verify. if no signatures remain, returns nil.
//TODO CFE implement properly, be able to process assertions, shard and zones!
func Verify(msg string) string {
	return msg
}

//Delegate adds the given public key to the zoneKeyCache
//TODO CFE implement
func Delegate(context string, zone string, cipher cipherSuite, key publicKey, until int) {

}

//Reap removes expired delegations from the cache
//TODO CFE implement
func Reap() {

}
