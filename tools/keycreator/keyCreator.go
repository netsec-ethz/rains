package keycreator

import (
	"path"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/siglib"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

//Generate creates a new ed25519 public private key pair. It stores the two keys pem encoded to
//privateKeyPath. The private key is encrypted with the default password (empty string). In case the
//subjectName is '@', a self signed delegation assertion is stored in gob format at publicKeyPath.
func Generate(selfSignPath, privateKeyPath, name, zone, context string, phase int) error {
	folder, file := path.Split(privateKeyPath)
	publicKey, err := keyManager.GenerateKey(folder, file, "", algorithmTypes.Ed25519.String(), "", phase)
	if err != nil {
		return err
	}
	if name == "@" {
		privateKey, err := keyManager.DecryptKey(folder, file, "")
		if err != nil {
			return err
		}
		pkey := keys.PublicKey{
			PublicKeyID: keys.PublicKeyID{
				KeySpace:  keys.RainsKeySpace,
				KeyPhase:  phase,
				Algorithm: algorithmTypes.Ed25519,
			},
			Key: ed25519.PublicKey(publicKey.Bytes),
		}
		assertion := &section.Assertion{
			Context:     context,
			SubjectZone: zone,
			SubjectName: name,
			Content:     []object.Object{object.Object{Type: object.OTDelegation, Value: pkey}},
		}
		sig := signature.Sig{
			PublicKeyID: pkey.PublicKeyID,
			ValidSince:  time.Now().Unix(),
			ValidUntil:  time.Now().Add(365 * 24 * time.Hour).Unix(),
		}
		assertion.AddSig(sig)
		ks := map[keys.PublicKeyID]interface{}{pkey.PublicKeyID: ed25519.PrivateKey(privateKey.Bytes)}
		if err := siglib.SignSectionUnsafe(assertion, ks); err != nil {
			return err
		}
		return util.Save(selfSignPath, assertion)
	}
	return nil
}
