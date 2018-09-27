package encoder

import (
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

//SignatureFormatEncoder is used to deterministically transform a Message or Section into a
//byte string that is ready for signing.
type SignatureFormatEncoder interface {
	//EncodeMessage transforms the given msg into a signable format.The signature meta data
	//must be present on the section. This method does not check for illegitimate content. The
	//returned byte string is ready for signing.
	EncodeMessage(msg *message.Message) []byte

	//EncodeSection transforms the given section into a signable format. The signature meta data
	//must be present on the section. This method does not check for illegitimate content. The
	//returned byte string is ready for signing.
	EncodeSection(section section.WithSig) []byte
}
