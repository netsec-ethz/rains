package borat

const (
	TagDateTimeString = 0
	TagDateTimeEpoch  = 1
	TagURI            = 32
	TagBase64URL      = 33
	TagBase64         = 34
	TagUUID           = 37
)

type CBORTag uint

const (
	majorUnsigned = 0x00
	majorNegative = 0x20
	majorBytes    = 0x40
	majorString   = 0x60
	majorArray    = 0x80
	majorMap      = 0xa0
	majorTag      = 0xc0
	majorOther    = 0xe0
	majorMask     = 0x1f
	majorSelect   = 0xe0
)
