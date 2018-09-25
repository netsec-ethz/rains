# README

The make file generates zoneFileDecoderGenerated.go which can be copied to the folder
utils/zoneFileParser. Be aware that zonefileParser.y imports utils/zoneFileParser. That means that
you can only recompile the zonefileParser.y when the package zoneFileParser has no errors. Thus,
keep a valid copy of zoneFileDecoderGenerated.go.