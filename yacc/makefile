all:
	goyacc -p "ZFP" zonefileParser.y
	go build -o zonefileParser y.go
	./zonefileParser
	sed -i 's/package main/package parser/g' y.go
	sed -i 's/"github.com\/netsec-ethz\/rains\/utils\/zoneFileParser"//' y.go
	sed -i 's/parser.T/T/g' y.go
	sed -i '0,/Lookahead()/{s/Lookahead() int/Lookahead() int\n    Result() []rainslib.MessageSectionWithSigForward/}' y.go
	sed -i 's/func ZFPNewParser()/func (p *ZFPParserImpl) Result() []rainslib.MessageSectionWithSigForward {\n\    return output\n}\nfunc ZFPNewParser()/g' y.go
	mv y.go zoneFileDecoderGenerated.go

clean:
	rm zoneFileDecoderGenerated.go
	rm y.output
	rm zonefileParser