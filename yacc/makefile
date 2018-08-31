all:
	goyacc -p "ZFP" zonefileParser.y
	go build -o zonefileParser y.go
	./zonefileParser

clean:
	rm y.go
	rm y.output
	rm zonefileParser