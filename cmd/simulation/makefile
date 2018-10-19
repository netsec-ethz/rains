all:
	rm -rf zonefiles/*
	rm -rf keys/*
	find conf -type f -not -name 'namingServer.conf' -not -name 'publisher.conf' -not -name 'resolver.conf' -delete
	go run simulation.go

clean:
	rm -rf zonefiles/*
	rm -rf keys/*
	find conf -type f -not -name 'namingServer.conf' -not -name 'publisher.conf' -not -name 'resolver.conf' -delete
