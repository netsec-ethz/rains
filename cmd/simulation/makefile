all:
	rm -r zonefiles/*
	rm -r keys/*
	find conf -type f -not -name 'namingServer.conf' -not -name 'publisher.conf' -not -name 'resolver.conf' -delete
	go run simulation.go

clean:
	rm -r zonefiles/*
	rm -r keys/*
	find conf -type f -not -name 'namingServer.conf' -not -name 'publisher.conf' -not -name 'resolver.conf' -delete
