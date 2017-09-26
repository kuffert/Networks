all: dnsserver httpserver scriptDeployCDN scriptRunCDN scriptStopCDN

dnsserver: dnsserver.cpp
	g++ dnsserver.cpp -o dnsserver

httpserver: httpserver.cpp
	g++ httpserver.cpp -o httpserver

scriptDeployCDN: deployCDN
	 chmod 777 deployCDN

scriptRunCDN: runCDN
	chmod 777 runCDN

scriptStopCDN: stopCDN
	chmod 777 stopCDN

clean:
	\rm dnsserver httpserver
