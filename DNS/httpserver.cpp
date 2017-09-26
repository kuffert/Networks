#include <stdio.h>
#include <stack>
#include <string>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sstream>
#include <ifaddrs.h>
#include <iterator>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <map>

using namespace std;

int port;
std::string origin;
std::string serverIPAddress;
int listenSocket, clientSocket, serverSocket;
int sendSocket;
struct hostent *host;
struct sockaddr_in clientAddr, originStruct, dnsStruct;
int RAMCacheSize = 0;
int discCacheSize = 0;
static int MAX_RAM_CACHE = 10000000;
static int MAX_DISC_CACHE = 10000000;
std::string grabString(std::string source, std::string beginning, std::string end);
std::fstream cachefile;
std::string cachename = "cache.txt";
std::map<std::string, std::string> cacheMap;
std::map<std::string, int> urlHits;
int requests = 0; // Tracks the number of requests received. If it reaches a threshold, reset to 0 and perform cache management
int cacheManageThresh = 50;

fd_set socketSet;

void populateMapFromCache();
std::string locateCachedURL(std::string GETurl);
std::string requestContentFromOriginServer(std::string GETurl);
bool cacheRequestedContents(std::string url, std::string contents);
void purgeCache();
bool decrementPageHits();
void printCachemMapHits();

int openListenSocket(int port);
int openSendSocketAndConnectToOrigin();
int resolveHostname(std::string hostname);

int main(int argc, char **argv)
{
	if (argc != 5)
	{
		printf("Error: invalid number of args\n");
        return 0;
	}
	
	// Set port and origin name
	port = atoi(argv[2]);
	origin = argv[4];
	

	// Attempt to resolve origin hostname
	if (resolveHostname(origin) < 0)
	{
		printf("Failed to resolve origin server.Exiting.\n");
		return 0;
	}

	// Open listening socket to hear incoming GET requests
	listenSocket = openListenSocket(port);
	listen(listenSocket, 5);

	// Set timeout value
	struct timeval timeVal;
	timeVal.tv_sec = 5;
	timeVal.tv_usec = 0;

	// Add request socket to receiving socket set
	fd_set listenSocks;
	FD_ZERO(&listenSocks);
	FD_SET(listenSocket, &listenSocks);

	//populateMapFromCache(); // Not going to be used, most likely

	bool cacheRequest = false; // Wether or not to cache the request

	while (1)
	{
		// Reset time val and set parameters for select
		timeVal.tv_sec = 5;
		timeVal.tv_usec = 0;
		fd_set listenSocks;
		FD_ZERO(&listenSocks);
		FD_SET(listenSocket, &listenSocks);
		cacheRequest = false;

		// Accept incoming connections
		if (select(listenSocket + 1, &listenSocks, NULL, NULL, &timeVal) > 0)
		{
			fflush(stdout);
			int clientLen = sizeof(clientAddr);
			clientSocket = accept(listenSocket, (struct sockaddr *)&clientAddr, (socklen_t *)&clientLen);
			if (clientSocket < 0)
			{
				printf("Error accepting client\n");
				exit(1);
			}

			// Receive connected client's GET request
			char buffer[1000];
			memset(buffer, 0, 1000);
			int receivedData = read(clientSocket, buffer, 1000);
			if (receivedData < 0)
			{
				printf("Failed to receive data from client. Exiting.\n");
				printf("%d\n", errno);
				return 0;
			}

			std::string GETurl = grabString(buffer, "GET ", " HTTP");

			// Check if URL they've request already has cached data
			std::string cachedData = locateCachedURL(GETurl);

			// If it does not, begin requesting that page's data from the origin server
			if (cachedData == "")
			{
				cachedData = requestContentFromOriginServer(GETurl);
				cacheRequest = true;
			}

			// Send the requested data back to the client.
			int clientResponseResult = write(clientSocket, cachedData.c_str(), strlen(cachedData.c_str()));
			if (clientResponseResult < 0)
			{
				printf("Failed to send response to client.\n");
				return 0;
			}
			printf("Sending response to client.\n");
			close(clientSocket);

			// Perform cache management if the threshold of concurrent requests has been received
			requests++;
			if (0 == requests % cacheManageThresh)
			{
				decrementPageHits();
			}

			if (cacheRequest)
			{
				cacheRequestedContents(GETurl, cachedData);
			}
			GETurl.clear();
			cachedData.clear();
			fflush(stdout);
		}
		else
		{
			//printf("cache size: %d\n", RAMCacheSize);
			printCachemMapHits();
			//decrementPageHits();
			fflush(stdout);
			//continue;
		}
	}
	// Close all sockets and shut down the server.
	close(sendSocket);
	close(serverSocket);
	close(listenSocket);
	purgeCache();
	return 0;
}

// open the socket to hear the clients request
int openListenSocket(int port)
{
	listenSocket = -1;
    // Attempt to open socket
    //close(openedSocket);
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0)
    {
        printf("Error: socket failed to open. Exiting.\n");
        close(listenSocket);
        return -1;
    }
    
    // Construct the address structure to bind
	memset(&originStruct, 0, sizeof(originStruct));
    originStruct.sin_port = htons(port);
    originStruct.sin_family = AF_INET;
	//htonl(inet_aton("127.0.0.1", &originStruct.sin_addr));
	originStruct.sin_addr.s_addr = INADDR_ANY;
	//originStruct.sin_addr.s_addr = inet_addr(serverIPAddress.c_str());
    
    // Attempt to bind to port
	int enable = 1;
	if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		printf("Failed to make socket port reusable. Exiting\n");
		close(listenSocket);
		exit(1);
	}
	if (bind(listenSocket, (struct sockaddr *) &originStruct, sizeof(struct sockaddr_in)) < 0)
	{
		printf("Failed to bind socket. Exiting.\n");
		printf("%d\n", errno);
		close(listenSocket);
		exit(1);
	}
    return listenSocket;
}

// open the socket to fulfill the client's request from server
int openSendSocketAndConnectToOrigin()
{
	serverSocket = -1;
	// Attempt to open socket
    //close(openedSocket);
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        printf("Error: socket failed to open. Exiting.\n");
        close(serverSocket);
        return -1;
    }
    host = gethostbyname(origin.c_str());
    if (host == NULL)
    {
        // If the host cannot be found, exit the program.
        printf("Error: host not found. Exiting.\n");
        close(serverSocket);
        return -1;
    }
	    // Construct the address structure to bind
	memset(&originStruct, 0, sizeof(originStruct));
    originStruct.sin_port = htons(8080);
    originStruct.sin_family = AF_INET;
	bcopy((char *)host->h_addr, (char *)&originStruct.sin_addr.s_addr, host->h_length);

    int connectionResult = connect(serverSocket, (const sockaddr *)&originStruct, sizeof(originStruct));
    if (connectionResult < 0)
    {
        printf("Error: failed to establish connection\n");
        close(serverSocket);
		printf("%d\n", errno);
        return -1;
    }
	return serverSocket;
}

// resolves the origin hostname
int resolveHostname(std::string hostname)
{
	host = gethostbyname(hostname.c_str());
	if (host == NULL)
	{
		return -1;
	}

	// Construct the address structure for the DNS host
	bcopy((char *)host->h_addr, (char *)&dnsStruct.sin_addr.s_addr, host->h_length);

	return 1;
}

// Given a prefix and a suffix, find the first occurence of a string between those
// two values within the given block of html.
std::string grabString(std::string source, std::string beginning, std::string end)
{
	std::size_t beginningLoc = source.find(beginning);
	if (beginningLoc == std::string::npos)
	{
		return "";
	}
	beginningLoc += beginning.length();
	std::string::size_type endLoc = source.find(end, beginningLoc);
	return source.substr(beginningLoc, endLoc - beginningLoc);
}

// Reads from the cache of URL data and populate the local map of cached data
void populateMapFromCache()
{
	cachefile.open(cachename.c_str(), ios::in);

	// READ IN THE FILE
	// POPULATE MAP WITH <URL, HTML> PAIRS
	// CLOSE FILE

	cachefile.close();
}

// Search the local cache map to find URL match. Return data if found.
std::string locateCachedURL(std::string GETurl)
{
	if (cacheMap.count(GETurl) > 0)
	{
		// Update cached URL hits
		int hits = urlHits[GETurl] + 1;
		urlHits[GETurl] = hits;
		return cacheMap[GETurl];
	}
	else return "";
}

// Requests the client's request from the origin server, since we do not have it cached
std::string requestContentFromOriginServer(std::string GETurl)
{
	serverSocket = openSendSocketAndConnectToOrigin();
	if (serverSocket < 0)
	{
		exit(1);
	}
	printf("No cached data found, connected to origin server.\n");

	// Send get request to origin server to receive data
	char originGetRequest[1000];
	memset(originGetRequest, 0, 1000);
	sprintf(originGetRequest, "GET %s HTTP/1.0\r\nHost: %s:8080\r\nConnection: keep-alive\r\n\r\n", GETurl.c_str(), origin.c_str());
	int sendResult = write(serverSocket, originGetRequest, strlen(originGetRequest));
	if (sendResult < 0)
	{
		printf("Failed to send GET request. Need to alert requester.\n");
		exit(1);
	}

	// Receive origin server get request response
	char originGETResult[100000];
	memset(originGETResult, 0, 100000);
	int rec = 0;
	do {
		int receiveResult = recv(serverSocket, &originGETResult[rec], sizeof(originGETResult) - rec, 0);
		if (receiveResult == 0)
		{
			// No more data to receive
			break;
		}
		if (receiveResult < 0)
		{
			printf("Failed to receive response from GET request. Need to alert requester.\n");
			exit(1);
		}
		else
		{
			rec += receiveResult;
		}
	} while (1);

	std::string result(originGETResult);
	close(serverSocket);
	return result;
}

// cache contents received from origin server, if we do not yet have them, and we have room in our cache.
// returns true if contents were cached, false otherwise.
/// DO NOT CACHE PAGES THAT DO NOT RETURN A 200 OK
bool cacheRequestedContents(std::string url, std::string contents)
{
	std::size_t found404 = contents.find("404 Not Found");
	if (found404 != std::string::npos)
	{
		printf("Page not found, not cacheing contents.\n");
		return false;
	}

	// If there is enough room in the cache...
	if ((RAMCacheSize + url.size() + contents.size()) < MAX_RAM_CACHE)
	{
		// Cache
		cacheMap[url] = contents;
		RAMCacheSize += contents.size() + url.size();

		// Cache Manager
		urlHits[url] = 1;

		return true;
	}

	// If there is not enough room in the cache...
	else
	{
		if (cacheMap.size() <= 0)
		{
			return false;
		}
		// decrement the hits on each page by 1, remove any at 0
		bool itemRemoved = decrementPageHits();
		cacheRequestedContents(url, contents);
	}
	return false;
}

// Purge cache of all contents, and wipe all hits from the manager
void purgeCache()
{
	cacheMap.clear();
	urlHits.clear();
	RAMCacheSize = 0;
}

// Decrements the number of hits on every cached URL. If an item has 0 hits afterwards, delete it.
// If an item is deleted, this function returns true.
bool decrementPageHits()
{
	bool itemDeleted = false;
	typedef std::map<std::string, int>::iterator it_type;
	for (it_type iterator = urlHits.begin(); iterator != urlHits.end(); iterator++) {
		int hits = iterator->second - 1;
		if (hits <= 0)
		{
			int sizeOfCachedData = 0;
			sizeOfCachedData = ((int)(cacheMap[iterator->first].size()) + ((int)(iterator->first).size()));
			RAMCacheSize -= sizeOfCachedData;
			urlHits.erase(iterator);
			cacheMap.erase(iterator->first);
			itemDeleted = true;
		}
		else
		{
			urlHits[iterator->first] = hits;
		}
	}
	return itemDeleted;
}

// Used for debugging. Prints number of hits for each URL in the cache
void printCachemMapHits()
{
	typedef std::map<std::string, int>::iterator it_type;
	for (it_type iterator = urlHits.begin(); iterator != urlHits.end(); iterator++) {

		printf("URL: %s | hits: %d\n", iterator->first.c_str(), iterator->second);
	}
	printf("Total Cache Data: %d\n", RAMCacheSize);
}
