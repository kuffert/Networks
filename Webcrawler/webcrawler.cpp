#include <stdio.h>
#include <stack>
#include <string>
#include <string.h>
#include <strings.h>
#include <unistd.h>
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

std::string visited;
std::stack<std::string> frontier;
int connectionResult;
struct hostent *host;
sockaddr_in addressStruct;
int openedSocket;
char* user;
char* pass;
char* csrfToken;
char* sessionId;

int keysFound = 0;

char currentHTMLChunk[2500];

int getToken(int socket, const char* url);
int getHTML(int socket, const char* url, char* currentHTMLChunk);
char* login(int socket, char* user, char* pass, char* token, char* sessionId);
std::string grabString(std::string source, std::string beginning, std::string end);
int openSock();
int parseHTMLForLinks(char* html);
char* checkForSecretFlags(char* html);
bool validateLink(std::string link);
void grabNewLocationURL(char* html);

int main(int argc, char **argv) {

    // Begin the crawl only if the nuid and password are given.
    if (argc != 3)
    {
        printf("Error: invalid number of args\n");
		return 0;
    }

	visited.clear();
	memset(currentHTMLChunk, 0, 2500);
	openedSocket = openSock();
	getToken(openedSocket, "GET /accounts/login/?next=/fakebook/ HTTP/1.0\r\nHost: cs5700f16.ccs.neu.edu\r\nConnection: Keep-Alive\r\n\r\n");
	openedSocket = openSock();
	sessionId = login(openedSocket, argv[1], argv[2], csrfToken, sessionId);
	const char* getFormat = "GET /fakebook/ HTTP/1.0\r\nHost: cs5700f16.ccs.neu.edu\r\nCookie:sessionid=%s\r\nConnection: Keep-Alive\r\n\r\n";
	char get[1024];
	memset(get, 0, 1024);
	sprintf(get, getFormat, sessionId);
	openedSocket = openSock();
	int htmlCode = getHTML(openedSocket, get, currentHTMLChunk);
	if (htmlCode != 200)
	{
		printf("Error: Did not get 200 from homepage get request, instead got: %d. Exiting.\n", htmlCode);
		return 0;
	}
	
	int urlsvisited = 0;

	// Begin crawling through the initial stack of URLs, popping them,
	// parsing their contents for more links or secret flags, then continuing.
	
	/*
	do
	{
		// Abort the crawler if all keys have been found.
		if (keysFound >= 5)
		{
			break;
		}
		
		// Open a new socket for this get request.
		openedSocket = openSock();

		// Abort the crawler if the server severs the connection
		if (openedSocket == -1)
		{
			printf("Error: Server has severed connection. Aborting crawler.");
			break;
		}

		// Pops the next URL to parse
		std::string nextURL = frontier.top();
		frontier.pop();

		if (std::string::npos != visited.find(nextURL))
		{
			continue;
		}
		
		visited += nextURL;

		// Format the get request for the next URL to crawl.
		const char* getFormat = "GET %s HTTP/1.0\r\nHost: cs5700f16.ccs.neu.edu\r\nCookie:sessionid=%s\r\nConnection: Keep-Alive\r\n\r\n";
		char get[1024];
		memset(get, 0, 1024);
		sprintf(get, getFormat, nextURL.c_str(), sessionId);

		// Submit the get request and retrieve the response code.
		int htmlCode = getHTML(openedSocket, get, currentHTMLChunk);

		// If the server responds with a 500, push the current URL back
		// onto the stack to be reattempted.
		if (htmlCode == 500)
		{
			openedSocket = openSock();
			if (validateLink(nextURL))
			{
				frontier.push(nextURL);
			}
		}
		urlsvisited++;

	} while (!frontier.empty());
	*/
	visited.clear();
	close(openedSocket);
	return 0;
}

// Submits a get request to the server, then saves the csrftoken and sessionId from the
// server's response.
int getToken(int socket, const char* url)
{
    int writeResult = write(socket, url, strlen(url));
    if (writeResult < 0)
    {
        printf("Error: Failed to write. Exiting.\n");
        close(socket);
        return 0;
    }
    char html[2500];
    memset(html, 0, 2500);
    int readResult = read(socket, html, 2500);
    if (readResult < 0)
    {
        printf("Error: Failed to read. Exiting.\n");
        close(socket);
        return 0;
    }
    std::string htmlString(html);
    csrfToken = strdup(grabString(htmlString, "csrftoken=", "; expires=").c_str());
    sessionId = strdup(grabString(htmlString, "sessionid=", "; expires=").c_str());
    return 1;
}

// Submits a get request to the server, then searches the response for any more links, returning
// the server's response code. 
int getHTML(int socket, const char* url, char* currentHTMLChunk)
{
    int writeResult = write(socket, url, strlen(url));
    if (writeResult < 0)
    {
        printf("Error: Failed to write. Exiting.\n");
        close(socket);
        return 0;
    }
    memset(currentHTMLChunk, 0, 2500);
    int readResult = read(socket, currentHTMLChunk, 2500);
    if (readResult < 0)
    {
        printf("Error: Failed to read. Exiting.\n");
        close(socket);
        return 0;
    }
	return parseHTMLForLinks(currentHTMLChunk);
}

// Constructs a post request to the server, and update the sessionId from the server's response.
char* login(int socket, char* user, char* pass, char* token, char* sessionId)
{
    const char* postFormat = "POST /accounts/login/ HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: csrftoken=%s; sessionid=%s\r\nContent-Length: %d\r\nHost: cs5700f16.ccs.neu.edu\r\nConnection: Keep-Alive\r\n\r\nnext=/fakebook/&username=%s&password=%s&csrfmiddlewaretoken=%s\r\n\r\n";
    char post[1024];
    memset(post, 0, 1024);
    sprintf(post, postFormat, token, sessionId, (strlen("next=/fakebook/") + strlen("&username=") + strlen(user) + strlen("&password=") + strlen(pass) + strlen("&csrfmiddlewaretoken=") + strlen(token)), user, pass, token);
    int writeResult = write(socket, post, strlen(post));
    if (writeResult < 0)
    {
        printf("Error: Failed to write. Exiting.\n");
        close(socket);
        return 0;
    }
    char html[2500];
    memset(html, 0, 2500);
    int readResult = read(socket, html, 2500);
    if (readResult < 0)
    {
        printf("Error: Failed to read. Exiting.\n");
        close(socket);
        return 0;
    }
    std::string htmlString(html);
    sessionId = strdup(grabString(htmlString, "sessionid=", "; expires=").c_str());
    return sessionId;
}

// Given a prefix and a suffix, find the first occurence of a string between those
// two values within the given block of html.
std::string grabString( std::string source, std::string beginning, std::string end )
{
    std::size_t beginningLoc = source.find(beginning);
    if(beginningLoc == std::string::npos )
    {
        return "";
    }
    beginningLoc += beginning.length();
    std::string::size_type endLoc = source.find(end, beginningLoc);
    return source.substr(beginningLoc, endLoc - beginningLoc);
}

// Closes the currently opened socket, then reopens and reconnects through a new one.
int openSock()
{
    // Attempt to open socket
	close(openedSocket);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("Error: socket failed to open. Exiting.\n");
        close(sock);
        return -1;
    }
    host = gethostbyname("cs5700f16.ccs.neu.edu");
    if (host == NULL)
    {
        // If the host cannot be found, exit the program.
        printf("Error: host not found. Exiting.\n");
        close(sock);
        return -1;
    }
    
    // Construct the address structure to pass into connect
    addressStruct.sin_port = htons(80);
    addressStruct.sin_family = AF_INET;
    bcopy((char *)host->h_addr, (char *)&addressStruct.sin_addr.s_addr, host->h_length);
    
    // Attempt to connect to the given host on the specified port.
    connectionResult = connect(sock, (const sockaddr *)&addressStruct, sizeof(addressStruct));
    if (connectionResult < 0)
    {
        printf("Error: failed to establish connection\n");
		close(sock);
        return -1;
    }
    return sock;
}

// Parses the given html and puts any links found onto the stack, then returns the response code. 
int parseHTMLForLinks(char* html)
{
	std::string htmlString(html);

	std::string responseKeyword = "HTTP/1.1 ";
	std::string responseEndword = "Date";
	
	std::string responseCode = grabString(htmlString, responseKeyword, responseEndword);
	printf(responseCode.c_str());

	// The prefix and suffix to search for.
	std::string hrefKeyword = "href=\"";
	std::string endKeyword = "\">";
	

	// Handles a 301 or a 302 response from the server
	std::size_t error301 = htmlString.find("301 MOVED PERMANENTLY");
	std::size_t error302 = htmlString.find("302 FOUND");
	if (error302 != std::string::npos || error301 != std::string::npos)
	{
		checkForSecretFlags(html);
		grabNewLocationURL(html);
		return 302;
	}

	// Handles a 403 or 404 response from the server
	std::size_t error404 = htmlString.find("404 NOT FOUND");
	std::size_t error403 = htmlString.find("403 FORBIDDEN");
	if (error404 != std::string::npos && error403 != std::string::npos)
	{
		checkForSecretFlags(html);
		return 404;
	}
	
	// Handles a 500 Server error response from the server
	std::size_t error500 = htmlString.find("500 INTERNAL SERVER ERROR");
	if (error500 != std::string::npos)
	{
		checkForSecretFlags(html);
		return 500;
	}

	// Handles a 200 OK response from the server
	std::size_t okStatus = htmlString.find("200 OK");
	if (okStatus != std::string::npos)
	{
		checkForSecretFlags(html);

		do
		{
			// If the prefix denoting a link is found, grab it. Otherwise, 
			// end the search.
			std::size_t hrefIndex = htmlString.find(hrefKeyword);
			if (hrefIndex == std::string::npos)
			{
				break;
			}

			std::string link = grabString(htmlString, hrefKeyword, endKeyword);

			// If the found link is valid, add it to the stack.
			if (validateLink(link))
			{
				frontier.push(link);
			}

			// Update the htmlString to be everything following the occurence of the last link found.
			htmlString = htmlString.substr(hrefIndex - 2 + strlen(hrefKeyword.c_str()) + strlen(link.c_str()) + strlen(endKeyword.c_str()), strlen(htmlString.c_str()));
		} while (1);

		return 200;
	}
	else
	{
		return -1;
	}
}

// Checks for, and prints out, any secret flags that are found in this chunk of html. 
char* checkForSecretFlags(char* html)
{
	std::string htmlString(html);
	std::string secretFlagKeyword = "FLAG: ";
	std::string endKeyword = "</h2>";

	do
	{
		// If the prefix denoting a secret flag is found, print out that 
		// flag. Otherwise, end the search.
		std::size_t secretFlagIndex = htmlString.find(secretFlagKeyword);
		if (secretFlagIndex == std::string::npos)
		{
			break;
		}

		std::string secretFlag = grabString(htmlString, secretFlagKeyword, endKeyword);
		keysFound++;
		printf("%s\n", secretFlag.c_str());

		// Update the htmlString to be everything following the occurence of the last flag found.
		htmlString = htmlString.substr(secretFlagIndex -2 + strlen(secretFlagKeyword.c_str()) + strlen(secretFlag.c_str()) + strlen(endKeyword.c_str()), strlen(htmlString.c_str()));
	} while (1);
}

// Determines if the given link is a valid link.
bool validateLink(std::string link)
{
	return std::string::npos != link.find("fakebook"); 
}

// Grabs the location to travel to next if a 301 is given.
void grabNewLocationURL(char* html)
{
	std::string link = grabString(html, "Location ", "Content-Length");
	if (validateLink(link))
	{
		frontier.push(link);
	}
}