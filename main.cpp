//#undef UNICODE

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#define DEFAULT_PORT "12345"
#define DEFAULT_BUFLEN 512

SOCKET CreateSocket(struct addrinfo* sa);
void* get_in_addr(struct sockaddr* sa);
DWORD WINAPI ClinetHandler(LPVOID Param);

int __cdecl main(void)
{
	WSADATA wsadata;
	/* Server uses Listen Socket to accepts connections and
	create Clients Sockets */
	SOCKET ListenSocket = INVALID_SOCKET,
		ClientSocket = INVALID_SOCKET;
	/* Normal BSD sockets arguments, res / hints (ptr is defined in
	CreateSocket function) */
	struct addrinfo* result = NULL,
		hints;

	/* Store source address of connection accepted by accept() */
	struct sockaddr_storage their_addr;
	int iResult = 0;

	/* strings used to store ip address and port numbers extracted from
	sockaddr_storage structures */
	char ipstr[NI_MAXHOST],
		portstr[NI_MAXSERV];
	socklen_t sin_size = sizeof(their_addr);

	/* Variables used to handle the threading tasks */
	DWORD ThreadID;
	HANDLE ThreadHandle;

	/* Starting WSA to create our sockets */
	iResult = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (iResult != 0) {
		printf("$ WSAStartup() failed: %d\n", iResult);
		ExitProcess(1);
	}

	/* Filling the required info into hints to use it in getaddrinfo()
	as our chosen options */
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;					/* IPv4 */
	hints.ai_socktype = SOCK_STREAM;			/* TCP */
	hints.ai_protocol = IPPROTO_TCP;			/* IP */
	hints.ai_flags = AI_PASSIVE;				/* Use Host (Current machine) address */

	/*
	*	getaddrinfo() return a linked list of addrinfo structs
	*	which we will test to create our socket and bind it to 
	*	the required port.
	*/
	iResult = getaddrinfo(0, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("$ getaddrinfo() failed: %d\n", iResult);
		WSACleanup();
		ExitProcess(1);
	}

	/* Launching our CreateSocket to handle the socket creation and binding tasks */
	ListenSocket = CreateSocket(result);
	/* free the linked list (*result), we don't need it if the created succesfully */
	freeaddrinfo(result);

	/* Start listening on ListenSocket with maximum alllowed queue length
	specisfied by listen */
	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
		printf("$ listen() failed: %ld\nClosing connection...\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		ExitProcess(1);
	}

	/*
	*	Infinite loop until one of our conditions happended.
	*	We accept any comming connectionm then use getnameinfo() to get client (source)
	*	address and port number, then we create a thread and pass it the new ClientSocket
	*	which is connected to the client, the thread will handle the connection with client
	*	and we move on to the next loop to accept another connection and so on....
	*/
	while (TRUE)
	{
		/* Here our socket is in blocking so we will not move until accept() returns,
		it will return a SOCKET which is connected to the source of the accepted connection
		(the client), and save the client address information into (their_addr) after it had 
		casted from sockaddr_storage to sockaddr */
		ClientSocket = accept(ListenSocket, (struct sockaddr*)&their_addr, &sin_size);
		if (ClientSocket == INVALID_SOCKET) {
			printf("$ accept() failed: %ld\nClosing connection...\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			ExitProcess(1);
		}

		/* getnameinfo() extract the source ip addr. and port no. from thier_addr struct
		after being casted to sockaddr */
		iResult = getnameinfo((struct sockaddr*)&their_addr, sin_size, ipstr,
			sizeof(ipstr), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);

		printf("[+] accept(): Accepted connection from %s:%s\n", ipstr, portstr);

/*
*	Another method to extract the source ip address and port number:
*		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof(s));
*		printf("Got connection from %s", s);
*/

		ThreadHandle = CreateThread(NULL, 0, ClinetHandler, &ClientSocket, 0, &ThreadID);
		if (ThreadHandle == NULL) {
			printf("$ CreateThread() failed: %ld\n[*] Failed to handle connection from client",
				GetLastError());

			if (iResult == 0)
				printf("%s:%s", ipstr, portstr);

			closesocket(ClientSocket);
		}
	}

	closesocket(ListenSocket);
	WSACleanup();
	ExitProcess(0);
}

/*
	Our function to handle the tests of the linked lists returned
	by getaddrinfo() (* res), then if a member of the list worked
	it will be returned type (SOCKET) to use it.
*/
SOCKET CreateSocket(struct addrinfo* result) {
	struct addrinfo* ptr = NULL;
	SOCKET ListenSocket = INVALID_SOCKET;
	int iResult = 0;
	char yes = TRUE;

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		/* Create a socket with the given info from the current value of (* ptr) */
		ListenSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ListenSocket == INVALID_SOCKET) {
			printf("$ socket() failed: %ld\n", WSAGetLastError());
			/* failure in socket() is not critical and we can test the next one */
			continue;
		}

		/* Set SO_REUSEADDR option to the created socket, to use the chosen port safely */
		/*
		*  Fro better security use the SO_EXCLUSIVEADDRUSE option, which requires admin
		*  previliges on windows.
		*  setsockopt(ListenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &yes, sizeof(char))
		*/
		if (setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(char)) == -1) {
			/* failure in setsockopt() is critical and it's worthless to test others */
			printf("$ setsockopt() failed: %ld\nClosing connection...\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			ExitProcess(1);
		}

		/* Binding the created socket to the port we entered to getaddrinfo() */
		iResult = bind(ListenSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			/* failure in bind() is not critical and we can test the next one */
			printf("$ bind() failed: %d\n", WSAGetLastError());
			continue;
		}
		break;
	}

	/* if ptr == NULL this means the for loop ended without creating a valid socket
	or failed to bind any of the created sockets to the required port */
	if (ptr == NULL) {
		printf("$ Couldn't open a socket\n");
		WSACleanup();
		ExitProcess(1);
	}

	return ListenSocket;
}

/*
*	Our function to extract the ip address from the sockaddr_strorage structure when
*	cast it to sockaddr structure
*/
void* get_in_addr(struct sockaddr* sa) {
	/* if the family of the given address is AF_INET, then it's an IPv4 address and
	we should use sockaddr_in to extract the sin_addr which is the address 
	in network bytes order */
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	/* else means it's AF_INET6 wich is IPv6, so we will use sockaddr_in6 to
	extract sin6_addr which is the address in network byte order */
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*
*	The function which we will create threads from to handle clients connection
*	(one thread : one client) a single thread per a single client (accepted connection)
*	it contains one buffer because this is just an echo server, any received message
*	will be sent back to the sender as is. If any emty message recived this means the
*	connection closed with the client, and we should end the loop, close the socket
*	and exit the thread.
*/
DWORD WINAPI ClinetHandler(LPVOID Param) {
	/* Save the received parameter in a local variable to keep use it freely and
	without being affected by any change out of the thread */
	SOCKET ClientSocket = *(SOCKET*)Param;

	/* Our storage structure to save the address returned by getpeername()
	which is the address of the client */
	struct sockaddr_storage their_addr;
	int iSendResult, iReceiveResult, iResult;

	/* The receive buffer which will contain the received messagem, then used to
	send as a message, finally flushed to be used in the next loop */
	char sRecvBuf[DEFAULT_BUFLEN],
		ipstr[NI_MAXHOST], portstr[NI_MAXSERV];
	int iRecvBufLen = DEFAULT_BUFLEN;
	socklen_t sin_size = sizeof(their_addr);
	char cExitCode = 0;

	/* getpeername() to get the address information of the client, and save them in their_addr.
	Then extarct the source ip address and source port number by getnameinfo() */
	getpeername(ClientSocket, (struct sockaddr*)&their_addr, &sin_size);
	iResult = getnameinfo((struct sockaddr*)&their_addr, sin_size, ipstr, sizeof(ipstr), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
	if (iResult == 0)
		printf("[+] CreateThread(): Created ClientHanlder thread succefully for the connection with %s:%s", ipstr, portstr);

	do {
		/* Flush (Zeroing) the receive buffer, to use safely */
		ZeroMemory(sRecvBuf, iRecvBufLen);
		/* recv() saves the received message in the received buffer and return the sizeof it in bytes */
		iReceiveResult = recv(ClientSocket, sRecvBuf, iRecvBufLen, 0);

		/* Only operate when the recived message isn't an empty message.
		Else break the loop, close the connectin and the thread. */
		if (iReceiveResult > 0) {
			printf("\n> Message received:\n%s\nBytes received: %d\n", sRecvBuf, iReceiveResult);

			/* send() use the data in the received buffer as the message to send, and returns the
			count of data sent in bytes. */
			iSendResult = send(ClientSocket, sRecvBuf, (int)strlen(sRecvBuf), 0);
			if (iSendResult == SOCKET_ERROR) {
				printf("$ send() failed: %ld\nClosing connection...\n", WSAGetLastError());
				cExitCode = 1;
				break;
			}
			printf("\n> Message sent:\n%s\nBytes sent: %d\n", sRecvBuf, iSendResult);
			continue;
		}

		else if (iReceiveResult == 0) {
			printf("\n$ Empty message received.\n$ Closing connection...\n\n");
			break;
		}

		else	{
			printf("$ recv() failed: %d\nConnection", WSAGetLastError());
			if (iResult == 0) {
				printf(" with %s:%s ", ipstr, portstr);
			}

			printf(" is closing...\n\n");
			cExitCode = 1;
			break;
		}
		break;
	} while (TRUE);

	/* Start the procedure of closing the connection with client by shuting down the sending side,
	*  then waits in an recv loop until zero bytes returned over the connection.
	*  Then close the socket safely, and exit the thread with last value of exit code. */
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("$ shutdown() failed: %ld\nClosing connection...\n", WSAGetLastError());
		cExitCode = 1;
	}

	printf("[+] shudown(): connection with client %s:%s shuteddown on SD_SEND\n", ipstr, portstr);
	printf("> starting the recv loop to close the connection safely...\n");
	while (iReceiveResult > 0) {
		iReceiveResult = recv(ClientSocket, sRecvBuf, iRecvBufLen, 0);
	}

	closesocket(ClientSocket);
	printf("[+] closesocket(): ended the recvloop and closed the client %s:%s socket safely\n", ipstr, portstr);
	printf("[+] ExitThread(): exiting the client %s:%s thread...\n\n", ipstr, portstr);
	/* In our case the exit code doesn't matter, because the main htread isn't waiting it or used any AsynchIO
	to handle the joining of Client Handlers. */
	ExitThread(cExitCode);
}