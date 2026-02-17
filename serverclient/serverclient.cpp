#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>	// OutputDebugString
#else
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <fstream>      // std::ofstream
#include <chrono>

#include"shared/file.h"
#include"shared/output.h"
#include"shared/math.h"
#include"shared/time.h"
#include"shared/std_ext.h"
#include"shared/net.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "socketservertls.h"

class Server : public SocketServerTLS {
	public:
		virtual bool OnConnected(ConnectedSocket* socket){ return true; }
		virtual bool OnDataTLS(ConnectedSocket* socket,void* ssl,char* data,int dataByteSize) {
			char buf[1024];
			memcpy(buf,data,dataByteSize);
			buf[dataByteSize]=0;
			uprintf("Server::OnData %s\n",buf);
			buf[1]='O';
			Send(ssl,buf,dataByteSize);
			return true;
		}
		virtual void OnClose(ConnectedSocket* socket){}
		virtual void OnEvent(ConnectedSocket** sockets,int num_sockets){}
		virtual void OnDestroy(ConnectedSocket* socket){}
};

class Client : public SocketClientTLS {
	public:
		virtual void OnConnected(){}
		virtual bool OnData(const void* data,int dataByteSize){
			uprintf("Client::OnData %s\n",data);
			return true;
		}
		virtual bool OnClose(){ return true; }
		virtual void OnTimer(){}
		void SendPing() {
			static int cnt=0;
			std::string s=stdx::format_string("PING %d",cnt++);
			Send(s.c_str(),(int)s.size()+1);
		}
};

class Viewer{
	public:
	void End();
	void Begin();
	void Run();
	protected:
};

void Viewer::Begin() {
	SSL_library_init();
	OpenSSL_add_all_algorithms();

}
void Viewer::End() {
}

std::atomic<bool> g_close={false};

void Viewer::Run() {
#if 0
	int tlsserver_select(int port_num, const char* certificateFilename, const char* privateKeyFilename);
	int tlsserver(int port_num,const char* certificateFilename,const char* privateKeyFilename);
	int tlsclient(const char* hostname,int port_num);
	int tcpserver(int port_num);
	int tcpclient(const char* hostname,int port_num);
	std::thread serverThread=std::thread([&]{
		std::string cert=GetFileNameRemap("$(DATA)/my_x509.pem");
		std::string key=GetFileNameRemap("$(DATA)/my_private_key.pem");
		//tlsserver(1234,cert.c_str(),key.c_str());
		tlsserver_select(1234,cert.c_str(),key.c_str());
	});
	std::this_thread::sleep_for(std::chrono::milliseconds(500));			//Wait for server to start
	//tcpclient("127.0.0.1",1234);
	tlsclient("127.0.0.1",1234);
	g_close=true;
	serverThread.join();
#else
	Server server;
	Client client;
	server.LoadCertificates("$(DATA)/my_x509.pem","$(DATA)/my_private_key.pem");
	server.Begin("127.0.0.1",1234,10000);
	//server.Begin("127.0.0.1",1234,10000);
	client.EnableNonBlockingConnect();
	//client.Begin("127.0.0.1",1234,0);
	client.Begin("127.0.0.1",1234,0);
	for(int i=0;i!=10;i++){
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		client.SendPing();
	}
	client.End();
	server.End();
#endif
}

void PrintCallback(const char* str) {
#ifdef _WIN32
	OutputDebugString(str);
#else
	::printf("%s",str);
#endif
}

int main(){
	SetPrintCallback(PrintCallback);
#ifdef CMAKE_SOURCE_DIR
	AddFilePathRemap("$(DATA)",std::string(CMAKE_SOURCE_DIR)+"/data");
#else
	AddFilePathRemap("$(DATA)",GetExecutablePath()+"/data");
#endif
	InitSockets();
	Viewer d;
	d.Begin();
	d.Run();
	d.End();
	EndSockets();
	return 0;
}

#ifdef _WIN32
#undef APIENTRY
#include<windows.h>
#include"debugapi.h"
#include<crtdbg.h>
int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,PSTR lpCmdLine,INT nCmdShow){
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_LEAK_CHECK_DF);
	//_CrtSetBreakAlloc(167);
	return main();
}
#endif


















#ifndef _WIN32
void closesocket(int h) {
	close(h);
}
#define SOCKET int
#endif

#define BUFFER_SIZE     1024

// Add a maximum concurrent clients limit
#define MAX_CLIENTS 30

// Structure to keep track of active connections
struct ClientContext {
    SOCKET fd;
    SSL* ssl;
};

int tlsserver_select(int port_num, const char* certificateFilename, const char* privateKeyFilename) {
    char msg_buf[BUFFER_SIZE];
    int rc;

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr) {
        uprintf("Unable to create SSL context\n");
        exit(1);
    }

    rc = SSL_CTX_use_certificate_file(ctx, certificateFilename, SSL_FILETYPE_PEM);
    if (rc <= 0) {
        uprintf("Set SSL_CTX_use_certificate_file() error\n");
        exit(1);
    }

    rc = SSL_CTX_use_PrivateKey_file(ctx, privateKeyFilename, SSL_FILETYPE_PEM);
    if (rc <= 0) {
        uprintf("Set SSL_CTX_use_PrivateKey_file() error\n");
        exit(1);
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;        // <-- IPv4 internet protocol
    sin.sin_addr.s_addr = INADDR_ANY; // <-- Accept any incoming messages
    sin.sin_port = htons(port_num);

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = bind(listener, (struct sockaddr*)&sin, sizeof(sin));
    if (rc < 0) {
        uprintf("bind socket error, port number : <%d>, listener : %d\n", port_num, listener);
        exit(1);
    }

    rc = listen(listener, 16);
    if (rc < 0) {
        uprintf("listen for connection error, listener : <%d>\n", listener);
        exit(1);
    }

    uprintf("SSL/TLS Echo Server started, port number : (%d)\n", port_num);

    // Initialize client tracking array
    ClientContext clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
        clients[i].ssl = nullptr;
    }

    while (!g_close) {
        fd_set readfds;
        FD_ZERO(&readfds);
        
        // Always add the listener to the read set
        FD_SET(listener, &readfds);
        SOCKET max_sd = listener;

        // Check if any existing SSL connections have decrypted data waiting
        bool pending_ssl_data = false;

        // Add valid child sockets to the read set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            SOCKET sd = clients[i].fd;
            if ((int)sd != -1) {
                FD_SET(sd, &readfds);
                if (sd > max_sd) {
                    max_sd = sd;
                }
                
                // If OpenSSL has buffered data, we shouldn't block in select()
                if (clients[i].ssl && SSL_pending(clients[i].ssl) > 0) {
                    pending_ssl_data = true;
                }
            }
        }

        // Set a timeout so the server can periodically check the !g_close flag
        struct timeval tv;
        tv.tv_sec = 1;  // 1 second timeout
        tv.tv_usec = 0;

        // If SSL has data in its buffer, don't wait in select at all
        if (pending_ssl_data) {
            tv.tv_sec = 0;
            tv.tv_usec = 0;
        }

        int activity = select((int)max_sd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0) {
            uprintf("select error\n");
            continue;
        }

        // 1. Handle new incoming connections
        if (FD_ISSET(listener, &readfds)) {
            struct sockaddr_in addr;
#ifdef _WIN32
			int len = sizeof(addr);
#else
			unsigned int len = sizeof(addr);
#endif
            SOCKET new_socket = accept(listener, (struct sockaddr*)&addr, &len);
            if (new_socket < 0) {
                perror("Unable to accept");
            } else {
                SSL* ssl = SSL_new(ctx);
                SSL_set_fd(ssl, (int)new_socket);

                // Note: SSL_accept can block momentarily. 
                if (SSL_accept(ssl) <= 0) {
                    uprintf("Unable to accept SSL handshake\n");
                    SSL_free(ssl);
                    closesocket(new_socket);
                } else {
                    // Find an empty slot for the new client
                    bool slot_found = false;
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if ((int)clients[i].fd == -1) {
                            clients[i].fd = new_socket;
                            clients[i].ssl = ssl;
                            slot_found = true;
                            break;
                        }
                    }
                    if (!slot_found) {
                        uprintf("Max clients reached. Rejecting connection.\n");
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        closesocket(new_socket);
                    }
                }
            }
        }

        // 2. Handle I/O on existing client connections
        for (int i = 0; i < MAX_CLIENTS; i++) {
            SOCKET sd = clients[i].fd;
            SSL* ssl = clients[i].ssl;

            // Process if select() flagged the socket OR if OpenSSL has buffered data
            if ((int)sd != -1 && (FD_ISSET(sd, &readfds) || SSL_pending(ssl) > 0)) {
                memset(msg_buf, '\0', BUFFER_SIZE);
                
                int n_recvd = SSL_read(ssl, msg_buf, BUFFER_SIZE);
                
                if (n_recvd <= 0) {
                    // Client disconnected or an error occurred
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    closesocket(sd);
                    clients[i].fd = -1;  // Free the slot
                    clients[i].ssl = nullptr;
                } else {
                    // Echo the message back
                    int n_send = SSL_write(ssl, msg_buf, n_recvd);
                    if (n_send <= 0) {
                        // Error during write
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        closesocket(sd);
                        clients[i].fd = -1;
                        clients[i].ssl = nullptr;
                    } else {
                        uprintf("Recvd Message  (%d - %d) : %s \n", (int)n_recvd, (int)n_send, msg_buf);
                    }
                }
            }
        }
    }

    // Global Cleanup on exit
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if ((int)clients[i].fd != -1) {
            SSL_shutdown(clients[i].ssl);
            SSL_free(clients[i].ssl);
            closesocket(clients[i].fd);
        }
    }

    closesocket(listener);
    SSL_CTX_free(ctx);
    return 0;
}

int tlsserver(int port_num,const char* certificateFilename,const char* privateKeyFilename) {
	char msg_buf[BUFFER_SIZE];
	int rc;

	SSL_CTX* ctx=SSL_CTX_new(TLS_server_method());
	if(ctx==nullptr){
		uprintf("Unable to create SSL context\n");
		exit(1);
	}

	rc=SSL_CTX_use_certificate_file(ctx,certificateFilename,SSL_FILETYPE_PEM);
	if(rc<=0){
		uprintf("Set SSL_CTX_use_certificate_file() error\n");
		exit(1);
	}

	rc=SSL_CTX_use_PrivateKey_file(ctx,privateKeyFilename,SSL_FILETYPE_PEM);
	if(rc<=0){
		uprintf("Set SSL_CTX_use_PrivateKey_file() error\n");
		exit(1);
	}

	struct sockaddr_in    sin;
	sin.sin_family=AF_INET;       // <-- IPv4 internet protcol
	sin.sin_addr.s_addr=INADDR_ANY;    // <-- Accept any incoming messages (0)
	sin.sin_port=htons(port_num);

	SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	rc=bind(listener,(struct sockaddr*)&sin,sizeof(sin));
	if(rc<0){
		uprintf("bind socket error, port number : <%d>, listener : %d\n",port_num,listener);
		exit(1);
	}

	rc=listen(listener,16);
	if(rc<0){
		uprintf("listen for connection error, listener : <%d>\n",listener);
		exit(1);
	}

	uprintf("SSL/TLS Echo Server started, port number : (%d)\n",port_num);
	while(!g_close){
		struct sockaddr_in addr;
#ifdef _WIN32
		int len=sizeof(addr);
#else
		unsigned int len=sizeof(addr);
#endif
		SOCKET fd=accept(listener,(struct sockaddr*)&addr,&len);
		if(fd<0){
			perror("Unable to accept");
			exit(EXIT_FAILURE);
		}

		SSL* ssl=SSL_new(ctx);
		SSL_set_fd(ssl,(int)fd);
		if(SSL_accept(ssl)<=0){
			uprintf("Unable to accept SSL handshake\n");
		}

		for(;; ){
			memset(msg_buf,'\0',BUFFER_SIZE);
			// ssize_t n_recvd = recv(fd, msg_buf, BUFFER_SIZE, 0);
			int n_recvd=SSL_read(ssl,msg_buf,BUFFER_SIZE);
			if(n_recvd<=0)
				break;
			// ssize_t n_send = send(fd, msg_buf, n_recvd, 0);
			int n_send=SSL_write(ssl,msg_buf,n_recvd);
			if(n_send<=0)
				break;
			uprintf("Recvd Message  (%d - %d) : %s \n",(int)n_recvd,(int)n_send,msg_buf);
		}

		SSL_shutdown(ssl);
		SSL_free(ssl);
		closesocket(fd);
	}

	closesocket(listener);
	SSL_CTX_free(ctx);
	return 0;
}

int tlsclient(const char* hostname,int port_num) {
	struct sockaddr_in sin;
	char recv_buf[BUFFER_SIZE];
	char send_buf[BUFFER_SIZE];

	struct hostent* h=gethostbyname(hostname);
	if(!h){
		uprintf("gethostbyname() could not resolve hostname\n");
		return -1;
	}

	/*
	 *  2) : create socket an endpoint for communication
	 */

	SOCKET fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(fd<0){
		uprintf("create new socket error\n");
		return -1;
	}

	sin.sin_family=AF_INET;
	sin.sin_port=htons(port_num);
	sin.sin_addr=*(struct in_addr*)h->h_addr;

	int rc=connect(fd,(struct sockaddr*)&sin,sizeof(sin));
	if(rc!=0){
		uprintf("connect to remote host failed \n");
		closesocket(fd);
		return -1;
	}

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_CTX* ctx=SSL_CTX_new(TLS_client_method());
	if(ctx==NULL){
		uprintf("ERROR: could not initialize the SSL context\n");
		exit(1);
	}
	SSL* ssl=SSL_new(ctx);
	SSL_set_fd(ssl,(int)fd);

	if(SSL_connect(ssl)<0){
		uprintf("ERROR: could not complete TLS handshake via SSL\n");
		exit(1);
	}

	for(int i=0;i!=10;i++){
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		uprintf("client send %d\n",i);
		memset(recv_buf,'\0',BUFFER_SIZE);
		memset(send_buf,'\0',BUFFER_SIZE);
		strcpy(send_buf,"my message");

		size_t msg_length=strlen(send_buf);
		if(msg_length==0){
			break;
		}

		// ssize_t n_send = send(fd, send_buf, msg_length, 0);
		int n_send=SSL_write(ssl,send_buf,(int)msg_length);
		// ssize_t n_recvd = recv(fd, recv_buf, BUFFER_SIZE, 0);
		int n_recvd=SSL_read(ssl,recv_buf,n_send);
		uprintf("Recvd Message (%d - %d) : %s \n",(int)n_recvd,(int)n_send,recv_buf);

	}

	SSL_set_shutdown(ssl,SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(fd);
	return 0;
}

int tcpserver(int port_num) {
	char msg_buf[BUFFER_SIZE];

	//int port_num=std::stoi(argv[1]);

	struct sockaddr_in    sin;
	sin.sin_family=AF_INET;       // <-- IPv4 internet protcol
	sin.sin_addr.s_addr=INADDR_ANY;    // <-- Accept any incoming messages (0)
	sin.sin_port=htons(port_num);

	SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	int rc=bind(listener,(struct sockaddr*)&sin,sizeof(sin));
	if(rc<0){
		uprintf("bind socket error, port number : <%d>, listener : %d\n",port_num,listener);
		exit(1);
	}

	rc=listen(listener,16);
	if(rc<0){
		uprintf("listen for connection error, listener : <%d>\n",listener);
		exit(1);
	}

	uprintf("TCP Echo Server started, port number : (%d)\n",port_num);
	while(!g_close){
		struct sockaddr_in addr;
#ifdef _WIN32
		int len=sizeof(addr);
#else
		unsigned int len=sizeof(addr);
#endif
		SOCKET fd=accept(listener,(struct sockaddr*)&addr,&len);
		if(fd<0){
			perror("Unable to accept");
			exit(EXIT_FAILURE);
		}

		for(;;){
			memset(msg_buf,'\0',BUFFER_SIZE);
			size_t n_recvd=recv(fd,msg_buf,BUFFER_SIZE,0);
			if(n_recvd<=0)
				break;
			size_t n_send=send(fd,msg_buf,(int)n_recvd,0);
			if(n_send<=0)
				break;
			uprintf("Recvd Message  (%d - %d) : %s \n",(int)n_recvd,(int)n_send,msg_buf);
		}

		closesocket(fd);
	}

	closesocket(listener);
	return 0;
}

int tcpclient(const char* hostname,int port_num) {
	struct sockaddr_in sin;
	char recv_buf[BUFFER_SIZE];
	char send_buf[BUFFER_SIZE];

	struct hostent* h=gethostbyname(hostname);
	if(!h){
		uprintf("gethostbyname() could not resolve hostname\n");
		return -1;
	}

	/*
	 *  2) : create socket an endpoint for communication
	 */

	SOCKET fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(fd<0){
		uprintf("create new socket error\n");
		return -1;
	}

	sin.sin_family=AF_INET;
	sin.sin_port=htons(port_num);
	sin.sin_addr=*(struct in_addr*)h->h_addr;

	int rc=connect(fd,(struct sockaddr*)&sin,sizeof(sin));
	if(rc!=0){
		uprintf("connect to remote host failed \n");
		closesocket(fd);
		return -1;
	}

	for(int i=0;i!=10;i++){
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		uprintf("client send %d\n",i);
		memset(recv_buf,'\0',BUFFER_SIZE);
		memset(send_buf,'\0',BUFFER_SIZE);
		strcpy(send_buf,"my message");

		size_t msg_length=strlen(send_buf);
		if(msg_length==0){
			break;
		}

		size_t n_send=send(fd,send_buf,(int)msg_length,0);
		size_t n_recvd=recv(fd,recv_buf,BUFFER_SIZE,0);
		uprintf("Recvd Message (%d - %d) : %s \n",(int)n_recvd,(int)n_send,recv_buf);

	}
	closesocket(fd);
	return 0;
}
