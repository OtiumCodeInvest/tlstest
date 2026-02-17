#include <stdio.h>
#include <stdlib.h>
#include"shared/time.h"

#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>		//GetAdaptersInfo
#else

#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <signal.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <limits.h>
#include <sys/time.h>
#include "unistd.h"
#include <assert.h>
#ifdef __linux__
#include <linux/wireless.h>
#endif

#define INVALID_SOCKET -1
#endif


#include"shared/file.h"
#include"shared/net.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h> // Strictly required for PEM_read_bio functions

#include "socketservertls.h"

#define SOCKET int

#define MAX_NUMBER_CONNECTIONS 1024

#define SOCKETSERVERERROR uprintf
#define SOCKETSERVERWARNING uprintf
#define SOCKETSERVERNOTIFY uprintf

#define SOCKETCLIENTERROR uprintf
#define SOCKETCLIENTWARNING uprintf
#define SOCKETCLIENTNOTIFY uprintf

#define TIMEGUARD(function,limit,msg) {uint64_t t=GetTimer();\
						function;\
						uint64_t dt=ElapsedMilliseconds(t);\
						if(dt>limit) {\
							uprintf("%s execution time %lluns\n",msg,dt);\
						}}\


class SocketHandle{
	int m_refCount=0;
	public:
#ifdef _WIN32
	void* m_event=0;
#endif
	SOCKET m_socket;
	SocketHandle(SOCKET lSocket) {
		m_socket=lSocket;
		m_refCount=1;
	}
	~SocketHandle() {
		if(m_socket){
#ifdef _WIN32
			//shutdown(m_socket,SD_SEND);
			if(closesocket(m_socket))
				FATAL("closesocket failed");
#else
			close(m_socket);
			//	::shutdown(m_socket,SHUT_RDWR);
	//#ifndef WSL
	//			::close(m_socket);
	//#endif
#endif
		}
	}
	void AddRef() {
		m_refCount++;
	}
	void Release() {
		m_refCount--;
		if(!m_refCount){
			delete this;
		}
	}
	bool IsValid()const {
		return (int)m_socket!=INVALID_SOCKET;
	}
};


void SocketServerTLS::Send(void* ssl,char* data,int dataByteSize) {
	SSL_write((SSL*)ssl,data,dataByteSize);
}


// Helper function to load TLS credentials from std::string
bool SocketServerTLS::LoadCertAndKeyFromMemory(SSL_CTX* ctx,const std::string& certBuffer,const std::string& keyBuffer) {

	// ---------------------------------------------------------
	// 1. Load the Certificate from Memory
	// ---------------------------------------------------------
	if(certBuffer.empty()){
		uprintf("Certificate string is empty\n");
		return false;
	}

	// BIO_new_mem_buf safely reads from the contiguous string memory
	BIO* certBio=BIO_new_mem_buf(certBuffer.data(),(int)certBuffer.size());
	if(!certBio){
		uprintf("Failed to create memory BIO for certificate\n");
		return false;
	}

	X509* cert=PEM_read_bio_X509(certBio,nullptr,nullptr,nullptr);
	BIO_free(certBio);

	if(!cert){
		uprintf("Failed to parse certificate from memory\n");
		return false;
	}

	if(SSL_CTX_use_certificate(ctx,cert)<=0){
		uprintf("Failed to use certificate in SSL_CTX\n");
		X509_free(cert);
		return false;
	}
	X509_free(cert);


	// ---------------------------------------------------------
	// 2. Load the Private Key from Memory
	// ---------------------------------------------------------
	if(keyBuffer.empty()){
		uprintf("Private key string is empty\n");
		return false;
	}

	BIO* keyBio=BIO_new_mem_buf(keyBuffer.data(),(int)keyBuffer.size());
	if(!keyBio){
		uprintf("Failed to create memory BIO for private key\n");
		return false;
	}

	EVP_PKEY* pkey=PEM_read_bio_PrivateKey(keyBio,nullptr,nullptr,nullptr);
	BIO_free(keyBio);

	if(!pkey){
		uprintf("Failed to parse private key from memory\n");
		return false;
	}

	if(SSL_CTX_use_PrivateKey(ctx,pkey)<=0){
		uprintf("Failed to use private key in SSL_CTX\n");
		EVP_PKEY_free(pkey);
		return false;
	}
	EVP_PKEY_free(pkey);


	// ---------------------------------------------------------
	// 3. Verify Key Match
	// ---------------------------------------------------------
	if(!SSL_CTX_check_private_key(ctx)){
		uprintf("Private key does not match the certificate public key\n");
		return false;
	}

	return true;
}

bool SocketServerTLS::LoadCertificates(const std::string& certificateFilename,const std::string& privateKeyFilename) {
	m_certBuffer=LoadFile(certificateFilename,false);
	m_keyBuffer=LoadFile(privateKeyFilename,false);
	return true;
}

int SocketServerTLS::Run() {
	// 1. Initialize OpenSSL Context
	SSL_CTX* ctx=SSL_CTX_new(TLS_server_method());
	if(ctx==nullptr){
		FATAL("Unable to create SSL context");
	}

	// Pass -1 for lengths if your buffers are standard null-terminated strings
	if(!LoadCertAndKeyFromMemory(ctx,m_certBuffer,m_keyBuffer)){
		FATAL("Failed to load certificate or private key from memory");
	}
	/*
		if(SSL_CTX_use_certificate_file(ctx,certificateFilename,SSL_FILETYPE_PEM)<=0){
			FATAL("Set SSL_CTX_use_certificate_file() error");
		}
		if(SSL_CTX_use_PrivateKey_file(ctx,privateKeyFilename,SSL_FILETYPE_PEM)<=0){
			FATAL("Set SSL_CTX_use_PrivateKey_file() error");
		}
	*/
	Socket socketMaster=Socket(Socket::INET,Socket::STREAM,Socket::TCP);
	SocketAddress address;
	address.Set(m_bindAddress.c_str());
	address.PortSet(m_bindPort);

	socketMaster.SetBlockingMode(false);
	socketMaster.SetBuffered(false);
	socketMaster.SetSendTimeout(5000);
	socketMaster.SetRecvTimeout(5000);

	SOCKETSERVERNOTIFY("NOTIFY: SocketServerTLS::Run\n");

	while(1){
		if(socketMaster.Bind(address)) break;
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		if(m_close){
			SSL_CTX_free(ctx);
			return 0;
		}
	}

	if(!socketMaster.Listen(3)){
		FATAL("INT3");
	}

	m_threadRunning=true;
	int numSockets=0;
	ConnectedSocket* sockets[MAX_NUMBER_CONNECTIONS];
	SSL* ssl_sessions[MAX_NUMBER_CONNECTIONS]; // Parallel array to track SSL states

	memset(sockets,0,sizeof(sockets));
	memset(ssl_sessions,0,sizeof(ssl_sessions));

	// Index 0 is always the master listener (no SSL session associated)
	sockets[numSockets]=new ConnectedSocket(socketMaster,m_socketIdCount++);
	ssl_sessions[numSockets]=nullptr;
	numSockets++;

	char data[0x10000];
	SOCKETSERVERNOTIFY("NOTIFY: %s::RunTLS enter listen loop port %d\n",ClassName(),m_bindPort);
	int event_index_read=0;

	while(!m_close){
		m_socketSet.SetReadSockets((const Socket**)sockets,numSockets);
		m_socketSet.SetErrorSockets((const Socket**)sockets,numSockets);

		// -- Send List Processing --
		if(m_sendList.size()){
			m_sendLock.lock();
			uint64_t dt=ElapsedMicroseconds(m_sendTime);
			for(int i=0; i!=(int)m_sendList.size(); i++){
				bool found=false;
				for(int j=1; j<numSockets; j++){ // do not include master
					if(sockets[j]->m_id==m_sendList[i].m_socketId){
						EncodeAndSend(sockets[j],m_sendList[i].m_data.data(),(int)m_sendList[i].m_data.size());
						found=true;
						break;
					}
				}
				if(!found){
					SOCKETSERVERWARNING("WARNING: %s::RunTLS Unable to find socket %d\n",ClassName(),m_sendList[i].m_socketId);
				}
			}
			m_sendList.clear();
			m_sendLock.unlock();
			if(dt>10*1000)
				SOCKETSERVERWARNING("WARNING: %s::RunTLS SendToSocketTime %llu\n",ClassName(),dt);
		}

		// -- Check Pending SSL Data to avoid Select() Block --
		bool pending_ssl_data=false;
		int numWriteSockets=0;
		const Socket* writeSockets[MAX_NUMBER_CONNECTIONS];

		for(int i=1; i<numSockets; i++){
			if(sockets[i]->m_send.DataByteSize()){
				writeSockets[numWriteSockets++]=sockets[i];
			}
			// Check OpenSSL's internal buffer
			if(ssl_sessions[i]&&SSL_pending(ssl_sessions[i])>0){
				pending_ssl_data=true;
			}
		}

		m_socketSet.SetWriteSockets(writeSockets,numWriteSockets);

		// If OpenSSL has buffered data, drop select timeout to 0 so we loop immediately
		int waitTime=pending_ssl_data ? 0 : 10000;
		int numSocketsReady=m_socketSet.WaitForDataOrSignal(waitTime);

		if(m_close) break;

		m_eventLock.lock();
		if(event_index_read!=m_eventIndex){
			event_index_read=m_eventIndex;
			TIMEGUARD(OnEvent(((ConnectedSocket**)sockets)+1,numSockets-1),10*1000,stdx::format_string("WARNING: %s::RunTLS OnEvent\n",ClassName()).c_str());
		}
		m_eventLock.unlock();

		if(numSocketsReady>0||pending_ssl_data){

			// -- Handle Errors --
			for(int i=0; i<numSockets; i++){
				if(m_socketSet.IsError(*sockets[i])){
					SOCKETSERVERERROR("ERROR: %s::RunTLS socket %d\n",ClassName(),i);
				}
			}

			// -- Handle Sending Data (Writes) --
			for(int i=1; i<numSockets; i++){
				if(m_socketSet.IsWrite(*sockets[i])){
					ConnectedSocket* socket=sockets[i];
					SSL* ssl=ssl_sessions[i];
					int maxSendSize=MIN(socket->m_send.DataByteSize(),(int)sizeof(data));
					int sendByteSize=socket->m_send.ReadBytes(data,maxSendSize,0);
					bool connectionLost=false;

					if(sendByteSize){
						int wasSentByteSize=SSL_write(ssl,data,sendByteSize);

						// [FIX] Safely handle WANT_WRITE and WANT_READ for asynchronous sockets
						if(wasSentByteSize<=0){
							int err=SSL_get_error(ssl,wasSentByteSize);
							if(err==SSL_ERROR_WANT_READ||err==SSL_ERROR_WANT_WRITE){
								// Network buffer is full. Pretend 0 sent so it remains in the queue
								wasSentByteSize=0;
							} else{
								connectionLost=true;
							}
						} else{
							socket->m_send.PopBytes(wasSentByteSize);
							m_totalBytesSend+=(int64_t)wasSentByteSize;
							if(m_verbose){
								SOCKETSERVERNOTIFY("NOTIFY: %s::RunTLS port %d send data %d remain %d\n",ClassName(),m_bindPort,wasSentByteSize,maxSendSize);
							}
						}
					} else{
						SOCKETSERVERWARNING("WARNING: %s::RunTLS send data size zero for socket id %d\n",ClassName(),socket->m_id);
					}

					if(connectionLost||socket->m_send.DataByteSize()==0){
						if(connectionLost||socket->m_closeAfterSend){
							TIMEGUARD(OnClose(socket),2*1000,stdx::format_string("WARNING: %s::RunTLS OnClose\n",ClassName()).c_str());

							SSL_shutdown(ssl_sessions[i]);
							SSL_free(ssl_sessions[i]);

							int lastIdx=numSockets-1;
							sockets[i]=sockets[lastIdx];
							ssl_sessions[i]=ssl_sessions[lastIdx];
							sockets[lastIdx]=nullptr;
							ssl_sessions[lastIdx]=nullptr;

							numSockets--;
							m_numConnectedSockets=numSockets-1;
							delete socket;
							i--; // Re-check the swapped index
						}
					}
				}
			}

			// -- Handle Receiving Data (Reads) --
			for(int i=0; i<numSockets; i++){
				bool isReadReady=m_socketSet.IsRead(*sockets[i]);
				bool hasPendingData=(i>0&&ssl_sessions[i]&&SSL_pending(ssl_sessions[i])>0);

				if(isReadReady||hasPendingData){
					if(i==0){
						// 1. Accept Master Socket Connection
						if(numSockets==countof(sockets)){
							SOCKETSERVERWARNING("WARNING: %s::RunTLS OnData unable to accept new connection sockets list full, max %d\n",ClassName(),numSockets);
						} else{
							Socket newSocket=socketMaster.Accept();
							if(newSocket.IsValid()){

								// [FIX] Force blocking mode temporarily for the TLS handshake
								newSocket.SetBlockingMode(true);

								SSL* ssl=SSL_new(ctx);
								SSL_set_fd(ssl,(int)newSocket.m_handle->m_socket);

								if(SSL_accept(ssl)<=0){
									SOCKETSERVERWARNING("WARNING: SSL_accept failed\n");
									SSL_free(ssl);
								} else{
									// [FIX] Handshake success. Restore non-blocking mode.
									newSocket.SetBlockingMode(false);
									newSocket.SetSendTimeout(5000);
									newSocket.SetRecvTimeout(5000);

									ConnectedSocket* socket=new ConnectedSocket(newSocket,m_socketIdCount++);
									socket->SetBuffered(false);

									ssl_sessions[numSockets]=ssl;
									sockets[numSockets++]=socket;

									SOCKETSERVERNOTIFY("NOTIFY: %s::RunTLS connected socket %d\n",ClassName(),socket->m_id);

									if(!OnConnected(socket)){
										SSL_shutdown(ssl_sessions[numSockets-1]);
										SSL_free(ssl_sessions[numSockets-1]);
										sockets[--numSockets]=nullptr;
										delete socket;
									}
									m_numConnectedSockets=numSockets-1;
								}
							}
						}
					} else{
						// 2. Read from Client Socket
						ConnectedSocket* socket=sockets[i];
						SSL* ssl=ssl_sessions[i];

						int bytesReceived=SSL_read(ssl,data,sizeof(data));
						bool close=false;

						if(bytesReceived<=0){
							// [FIX] Ignore WANT_READ / WANT_WRITE instead of dropping the connection
							int err=SSL_get_error(ssl,bytesReceived);
							if(err==SSL_ERROR_WANT_READ||err==SSL_ERROR_WANT_WRITE){
								bytesReceived=0; // Wait for the next select loop
							} else{
								close=true; // Actual failure or disconnect
							}
						}

						if(bytesReceived>0){
							//SOCKETSERVERNOTIFY("NOTIFY: %s::RunTLS data socket %d bytes received %d\n",ClassName(),socket->m_id,bytesReceived);
							socket->m_timeLastByteReceived=std::chrono::high_resolution_clock::now();
							m_totalBytesReceived+=(int64_t)bytesReceived;

							TIMEGUARD(close=!OnDataTLS(socket,ssl,data,bytesReceived),100*1000,stdx::format_string("WARNING: %s::RunTLS OnData\n",ClassName()).c_str());
						}

						if(close){
							SOCKETSERVERNOTIFY("NOTIFY: %s::RunTLS close socket %d\n",ClassName(),socket->m_id);
							TIMEGUARD(OnClose(socket),2*1000,stdx::format_string("WARNING: %s::RunTLS OnClose\n",ClassName()).c_str());

							SSL_shutdown(ssl_sessions[i]);
							SSL_free(ssl_sessions[i]);

							int lastIdx=numSockets-1;
							sockets[i]=sockets[lastIdx];
							ssl_sessions[i]=ssl_sessions[lastIdx];
							sockets[lastIdx]=nullptr;
							ssl_sessions[lastIdx]=nullptr;

							numSockets--;
							m_numConnectedSockets=numSockets-1;
							delete socket;
							i--; // Re-check the swapped index
						}
					}
				}
			}
		}
	}

	// Global Cleanup on exit
	for(int i=0; i<MAX_NUMBER_CONNECTIONS; ++i){
		if(sockets[i]){
			if(i){ // Skip master socket for custom events
				OnDestroy(sockets[i]);
				SSL_shutdown(ssl_sessions[i]);
				SSL_free(ssl_sessions[i]);
			}
			delete sockets[i];
		}
	}

	SSL_CTX_free(ctx);
	m_numConnectedSockets=0;
	SOCKETSERVERNOTIFY("NOTIFY: %s::RunTLS leave listen loop\n",ClassName());
	m_threadRunning=false;

	return 0;
}











SocketAddress GetHostByName(const char* pszHostName);

int SocketClientTLS::KeepAliveThreadFunc() {
	SSL_CTX* ctx=SSL_CTX_new(TLS_client_method());
	if(ctx==nullptr){
		FATAL("Unable to create SSL context for Client");
	}

	SSL* ssl=nullptr;
	m_socket=0;
	uint8_t data[64*1000];
	uint64_t startTime=GetTimer();
	uint64_t prevTime=-1;

	while(!m_close){
		if(!m_connected){
			if(m_host.length()){
				m_address=GetHostByName(m_host.c_str());
				m_address.PortSet(m_port);
			}

			if(m_nonBlockConnect){
				if(!m_socket){
					Socket socket=Socket(Socket::INET,Socket::STREAM,Socket::TCP);
					socket.SetBuffered(false);
					socket.SetSendTimeout(5000);
					socket.SetRecvTimeout(5000);
					if(!socket.ConnectNonBlock(m_address)){
						continue;
					}
					SOCKETCLIENTNOTIFY("NOTIFY: %s socket non blocking connect success\n",InstanceName());
					m_socket=new ConnectedSocket(socket);
					m_socketSet.SetWriteSockets((const Socket**)&m_socket,1);
					m_socketSet.SetReadSockets(nullptr,0);
				}
				int ret=m_socketSet.WaitForDataOrSignal(5000);
				if(ret<1){
					if(ret==-1){
						m_socketSet.SetWriteSockets(0,0);
					} else{
						if(m_host.length()){
							SOCKETCLIENTWARNING("WARNING: %s::KeepAliveThreadFuncTLS Unable to connect. Retrying in 5 seconds\n",InstanceName());
						}
					}
					delete m_socket;
					m_socket=nullptr;
					continue;
				} else{
					if(m_socketSet.IsWrite(*m_socket)&&m_socket->OptionNoError()&&m_socket->HasPeerName()){
						m_socketSet.SetWriteSockets(0,0);

						// [TLS FIX] Force block temporarily for client handshake
						m_socket->SetBlockingMode(true);
						ssl=SSL_new(ctx);
						SSL_set_fd(ssl,(int)m_socket->m_handle->m_socket);

						if(SSL_connect(ssl)<=0){
							SOCKETCLIENTWARNING("WARNING: %s::KeepAliveThreadFuncTLS SSL_connect failed\n",InstanceName());
							SSL_free(ssl);
							ssl=nullptr;
							delete m_socket;
							m_socket=nullptr;
							continue;
						} else{
							SOCKETCLIENTNOTIFY("NOTIFY: %s SSL_connect success\n",InstanceName());
						}
						m_socket->SetBlockingMode(false); // Back to non-blocking
					} else{
						m_socketSet.SetWriteSockets(0,0);
						delete m_socket;
						m_socket=nullptr;
						continue;
					}
				}
			} else{
				if(!m_socket){
					Socket socket=Socket(Socket::INET,Socket::STREAM,Socket::TCP);
					m_socket=new ConnectedSocket(socket);
					m_socket->SetBuffered(false);
					m_socket->SetSendTimeout(5000);
					m_socket->SetRecvTimeout(5000);
				}
				if(!m_socket->Connect(m_address)){
					SOCKETCLIENTNOTIFY("NOTIFY: %s::KeepAliveThreadFuncTLS Unable to connect. Retrying...\n",InstanceName());
					std::this_thread::sleep_for(std::chrono::milliseconds(5000));
					continue;
				}

				// [TLS FIX] Handshake for blocking TCP connection
				ssl=SSL_new(ctx);
				SSL_set_fd(ssl,(int)m_socket->m_handle->m_socket);
				if(SSL_connect(ssl)<=0){
					SSL_free(ssl);
					ssl=nullptr;
					delete m_socket;
					m_socket=nullptr;
					std::this_thread::sleep_for(std::chrono::milliseconds(5000));
					continue;
				}
				m_socket->SetBlockingMode(false);
			}

			SOCKETCLIENTNOTIFY("NOTIFY: %s::KeepAliveThreadFuncTLS Connected to %s\n",InstanceName(),m_address.ToString().c_str());
			OnConnected();
			m_connected=true;
		}

		int waitNextTimer=-1;
		if(m_timerFrequency){
			uint64_t time=GetTimer()-startTime;
			if(floorf((float)prevTime/m_timerFrequency)!=floorf((float)time/m_timerFrequency)){
				OnTimer();
			}
			double timeNextTimer=(floorf((float)time/m_timerFrequency)+1.0f)*m_timerFrequency;
			waitNextTimer=(int)(timeNextTimer-time);
			prevTime=time;
		}

		m_socket->m_sendLock.lock();
		if(m_socket->m_send.DataByteSize()){
			m_socketSet.SetWriteSockets((const Socket**)&m_socket,1);
		} else{
			m_socketSet.SetWriteSockets(0,0);
		}
		m_socket->m_sendLock.unlock();

		m_socketSet.SetReadSockets((const Socket**)&m_socket,1);
		m_socketSet.SetErrorSockets((const Socket**)&m_socket,1);

		// [TLS FIX] Check pending decrypted data to prevent select() from blocking indefinitely
		bool pending_ssl_data=(ssl&&SSL_pending(ssl)>0);
		if(pending_ssl_data){
			waitNextTimer=0;
		}

		int numSocketsReady=m_socketSet.WaitForDataOrSignal(waitNextTimer);
		if(m_close) break;

		if(numSocketsReady>0||pending_ssl_data){
			if(m_socketSet.IsError(*m_socket)){
				SOCKETCLIENTERROR("ERROR: %s::KeepAliveThreadFuncTLS Socket error\n",InstanceName());
			}

			// --- Write Phase ---
			if(m_socketSet.IsWrite(*m_socket)){
				m_socket->m_sendLock.lock();
				int maxSendSize=MIN(m_socket->m_send.DataByteSize(),(int)sizeof(data));
				int sendByteSize=m_socket->m_send.ReadBytes(data,maxSendSize,0);

				if(m_socket->m_send.IsStartOfData()){
					OnSendInjection(data,sendByteSize);
				}

				// REPLACE: m_socket->Send with SSL_write
				int wasSentByteSize=SSL_write(ssl,data,sendByteSize);

				if(wasSentByteSize<=0){
					int err=SSL_get_error(ssl,wasSentByteSize);
					if(err==SSL_ERROR_WANT_READ||err==SSL_ERROR_WANT_WRITE){
						wasSentByteSize=0; // Buffer full, try again later
					}
				}

				if(wasSentByteSize>0){
					m_socket->m_send.PopBytes(wasSentByteSize);
					m_totalBytesSend+=(int64_t)wasSentByteSize;
				}
				m_socket->m_sendLock.unlock();

				if(wasSentByteSize<=0||m_socket->m_send.DataByteSize()==0){
					if((wasSentByteSize<=0&&SSL_get_error(ssl,wasSentByteSize)!=SSL_ERROR_WANT_WRITE)||m_socket->m_closeAfterSend){
						SSL_shutdown(ssl);
						SSL_free(ssl);
						ssl=nullptr;
						delete m_socket;
						m_socket=0;
						bool reconnect;
						TIMEGUARD(reconnect=OnClose(),20*1000,"WARNING: KeepAliveThreadFuncTLS OnClose\n");
						m_connected=false;
						std::this_thread::sleep_for(std::chrono::milliseconds(1000));
						if(!reconnect)
							break;
						continue;
					}
				}
			}

			// --- Read Phase ---
			if(m_socketSet.IsRead(*m_socket)||pending_ssl_data){
				// REPLACE: m_socket->Receive with SSL_read
				int bytesReceived=SSL_read(ssl,data,sizeof(data));
				bool close=false;

				if(bytesReceived<=0){
					int err=SSL_get_error(ssl,bytesReceived);
					if(err==SSL_ERROR_WANT_READ||err==SSL_ERROR_WANT_WRITE){
						bytesReceived=0;
					} else{
						close=true;
					}
				}

				if(bytesReceived>0){
					m_totalBytesReceived+=(int64_t)bytesReceived;
					TIMEGUARD(close=!OnData(data,bytesReceived),40*100,"WARNING: SocketClient::KeepAliveThreadFuncTLS OnData\n");
				}

				if(close){
					SOCKETCLIENTNOTIFY("NOTIFY: %s::KeepAliveThreadFuncTLS socket closed\n",InstanceName());
					SSL_shutdown(ssl);
					SSL_free(ssl);
					ssl=nullptr;
					delete m_socket;
					m_socket=0;
					bool reconnect;
					TIMEGUARD(reconnect=OnClose(),20*1000,"WARNING: KeepAliveThreadFuncTLS OnClose\n");
					m_connected=false;
					if(!reconnect) break;
					std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					continue;
				}
			}
		} else if(numSocketsReady<0){
			if(ssl){
				SSL_shutdown(ssl);
				SSL_free(ssl);
				ssl=nullptr;
			}
			delete m_socket;
			m_socket=0;
			bool reconnect;
			TIMEGUARD(reconnect=OnClose(),20*1000,"WARNING: SocketClient::KeepAliveThreadFuncTLS OnClose\n");
			m_connected=false;
			std::this_thread::sleep_for(std::chrono::milliseconds(60*1000));
			if(!reconnect) break;
			continue;
		}
	}

	SOCKETCLIENTNOTIFY("NOTIFY: %sSocketClient::KeepAliveThreadFuncTLS end thread\n",InstanceName());
	if(ssl){
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	SSL_CTX_free(ctx);

	delete m_socket;
	m_socket=0;
	if(m_connected){
		OnClose();
	}
	m_connected=false;
	m_socketSet.SetReadSockets(nullptr,0);
	m_socketSet.SetWriteSockets(nullptr,0);
	m_socketSet.SetErrorSockets(nullptr,0);
	m_socketSet.WaitForDataOrSignal(0);
	m_keepAliveThread.detach();
	m_running.store(false);
	return 0;
}