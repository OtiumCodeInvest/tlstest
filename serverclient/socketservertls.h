#pragma once

#include <string.h>
#include <string>
#include"shared/net.h"

class SocketClientTLS : public SocketClient{
	public:
	protected:
		virtual int KeepAliveThreadFunc();
};

class SocketServerTLS : public SocketServer{
	public:
		bool LoadCertificates(const std::string& certificateFilename,const std::string& privateKeyFilename);
        //bool BeginTLS(const char* bindAddress,uint16_t bindPort,int timeout);
        virtual int Run();
		void Send(void* ssl,char* data,int dataByteSize);
		virtual bool OnConnected(ConnectedSocket* socket){ return true; }
	    virtual bool OnDataTLS(ConnectedSocket* socket,void* ssl,char* data,int dataByteSize)=0;
	protected:
		bool LoadCertAndKeyFromMemory(SSL_CTX* ctx, const std::string& certBuffer, const std::string& keyBuffer);
	private:
		virtual bool OnData(ConnectedSocket* socket,char* data,int dataByteSize){return true;}
		std::string m_certBuffer;
		std::string m_keyBuffer;
};
