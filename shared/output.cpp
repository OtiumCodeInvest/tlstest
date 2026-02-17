#ifdef _WIN32
#include <windows.h>
#include <malloc.h>
#endif

#ifdef __linux__
#include <string.h> // memcpy
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <chrono>

#include "shared/output.h"

void OutputDebugStringWrap(const char* str) {
#ifdef _WIN32
	OutputDebugString(str);
#else
	::printf("%s",str);
#endif
}

TPrintCallbackFunc g_printCallback=0;
PrependType g_prependType=PT_NA;

void SetPrintCallback(TPrintCallbackFunc pcb,PrependType prependType) {
	g_prependType=prependType;
	g_printCallback=pcb;
}

int PrintPrepend(char* buf,size_t bufByteSize) {
	if(g_prependType==PT_NA)
		return 0;
	uint64_t microsecondsUTC=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	uint64_t secondsSince1970=microsecondsUTC/1000000;
	time_t rawtime=secondsSince1970;
	struct tm ts;
#if _WIN32
	(void)gmtime_s(&ts,&rawtime);
#else
	(void)gmtime_r(&rawtime,&ts);
#endif
#if 1
	int tlen=snprintf(buf,bufByteSize,"[%d/%02d/%02d %02d:%02d:%02d:%03d] ",ts.tm_year+1900,ts.tm_mon+1,ts.tm_mday,ts.tm_hour,ts.tm_min,ts.tm_sec,(int)((microsecondsUTC/1000)%1000));
#else
	int tlen=snprintf(buf,bufByteSize,"[%d %02d %02d %02d:%02d:%02d] ",ts.tm_year+1900,ts.tm_mon+1,ts.tm_mday,ts.tm_hour,ts.tm_min,ts.tm_sec);
#endif
	return tlen;
}

extern "C" {
	void Print(const char* format,...){
		thread_local static bool newline=true;
		va_list v;
		va_start(v,format);
		int len=vsnprintf(NULL,0,format,v);
		va_end(v);
		char tstr[100];
		int tlen=newline?PrintPrepend(tstr,sizeof(tstr)):0;
		char* str=(char*)malloc(tlen+len+1);
		if(tlen)
			memcpy(str,tstr,tlen);
		va_start(v,format);
		vsnprintf(str+tlen,len+1,format,v);
		va_end(v);
		str[tlen+len]=0;
		newline=str[tlen+len-1]=='\n';
		if(g_printCallback)
			g_printCallback(str);
		free(str);
	}
	void Fatal(const char* file,int line,const char* func,const char* format,...){
		static const char* pformat = "FATAL %s\n\t%s:%d : ";
		int plen=snprintf(nullptr,0,pformat,func,file,line);
		va_list v;
		va_start(v,format);
		int len=vsnprintf(nullptr,0,format,v);
		va_end(v);
#ifdef _WIN32
		char* str=(char*)_malloca(len+plen+2);
#else
		char* str=(char*)malloc(len+plen+2);
#endif
		snprintf(str,plen+1,pformat,func,file,line);
		int offset = plen;
		va_start(v,format);
		vsnprintf(str+offset,len+1,format,v);
		va_end(v);
		offset += len;
		str[offset++]='\n';
		str[offset++]=0;
		uprintf("%s",str);
		if(g_printCallback)
			g_printCallback(str);
#ifdef _WIN32
		_freea(str);
#else
		free(str);
		fflush(0);
#endif
	}
};
