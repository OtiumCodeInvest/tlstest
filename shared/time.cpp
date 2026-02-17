#include "time.h"
#include <string>
#include <chrono>
#include <string.h>
#include "std_ext.h"

Time g_time;

uint64_t GetTimer() {
	auto t=std::chrono::steady_clock::now().time_since_epoch();
	return std::chrono::duration_cast<std::chrono::microseconds>(t).count();
}

double Time::GetTime() {
	if(!g_time.m_lHDTickFrequency) {
		//QueryPerformanceFrequency((LARGE_INTEGER*)&g_time.m_lHDTickFrequency);
		//QueryPerformanceCounter((LARGE_INTEGER*)&g_time.m_lHDTicksStart);
		g_time.m_lHDTickFrequency=1000000;
		g_time.m_lHDTicksStart=GetTimer();
	}
	uint64 lHDTicks=GetTimer();
	//QueryPerformanceCounter((LARGE_INTEGER*)&lHDTicks);
	return ((double)(lHDTicks-g_time.m_lHDTicksStart)/(double)(g_time.m_lHDTickFrequency));
}

uint64_t GetTimerU64() {
	uint64_t microsecondsUTC=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	return microsecondsUTC;
}
uint64_t GetTimeEpochMicroseconds() {
	return GetTimerU64();
}
uint64_t GetTimeEpochMilliseconds(){
	return GetTimerU64()/1000L;
}
uint64_t ElapsedMilliseconds(uint64_t t) {
	return ElapsedMicroseconds(t)/1000;
}

uint64_t ElapsedMicroseconds(uint64_t t) {
	return GetTimer()-t;
}

/*
uint64_t GetTimer() {
	//auto t=std::chrono::high_resolution_clock::now().time_since_epoch();
	uint64_t microsecondsUTC=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	return microsecondsUTC;
}
*/
uint64 TimersGetHDTicks() {
	uint64 ticks=GetTimerU64();
	//QueryPerformanceCounter((LARGE_INTEGER*)&ticks);
	return ticks;
}

uint64 TimersGetHDTicksSecond() {
	uint64 frequency=1000000;
	//QueryPerformanceFrequency((LARGE_INTEGER*)&frequency);
	return frequency;
}



//ProfilerMT
TimerMT::TimerMT(ProfilerMT* profiler) {
	m_profiler=profiler;
	int id=profiler->NextTimerId();
	if(id>=MAX_NUMBER_MT_IDS)
		FATAL("TimerMT::TimerMT");
	m_id=id;
}
ProfilerMT::ProfilerMT() {
	m_rangeMilliseconds=1000;
	memset(m_tempTimers,0,sizeof(m_tempTimers));
	m_id=0;
}
int ProfilerMT::NextTimerId() {
	FATAL("ProfilerMT::NextTimerId");
	//return InterlockedIncrement(&m_id)-1;
	return 0;
}
void ProfilerMT::PrintDisplayTimers(std::vector<DisplayTimer>& display) {
}
void ProfilerMT::Reset() {
}
void ProfilerMT::StartTimer(const TimerMT* timer,const char* name,uint32 color) {
	//ASSERT(timer->m_profiler==profiler);
	TempTimerMT* tt=m_tempTimers+timer->m_id;
	tt->m_color=color;
	tt->m_name=name;
	tt->m_core=0;//GetCurrentProcessorNumber();
	tt->m_startTime=TimersGetHDTicks();
}
void ProfilerMT::EndTimer(const TimerMT* timer) {
	TempTimerMT* tt=m_tempTimers+timer->m_id;
	tt->m_time=TimersGetHDTicks()-tt->m_startTime;
}
void ProfilerMT::GetDisplayTimers(std::vector<DisplayTimer>& display) {
	int64 cyclesSecond=TimersGetHDTicksSecond();
	int64 cyclesMillisecond=cyclesSecond/1000;
	float range=(float)((double)cyclesSecond/(1000.0f/m_rangeMilliseconds));
	for(int i=0;i!=m_id;i++) {
		TempTimerMT* tt=m_tempTimers+i;
		if(!tt->m_name)
			continue;
		float barEnd=(float)((double)tt->m_time/(double)range);
		DisplayTimer dt;
		dt.m_bars.push_back({0,barEnd,0x80000000|tt->m_color});
		dt.m_depth=0;
		dt.m_count=0;
		dt.m_name=tt->m_name;
		dt.m_time=(float)((double)tt->m_time/(double)cyclesMillisecond);
		display.push_back(dt);
	}
}

//Profiler
Profiler::Profiler() {
	m_tempTimers=new TempTimer[MAX_NUMBER_DRAW_TIMERS];
	m_tempTimersPrev=new TempTimer[MAX_NUMBER_DRAW_TIMERS];
	memset((char*)m_tempTimers,0,sizeof(*m_tempTimers)*MAX_NUMBER_DRAW_TIMERS);
	memset((char*)m_tempTimersPrev,0,sizeof(*m_tempTimersPrev)*MAX_NUMBER_DRAW_TIMERS);
	m_numTempTimers=0;
	m_numTempTimersPrev=0;
	m_rangeMilliseconds=1000;
	memset(m_timers,0,sizeof(m_timers));
	m_depth=0;
	m_writePosition=0;
	m_readPosition=0;
}
Profiler::~Profiler() {
	delete[] m_tempTimers;
	delete[] m_tempTimersPrev;
}

void Profiler::PrintDisplayTimers(std::vector<DisplayTimer>& display) {
	for(int i=0;i!=(int)display.size();i++) {
		std::string spaces0(display[i].m_depth,' ');
		uprintf("timer %d %s%s %7.2fms",i,spaces0.c_str(),display[i].m_name.c_str(),display[i].m_time);
	}
}
void Profiler::Reset() {
	m_depth=0;
	m_numTempTimers=0;
	m_readPosition=m_writePosition;
	memset((char*)m_tempTimers,0,sizeof(m_tempTimers));
}
Timer* Profiler::StartTimer(const char* name,uint32 lColor) {
	Timer* timer=m_timers+(m_writePosition&(MAX_NUMBER_TIMERS-1));
	strncpy(timer->m_name,name,sizeof(timer->m_name)-1);
	timer->m_name[sizeof(timer->m_name)-1]=0;
  	timer->m_color=lColor;
	timer->m_depth=m_depth;
	m_writePosition++;
	m_depth++;
	timer->m_usedTime=0;
	timer->m_core=0;//GetCurrentProcessorNumber();
	timer->m_startTime=TimersGetHDTicks();
	return timer;
}
void Profiler::EndTimer(Timer* timer) {
	if((m_writePosition-m_readPosition)>MAX_NUMBER_TIMERS)return;
	if(timer-m_timers>=MAX_NUMBER_TIMERS)return;
	if(timer->m_startTime!=-1) {
		timer->m_usedTime+=TimersGetHDTicks()-timer->m_startTime;
	}
	m_depth--;
}
void Profiler::StartSubTime(Timer* timer) {
	timer->m_startTime=TimersGetHDTicks();
}
void Profiler::StopSubTime(Timer* timer) {
	timer->m_usedTime+=TimersGetHDTicks()-timer->m_startTime;
	timer->m_startTime=-1;
}
void Profiler::GetDisplayTimers(std::vector<DisplayTimer>& display) {
	//Backup draw timers
	TempTimer tempTimersPrev[MAX_NUMBER_DRAW_TIMERS];
	int numTempTimersPrev=m_numTempTimers;
	memcpy(tempTimersPrev,m_tempTimers,m_numTempTimers*sizeof(TempTimer));
	m_depth=0;
	//Collect drawtimers
	int numTempTimers=0;
	uint8 displayDepth=0;
	Timer* timer=m_timers+(m_readPosition&(MAX_NUMBER_TIMERS-1));
	if(m_writePosition-m_readPosition<MAX_NUMBER_TIMERS) {
		while(m_readPosition!=m_writePosition) {
			timer=m_timers+(m_readPosition&(MAX_NUMBER_TIMERS-1));
			displayDepth=timer->m_depth;
			TempTimer* temp_timer=0;
			if(numTempTimers) {
				for(int a=numTempTimers-1;a>0;a--) {
					if(m_tempTimers[a].m_depth<displayDepth)break;		
					if(m_tempTimers[a].m_depth==displayDepth && !strcmp(m_tempTimers[a].m_name,timer->m_name)) {
						temp_timer=m_tempTimers+a;
						temp_timer->m_count++;
						break;
					}
				}
			}
			if(!temp_timer) {
				temp_timer=m_tempTimers+numTempTimers++;
				temp_timer->m_time=0;
				temp_timer->m_count=1;
				temp_timer->m_core=0;
			}
			temp_timer->m_time+=timer->m_usedTime;
			temp_timer->m_color=timer->m_color;
			temp_timer->m_depth=displayDepth;
			temp_timer->m_core|=1<<timer->m_core;
			//XStringBase::Copy(temp_timer->m_name,timer->m_szName,MAXTIMERNAMELENGTH);
			temp_timer->m_name=timer->m_name;
			m_readPosition++;
			if(numTempTimers==MAX_NUMBER_DRAW_TIMERS)break;
		}
	}
	m_numTempTimers=numTempTimers;
	m_readPosition=m_writePosition;

	//Copy values from previus drawtimers
	uint8 HashLookup[0x100];
	memset(HashLookup,0xff,sizeof(HashLookup));
	for(int a=0;a!=numTempTimersPrev;a++) {
		uint8 lHash=tempTimersPrev[a].m_name[0];
		tempTimersPrev[a].m_lNextSameHash=HashLookup[lHash];
		HashLookup[lHash]=a;
	}
	for(int a=0;a!=m_numTempTimers;a++) {
		TempTimer* temp_timer=m_tempTimers+a;
		uint8 lHash=temp_timer->m_name[0];
		uint8 lIndex=HashLookup[lHash];
		while(lIndex!=0xff) {
			TempTimer* temp_timerOld=tempTimersPrev+lIndex;
			if(temp_timerOld->m_depth==temp_timer->m_depth && !strcmp(temp_timer->m_name,temp_timerOld->m_name)) {
				temp_timer->m_Times=temp_timerOld->m_Times;
				break;
			}
			lIndex=temp_timerOld->m_lNextSameHash;
		}		
		temp_timer->m_Times.Set(temp_timer->m_time);
	}

	int64 cyclesSecond=TimersGetHDTicksSecond();
	int64 cyclesMillisecond=cyclesSecond/1000;
	TempTimer tempTimers[MAX_NUMBER_DRAW_TIMERS];
	float rangeMilliseconds=m_rangeMilliseconds;
	if(m_rangeMilliseconds)rangeMilliseconds=m_rangeMilliseconds;
	float range=(float)((double)cyclesSecond/(1000.0f/rangeMilliseconds));
	TempTimer* ptempTimers=m_tempTimersPrev;
	numTempTimers=m_numTempTimers;
	m_numTempTimersPrev=numTempTimers;
	memcpy(ptempTimers,m_tempTimers,numTempTimers*sizeof(TempTimer));
	memcpy(tempTimers,ptempTimers,numTempTimers*sizeof(TempTimer));
	m_NumberTimers.Set(numTempTimers);
	//uint32 bar_maxNumberTimers=m_NumberTimers.Max();
	//int lPlotLine=0;
	if(numTempTimers) {
		float lBarSizeX=1;
		for(int b=0;b!=numTempTimers;b++) {
			float barEnd=lBarSizeX*(float)((double)tempTimers[b].m_time/(double)range);
			float bar_max=(float)tempTimers[b].m_Times.Max();
			float bar_maxX=lBarSizeX*bar_max/range;
			float time=(float)((double)tempTimers[b].m_time/(double)cyclesMillisecond);
			int64 sum_children_time=0;
			for(int c=b+1;c<numTempTimers;c++) {
				if(tempTimers[b].m_depth>=tempTimers[c].m_depth)break;
				if(tempTimers[b].m_depth+1==tempTimers[c].m_depth) {
					sum_children_time+=tempTimers[c].m_time;
				}
			}
			DisplayTimer display_timer;
			uint32 color=tempTimers[b].m_color&0xffffff;
			if(sum_children_time>tempTimers[b].m_time) {
				display_timer.m_bars.push_back({0,barEnd,0x80000000|color});
			}else{
				float lUnaccountedBarSize=lBarSizeX*(float)(((double)(tempTimers[b].m_time-sum_children_time))/(double)range);
				display_timer.m_bars.push_back({0,barEnd-lUnaccountedBarSize,0x80000000|color});
				display_timer.m_bars.push_back({barEnd-lUnaccountedBarSize,barEnd,0x40000000|color});
			}
			display_timer.m_bars.push_back({bar_maxX,bar_maxX,0xff000000|color});
			display_timer.m_depth=tempTimers[b].m_depth;
			display_timer.m_time=time;
			display_timer.m_count=tempTimers[b].m_count;
			display_timer.m_name=tempTimers[b].m_name;
			display_timer.m_core=tempTimers[b].m_core;
			display.push_back(display_timer);
			tempTimers[b].m_time-=sum_children_time;
		}
		//int64 lCurrentTime=0;
		//int lBarEnd=0;
		//for(int b=0;b!=numTempTimers;b++) {	
			//int lBarStart=(int)((int64)lBarSizeX*lCurrentTime/range);
			//lCurrentTime+=tempTimers[b].m_time;
			//lBarEnd=(int)((int64)lBarSizeX*lCurrentTime/range);
			//Frame.DrawBar(lMenuPixelSplitX+lBarStart,lMenuPixelSplitX+lBarEnd,0,0x80000000|tempTimers[b].m_lColor);
		//}
	}
}

std::string TimeEpochMicrosecondsToFileString(uint64_t microsecondsUTC) {
	uint64_t secondsSince1970=microsecondsUTC/1000000;
	time_t rawtime=secondsSince1970;
	struct tm ts;
#if _WIN32
	(void)gmtime_s(&ts,&rawtime);
#else
	(void)gmtime_r(&rawtime,&ts);
#endif
	return stdx::format_string("%d%02d%02d_%02d%02d",ts.tm_year-100,ts.tm_mon+1,ts.tm_mday,ts.tm_hour,ts.tm_min);
}
std::string TimeEpochMicrosecondsToString(uint64_t microsecondsUTC) {
	uint64_t secondsSince1970=microsecondsUTC/1000000;
	time_t rawtime=secondsSince1970;
	struct tm ts;
#if _WIN32
	(void)gmtime_s(&ts,&rawtime);
#else
	(void)gmtime_r(&rawtime,&ts);
#endif
	return stdx::format_string("%d/%02d/%02d %02d:%02d:%02d:%03d",ts.tm_year+1900,ts.tm_mon+1,ts.tm_mday,ts.tm_hour,ts.tm_min,ts.tm_sec,(int)((microsecondsUTC/1000)%1000));
}

extern "C" {
	Timer* CStartTimer(Profiler* profiler,const char* name,uint32 color){
		return StartTimer(profiler,name,color);
	}
	void CEndTimer(Timer* timer,Profiler* profiler){
		EndTimer(timer,profiler);
	}
	void CStartSubTimer(Timer* timer,Profiler* profiler){
		StartSubTimer(timer,profiler);
	}
	void CEndSubTimer(Timer* timer,Profiler* profiler){
		EndSubTimer(timer,profiler);
	}
};
