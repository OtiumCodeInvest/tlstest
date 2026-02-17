#ifndef __TIME_H__
#define __TIME_H__

#include "types.h"
#include <vector>
#include <string>

class Time {
	public:
		Time() {
			m_lHDTicksStart=0;
			m_lHDTickFrequency=0;
		}
		static double GetTime();

	protected:
		uint64 m_lHDTicksStart;
		uint64 m_lHDTickFrequency;
};

uint64_t GetTimer();
uint64_t GetTimeEpochMicroseconds();
uint64_t GetTimeEpochMilliseconds();
uint64_t ElapsedMilliseconds(uint64_t t);
uint64_t ElapsedMicroseconds(uint64_t t);

std::string TimeEpochMicrosecondsToString(uint64_t microsecondsUTC);
std::string TimeEpochMicrosecondsToFileString(uint64_t microsecondsUTC);

#define HISTORYCOUNT 128

template<int _TBits,typename _TType> struct XSimpleHistory {
	XSimpleHistory() {
		m_lPosition=0;
	}
	inline void Set(_TType Value) {
		m_Values[m_lPosition&((1<<_TBits)-1)]=Value;
		m_lPosition++;
	}
	inline _TType Max()const {
		int lCount=1<<_TBits;
		if(lCount>m_lPosition)lCount=m_lPosition;
		_TType Max=m_Values[0];
		for(int a=0;a!=lCount;a++) {
			if(Max<m_Values[a])Max=m_Values[a];
		}
		return Max;
	}
	inline _TType Average()const {
		int lCount=1<<_TBits;
		if(lCount>m_lPosition)lCount=m_lPosition;
		_TType Average=m_Values[0];
		for(int a=1;a!=lCount;a++) {
			Average+=m_Values[a];
		}
		return Average/(_TType)lCount;
	}
	inline int Get(_TType Array[1<<_TBits])const {
		int lCount=1<<_TBits;
		if(lCount>m_lPosition)lCount=m_lPosition;
		int lPosition=m_lPosition;
		for(int a=0;a!=lCount;a++) {
			lPosition--;
			Array[a]=m_Values[lPosition&((1<<_TBits)-1)];
		}
		return 	lCount;	
	}
	int m_lPosition;
	_TType m_Values[1<<_TBits];
};


struct DisplayTimer {
	uint8 m_depth;
	uint32 m_count;
	uint32 m_core;
	float m_time;
	std::string m_name;
	struct Bar {
		float m_start;
		float m_end;
		uint32 m_color;
	};
	std::vector<Bar> m_bars;
};

//Multithread profiler
struct TempTimerMT {
	const char* m_name;
	uint32 m_color;
	uint32 m_core; //Only 6 bits used
	int64 m_startTime;
	int64 m_time;
};

struct TimerMT;
#define MAX_NUMBER_MT_IDS 256
class ProfilerMT {
	public:
		ProfilerMT();
		void SetRange(float rangeMilliseconds){m_rangeMilliseconds=rangeMilliseconds;}
		void PrintDisplayTimers(std::vector<DisplayTimer>& display);
		void Reset();
		virtual void StartTimer(const TimerMT* timer,const char* name,uint32 color);
		virtual void EndTimer(const TimerMT* timer);
		virtual int NextTimerId();
		void GetDisplayTimers(std::vector<DisplayTimer>& display);
	protected:
		volatile int32 m_id;
		TempTimerMT m_tempTimers[MAX_NUMBER_MT_IDS];
		float m_rangeMilliseconds;
};
struct TimerMT {
	TimerMT(ProfilerMT* profiler);
	ProfilerMT* m_profiler;
	uint8 m_id;
};

//Singlethread profiler
#define MAX_NUMBER_TIMERS 0x100
#define MAX_NUMBER_DRAW_TIMERS 0x100

struct TempTimer {
	uint8 m_depth;
	uint8 m_lNextSameHash;
	uint32 m_count;
	uint32 m_color;
	uint32 m_core;
	int64 m_time;
	const char* m_name;
	XSimpleHistory<6,int64> m_Times;
};

struct Timer {
	int64 m_startTime;
	int64 m_usedTime;
	char m_name[32];
	uint32 m_color;
	uint32 m_depth;
	uint32 m_core;
};
class Profiler {
	public:
		Profiler();
		~Profiler();
		void SetRange(float rangeMilliseconds){m_rangeMilliseconds=rangeMilliseconds;}
		void PrintDisplayTimers(std::vector<DisplayTimer>& display);
		void Reset();
		virtual Timer* StartTimer(const char* pszName,uint32 lColor);
		void GetDisplayTimers(std::vector<DisplayTimer>& display);
		virtual void EndTimer(Timer* pThreadTimer);
		void StartSubTime(Timer* pThreadTimer);
		void StopSubTime(Timer* pThreadTimer);
		Timer m_timers[MAX_NUMBER_TIMERS];
		uint32 m_depth;
		uint32 m_writePosition;
		uint32 m_readPosition;
		int m_numTempTimers;
		float m_rangeMilliseconds;
		//TempTimer m_tempTimers[MAX_NUMBER_DRAW_TIMERS];
		//TempTimer m_tempTimersPrev[MAX_NUMBER_DRAW_TIMERS];
		TempTimer* m_tempTimers;
		TempTimer* m_tempTimersPrev;

		int m_numTempTimersPrev;
		XSimpleHistory<7,uint32> m_NumberTimers;
};



inline Timer* StartTimer(Profiler* profiler,const char* name,uint32 color) {if(!profiler)return 0;return profiler->StartTimer(name,color);}
inline void EndTimer(Timer* timer,Profiler* profiler) {if(profiler)profiler->EndTimer(timer);}
inline void StartSubTimer(Timer* timer,Profiler* profiler) {if(profiler)profiler->StartSubTime(timer);}
inline void EndSubTimer(Timer* timer,Profiler* profiler) {if(profiler)profiler->StopSubTime(timer);}

#define START_TIMER(timer,profiler,name,color) Timer* timer=StartTimer(profiler,name,color);
#define END_TIMER(timer,profiler) EndTimer(timer,profiler);

#define START_TIMER_MT(timer,profiler,name,color) static TimerMT timer(profiler);profiler->StartTimer(&timer,name,color);
#define END_TIMER_MT(timer,profiler) profiler->EndTimer(&timer);

#endif//__TIME_H__