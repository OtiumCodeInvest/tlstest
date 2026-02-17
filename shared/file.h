#pragma once

#include <vector>
#include <string>
#include <stdint.h>

//bool DeleteFile(const std::string& filename);
std::wstring str2wstr(std::string const& str);

bool LoadFile(std::vector<char>* data,const std::string& filename);
bool LoadFileUTF8(std::vector<char>* data, const std::string& filename);
bool SaveFile(const std::string& filename,const void* p,size_t len);
bool SaveFile(const std::string& filename,const std::vector<char>& data);
bool SaveFile(const std::string& filename,const std::vector<uint8_t>& data);
bool FileExists(const std::string& filename);
bool DirectoryExists(const std::string& path);
std::string LoadFile(const std::string& filename,bool binary);

bool CopyFile1(const std::string& filenameSrc,const std::string& filenameDst);

bool SplitFileName(const std::string& fileName,std::string* dir,std::string* name,std::string* extension);
bool SplitFileName(const std::string& fileName,std::string* dir,std::string* name);

void RemoveFilePathRemaps();
void AddFilePathRemap(const char* alias,const char* path);
void AddFilePathRemap(const char* alias,const std::string& path);
std::string GetFileNameRemap(const char* fileName);
std::string GetFileNameRemap(const std::string& fileName);

std::string GetExecutablePath();
std::string GetExecutableDir();
std::string GetHomeDir();
std::string GetTempDirectory();

bool CreateDirRecursive(const std::string& strDirectoryName);

bool GetDirectoryFiles(std::vector<std::string>* files,std::vector<std::string>* directories,const char* dir);

typedef struct _XFILETIME {
    unsigned long dwLowDateTime;
    unsigned long dwHighDateTime;
} 	XFILETIME;

class FileTime {
	public:
		FileTime(XFILETIME FileTime);
		FileTime();
		bool IsValid();
		bool operator<(const FileTime& FileTime)const;
		bool operator>(const FileTime& FileTime)const;
		bool operator>=(const FileTime& FileTime)const;
		bool operator==(const FileTime& FileTime)const;

		uint64_t AsEpoch()const;
		bool m_bValid;
		XFILETIME m_FileTime;
};

class File {
	public:
		File();
		explicit File(const char* pszFileName);
		explicit File(const std::string& pszFileName);
		~File();
		static bool Delete(const char* pszFileName);
		bool Valid()const{return m_strFileName.size() ? true:false;}
		bool Exists();
		void SetFileName(const char* pszFileName);
		void SetFileName(const std::string& pszFileName);
		const char* GetFileName()const{return m_strFileName.c_str();}
		int GetSize();
		bool Read(void* buffer,int bufferBytesize)const;
		bool Read(std::vector<char>* buf)const;
		bool Read(std::vector<uint8_t>* buf)const;
		bool Read(std::string* buf)const;
		bool Write(const void* p,int len);
		bool Write(const std::vector<char>& buf);
		bool Write(const std::vector<uint8_t>& buf);
		bool Write(const std::string& buf);
		bool Append(const void* p,int len);
		bool AppendString(const char* p);
		FileTime GetWriteTime();
	protected:
		std::string m_strFileName;
};
