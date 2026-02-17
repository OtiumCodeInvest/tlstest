#ifdef _WIN32
#include "windows.h"
#endif

#ifdef __linux__
#include <unistd.h>			//readlink
#include <libgen.h>			//dirname
#include <pwd.h>			//getpwuid
#include <dirent.h>
#include <sys/stat.h>
#endif

#ifdef __APPLE__
#include <sys/stat.h>
#include <libgen.h>
#include <sys/dir.h>
#include <sys/dirent.h>
#include <mach-o/dyld.h>
#endif

#include <fstream>
#include <sstream>
#include <algorithm>
#include "shared/types.h"
#include "shared/file.h"
#include "std_ext.h"

#include <filesystem>

bool File::Delete(const char* filename) {
#ifdef _WIN32
	return DeleteFile(filename);
#else
	return std::remove(filename);
#endif
}

std::string::size_type find_last_path_separator(const std::string& path) {
    // Define common path separators
    const char windows_separator = '\\';
    const char unix_separator = '/';

    std::string::size_type pos_win = path.rfind(windows_separator);
    std::string::size_type pos_unix = path.rfind(unix_separator);

    if (pos_win != std::string::npos && pos_unix != std::string::npos) {
        return MAX(pos_win, pos_unix); // Return the one that appears later
    } else if (pos_win != std::string::npos) {
        return pos_win;
    } else {
        return pos_unix; // Could be npos if neither is found
    }
}


bool SplitFileName(const std::string& fileName,std::string* dir,std::string* name,std::string* extension) {
	std::filesystem::path p=fileName;
	dir->assign(p.parent_path().string());
	name->assign(p.stem().string());
	extension->assign(p.extension().string());
	return true;
}
bool SplitFileName(const std::string& fileName,std::string* dir,std::string* name) {
	std::filesystem::path p=fileName;
	dir->assign(p.parent_path().string());
	name->assign(p.filename().string());
	return true;
}

bool DirectoryExists(const std::string& path) {
	std::error_code ec;
	const auto isDir = std::filesystem::is_directory(path,ec);
	if(ec) {
		return false;
	}else{
		return isDir;
	}
}
bool FileExists(const std::string& fileName) {
	File file(fileName.c_str());
	return file.Exists();
}

bool SaveFile(const std::string& filename,const void* p,size_t len) {
	std::string fn=GetFileNameRemap(filename);
	FILE* fp=fopen(fn.c_str(),"wb");
	if(!fp)
		return false;
	size_t res=fwrite(p,1,len,fp);
	fclose(fp);
	return res==len ? true : false;
}
bool SaveFile(const std::string& filename,const std::vector<char>& data) {
	return SaveFile(filename,data.data(),data.size());
}
bool SaveFile(const std::string& filename,const std::vector<uint8_t>& data) {
	return SaveFile(filename,data.data(),data.size());
}

#ifdef _WIN32
#define CP_UTF8                   65001       // UTF-8 translation
std::wstring str2wstr(std::string const& str) {
	int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
	std::wstring ret(len, '\0');
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), (LPWSTR)ret.data(), (int)ret.size());
	return ret;
}
#endif

bool LoadFileUTF8(std::vector<char>* data, const std::string& filename) {
	std::string fn = GetFileNameRemap(filename);
#ifdef _WIN32
	std::wstring fnw = str2wstr(fn);
	FILE* pf = _wfsopen(fnw.c_str(), L"rb", _SH_DENYNO);
#else
	FILE* pf = fopen(fn.c_str(), "rb");
#endif
	bool success = false;
	if (pf) {
		fseek(pf, 0, SEEK_END);   // non-portable
		int byteSize = (int)ftell(pf);
		rewind(pf);
		if (byteSize >= 0) {
			data->resize(byteSize);
			void* buf = data->data();
			if ((int)fread(buf, 1, byteSize, pf) == byteSize) {
				success = true;
			}
		}
		fclose(pf);
	}
	return success;
}


bool LoadFile(std::vector<char>* data,const std::string& filename) {
	std::string fn=GetFileNameRemap(filename);
#ifdef _WIN32
	FILE* pf=_fsopen(fn.c_str(),"rb",_SH_DENYNO);
#else
	FILE * pf=fopen(fn.c_str(),"rb");
#endif
	bool success=false;
	if(pf) {
		fseek(pf,0,SEEK_END);   // non-portable
		int byteSize=(int)ftell(pf);
		rewind(pf);
		if(byteSize>=0) {
			data->resize(byteSize);
			void* buf=data->data();
			if((int)fread(buf,1,byteSize,pf)==byteSize) {
				success=true;
			}
		}
		fclose(pf);
	}
	return success;
}

std::string LoadFile(const std::string& filename,bool binary) {
	std::string fn=GetFileNameRemap(filename);
	std::string result;
	std::ifstream stream(fn,std::ios::ate|(binary ? std::ios::binary:std::ios_base::openmode(0)));
	if(!stream.is_open()) {
		return result;
	}
	result.reserve(stream.tellg());
	stream.seekg(0,std::ios::beg);
	result.assign((std::istreambuf_iterator<char>(stream)),std::istreambuf_iterator<char>());
	return result;
}

struct FileNameRemap {
	std::string m_alias;
	std::string m_path;
};
int g_remapCount=0;
FileNameRemap g_remapList[16];

void RemoveFilePathRemaps() {
	for(int i=0;i!=g_remapCount;i++) {
		g_remapList[i]={};
	}
}

void AddFilePathRemap(const char* alias,const char* path) {
	if(g_remapCount==countof(g_remapList))
		FATAL("AddFilePathRemap out of space");
	for(int i=0;i!=g_remapCount;i++) {
		if(g_remapList[i].m_alias==alias) {
			g_remapList[i].m_path=path;
			return;
		}
	}
	g_remapList[g_remapCount].m_alias=alias;
	g_remapList[g_remapCount++].m_path=path;
}
void AddFilePathRemap(const char* alias,const std::string& path) {
	AddFilePathRemap(alias,path.c_str());
}

std::string GetFileNameRemapString(const char* fileName) {
	char buf[512];
	const char* p=fileName;
	char* b=buf;
	while(true) {
		int i=0;
		for(;i!=g_remapCount;i++) {
			//uprintf("%d %s->%s",i,g_remapList[i].m_alias.AsChar(),g_remapList[i].m_path.AsChar());
			if(g_remapList[i].m_alias=="~") {
				if(p==fileName && !strncmp(p,g_remapList[i].m_alias.c_str(),g_remapList[i].m_alias.size())) {
					b+=g_remapList[i].m_path.copy(b,int((buf+sizeof(buf))-b),0);
					p+=g_remapList[i].m_alias.size();
					break;
				}

			}else
			if(!strncmp(p,g_remapList[i].m_alias.c_str(),g_remapList[i].m_alias.size())) {
				b+=g_remapList[i].m_path.copy(b,int((buf+sizeof(buf))-b),0);
				p+=g_remapList[i].m_alias.size();
				break;
			}
		}
		if(i==g_remapCount) {
			*b=*p++;
			if(*b++==0)
				break;
		}
	}
	return std::string(buf);
}

std::string GetFileNameRemap(const char* fileName) {
	std::string str=GetFileNameRemapString(fileName);
	stdx::ReplaceAll(&str,"\\","/");

	if(str.find('$')!=std::string::npos) {
		str=GetFileNameRemapString(str.c_str());
	}


	if(str.find('$')!=std::string::npos) {
		FATAL("GetFileNameRemap unable to remap path %s",fileName);			//probably missing alias
	}
	return str;
}
std::string GetFileNameRemap(const std::string& fileName) {
	return GetFileNameRemap(fileName.c_str());
}

#ifdef _WIN32
int File::GetSize() {
	WIN32_FIND_DATAA fd;
	HANDLE h=FindFirstFileA(m_strFileName.c_str(),&fd);
	if(h==INVALID_HANDLE_VALUE) return -1;
	FindClose(h);
	return fd.nFileSizeLow;
}
std::string GetExecutablePath() {
	char p[MAX_PATH];
	HMODULE hModule=GetModuleHandleW(NULL);
	GetModuleFileName(hModule,p,MAX_PATH);
	std::string path;
	path=p;
	stdx::ReplaceAll(&path,"\\","/");
	//path.erase(path.begin()+path.rfind('/')+1,path.end());
	return path;
}
std::string GetExecutableDir() {
	char p[MAX_PATH];
	HMODULE hModule=GetModuleHandleW(NULL);
	GetModuleFileName(hModule,p,MAX_PATH);
	std::string path;
	path=p;
	stdx::ReplaceAll(&path,"\\","/");
	path.erase(path.begin()+path.rfind('/')+1,path.end());
	return path;
}
#endif

#ifdef __linux__
std::string GetExecutableDir() {
	char result[ PATH_MAX ];
	ssize_t count = readlink("/proc/self/exe", result, PATH_MAX-1);
	const char *path;
	if(count != -1) {
		result[count]=0;
		path = dirname(result);
		return std::string(path)+"/";
	}
	return std::string("");
}
std::string GetExecutablePath() {
	char result[ PATH_MAX ];
	ssize_t count = readlink("/proc/self/exe", result, PATH_MAX-1);
	if(count != -1) {
		result[count]=0;
		return std::string(result);
	}
	return std::string("");
}
std::string GetHomeDir() {
	const char* home=getenv("HOME");
	if(!home)
		home = getpwuid(getuid())->pw_dir;
	return std::string(home);
}
std::string GetTempDirectory() {
	return "/tmp/";
}

#endif

#ifdef __APPLE__
#include <cassert>

std::string GetExecutableDir() {
	std::string exePath = GetExecutablePath();
	std::string result = exePath;
	return std::string(dirname_r(exePath.data(), result.data())) + "/";
}

std::string GetExecutablePath() {
	char buf[PATH_MAX];
	uint32_t bufsize = PATH_MAX;
	int status = _NSGetExecutablePath(buf, &bufsize);
	if(status == 0)
		return std::string(buf);

	assert(status == -1);
	char* tmp = new char[bufsize];
	status = _NSGetExecutablePath(tmp, &bufsize);
	assert(status == 0);
	assert(tmp[bufsize-1] == 0);
	auto result = std::string(tmp);
	delete[] tmp;
	return result;
}

std::string GetHomeDir() {
	const char* home=getenv("HOME");
	return std::string(home);
}
std::string GetTempDirectory() {
	return "/tmp/";
}

#endif
/*
std::string GetResourcePath(const char* path,const char* filename) {
	//uprintf("path: %s", path);
	//uprintf("filename: %s", filename);
	std::string res;
#ifdef SOURCES
	//uprintf("SOURCES defined");
	res=SOURCES;
	res+=path;
	res+=filename;
	return res;
#else
	//uprintf("SOURCES not defined");
	res=GetExecutableDir();
	return res+filename;
#endif
}
*/

#ifdef _WIN32
bool GetDirectoryFiles(std::vector<std::string>* files,std::vector<std::string>* directories,const char* dir) {
	std::string dr=GetFileNameRemap(dir).c_str();
	std::replace(dr.begin(),dr.end(), '/', '\\'); // replace all '/' with '\\'

	if(!stdx::ends_with(dr,"\\")) {
		dr+="\\*";
	}else{
		dr+="*";
	}

	//dr.ReplaceChars('/','\\');
	//if(!dr.EndsWith("\\")) {
	//	dr+="\\*";
	//} else {
	//	dr+="*";
	//}
	WIN32_FIND_DATAA FindFileData={0};
	HANDLE hFind=FindFirstFileA(dr.c_str(),&FindFileData);
	if(hFind==INVALID_HANDLE_VALUE) {
		return false;
	}
	do {
		if(!strcmp(FindFileData.cFileName,".")||!strcmp(FindFileData.cFileName,"..")) {
			continue;
		}
		if(FindFileData.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) {
			if(directories)
				directories->push_back(FindFileData.cFileName);
		} else {
			if(files)
				files->push_back(FindFileData.cFileName);
		}
	} while(FindNextFileA(hFind,&FindFileData));
	FindClose(hFind);
	return true;
}
std::string GetHomeDir() {
	return getenv("USERPROFILE");
}
std::string GetTempDirectory() {
	return getenv("TEMP");
}

#else
int File::GetSize() {
	struct stat buf;
	return stat(m_strFileName.c_str(),&buf)==0 ? buf.st_size : 0;
}
bool GetDirectoryFiles(std::vector<std::string>* files,std::vector<std::string>* directories,const char* dir) {
	std::string dr=GetFileNameRemap(dir).c_str();
	DIR* dp=opendir(dr.c_str());
	if(!dp) {
		//Error::Set("ERROR: GetDirectoryFiles opendir returned zero for %s",dr.c_str());
		return false;
	}
	struct dirent *dirp;
	while((dirp=readdir(dp))!=NULL) {
		if(!strcmp(dirp->d_name,".") || !strcmp(dirp->d_name,".."))
			continue;
		if(dirp->d_type == DT_LNK) {
			struct stat st;
			std::string tmp=stdx::format_string("%s/%s",dir,dirp->d_name);
			stat(tmp.c_str(),&st);
			if(S_ISDIR(st.st_mode)) goto dir;
		}
		if(dirp->d_type == DT_DIR) {
dir:		if(directories)
				directories->push_back(dirp->d_name);
		}else{
			if(files)
				files->push_back(dirp->d_name);
		}
	}
	closedir(dp);
	return true;
}
#endif

//File
File::File() {
}
File::File(const char* pszFileName) {
	SetFileName(pszFileName);
}
File::File(const std::string& fileName) {
	SetFileName(fileName.c_str());
}
void File::SetFileName(const std::string& pszFileName) {
	SetFileName(pszFileName.c_str());
}
void File::SetFileName(const char* pszFileName) {
	m_strFileName=GetFileNameRemap(pszFileName).c_str();
#ifndef _WIN32
	char* path=realpath(m_strFileName.c_str(),NULL); //resolve symlink to real path
	if(path) {
		m_strFileName.assign(path);
		free(path);
	}
#endif
}

File::~File() {}

bool File::Exists() {
	FILE* pFile=fopen(m_strFileName.c_str(),"rb");
    //uprintf("exists %s %p", m_strFileName.c_str(),pFile);
	if(pFile) {
        fclose(pFile);
        return true;
    }
    return false;
}
bool File::Read(void* buffer,int bufferBytesize)const {
#ifdef _WIN32
	FILE* pf=_fsopen(m_strFileName.c_str(),"rb",_SH_DENYNO);
#else
	FILE * pf=fopen(m_strFileName.c_str(),"rb");
#endif
	bool success=false;
	if(pf) {
		fseek(pf,0,SEEK_END);   // non-portable
		int byteSize=(int)ftell(pf);
		rewind(pf);
		if(byteSize==bufferBytesize) {
			if((int)fread(buffer,1,byteSize,pf)==byteSize) {
				success=true;
			}
		}
		fclose(pf);
	}
	return success;
}

bool File::Read(std::string* buf)const {
#ifdef _WIN32
	FILE* pf=_fsopen(m_strFileName.c_str(),"rb",_SH_DENYNO);
#else
	FILE * pf=fopen(m_strFileName.c_str(),"rb");
#endif
	bool success=false;
	if(pf) {
		fseek(pf,0,SEEK_END);   // non-portable
		int byteSize=(int)ftell(pf);
		rewind(pf);
		if(byteSize>=0) {
			buf->resize(byteSize);
			if((int)fread(&buf->front(),1,byteSize,pf)==byteSize) {
				success=true;
			}
		}
		fclose(pf);
	}
	return success;
}
bool File::Read(std::vector<char>* buf)const {
#ifdef _WIN32
	FILE* pf=_fsopen(m_strFileName.c_str(),"rb",_SH_DENYNO);
#else
	FILE * pf=fopen(m_strFileName.c_str(),"rb");
#endif
	bool success=false;
	if(pf) {
		fseek(pf,0,SEEK_END);   // non-portable
		int byteSize=(int)ftell(pf);
		rewind(pf);
		if(byteSize>=0) {
			buf->resize(byteSize);
			if((int)fread(&buf->front(),1,byteSize,pf)==byteSize) {
				success=true;
			}
		}
		fclose(pf);
	}
	return success;
}
bool File::Read(std::vector<uint8_t>* buf)const {
#ifdef _WIN32
	FILE* pf=_fsopen(m_strFileName.c_str(),"rb",_SH_DENYNO);
#else
	FILE * pf=fopen(m_strFileName.c_str(),"rb");
#endif
	bool success=false;
	if(pf) {
		fseek(pf,0,SEEK_END);   // non-portable
		int byteSize=(int)ftell(pf);
		rewind(pf);
		if(byteSize>=0) {
			buf->resize(byteSize);
			if((int)fread(&buf->front(),1,byteSize,pf)==byteSize) {
				success=true;
			}
		}
		fclose(pf);
	}
	return success;
}
bool File::Write(const void* p,int len) {
	FILE* fp=fopen(m_strFileName.c_str(),"wb");
	if(!fp)
		return false;
	int res=(int)fwrite(p,1,len,fp);
	fclose(fp);
	return res==len ? true : false;
}

//bool File::Write(const MemoryBuffer& mb) {
//	return Write(mb.Data(),mb.ByteSize());
//}
bool File::Write(const std::vector<char>& buf) {
	return Write((const void*)buf.data(),(int)buf.size());
}
bool File::Write(const std::vector<uint8_t>& buf) {
	return Write((const void*)buf.data(),(int)buf.size());
}
bool File::Write(const std::string& buf) {
	return Write((const void*)buf.data(),(int)buf.size());
}

bool File::Append(const void* p,int len) {
	FILE* fp=fopen(m_strFileName.c_str(),"ab");
	if(!fp)
		return false;
	int res=(int)fwrite(p,1,len,fp);
	fclose(fp);
	return res==len ? true : false;
}

bool File::AppendString(const char* p) {
	return Append(p,(int)strlen(p));
}

bool CopyFile1(const std::string& filenameSrc,const std::string& filenameDst) {
	std::string sn=GetFileNameRemap(filenameSrc);
	std::string dn=GetFileNameRemap(filenameDst);
	std::ifstream  src(sn.c_str(),std::ios::binary);
	std::ofstream  dst(dn.c_str(),std::ios::binary);
	dst<<src.rdbuf();
	dst.close();
	src.close();
	File fileSrc(filenameSrc);
	File fileDst(filenameDst);
	return fileSrc.GetSize()==fileDst.GetSize();
}

#ifdef _WIN32
bool CreateDirRecursive(const std::string& strDirectoryName) {
	std::string dr=GetFileNameRemap(strDirectoryName).c_str();
	stdx::ReplaceAll(&dr,"/","\\");
	const char* DirName=dr.c_str();
	char my_dir_name[512];
	size_t iInputLen=strlen(DirName);
	//XASSERT(iInputLen < sizeof(my_dir_name));
	strcpy_s(my_dir_name,sizeof(my_dir_name),DirName);

	if(my_dir_name[iInputLen-1]=='\\'||my_dir_name[iInputLen-1]=='/') {
		my_dir_name[iInputLen-1]=0;
	}
	char* parent_dir=my_dir_name;
	while(parent_dir=strpbrk(parent_dir,"/\\")) {
		*parent_dir=0;
		if(*my_dir_name != 0) {
			if(!::CreateDirectoryA(my_dir_name,NULL)) {
				if(GetLastError()==ERROR_PATH_NOT_FOUND) {
					return false;
				}
			}
		}
		*parent_dir='\\';
		parent_dir++;
	}
	if(!::CreateDirectoryA(my_dir_name,NULL)) {
		if(GetLastError()==ERROR_PATH_NOT_FOUND) {
			return false;
		}
	}
	return true;
//	::CreateDirectoryA(my_dir_name,NULL);
//	return ::CreateDirectoryA(my_dir_name,NULL) ? true:false;
}
#else
bool CreateDirRecursive(const std::string& strDirectoryName) {
	std::string sr=GetFileNameRemap(strDirectoryName).c_str();

	const char* DirName=sr.c_str();

	//uprintf("NOTIFY: CreateDirRecursive %s",DirName);

	char my_dir_name[2048];
	size_t iInputLen=strlen(DirName);

	if(iInputLen>=sizeof(my_dir_name)) {
		uprintf("WARNING: CreateDirRecursive path %d longer than buf %d\n",iInputLen,sizeof(my_dir_name));
		return false;
	}
	strcpy(my_dir_name,DirName);
	if(my_dir_name[iInputLen-1]=='/') {
		my_dir_name[iInputLen-1]=0;
	}
	char *parent_dir=my_dir_name;
	while((parent_dir=strchr(parent_dir,'/'))) {
		*parent_dir=0;
		if(*my_dir_name != 0) {
			if(::mkdir(my_dir_name,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)!=0) {
				if(errno!=EEXIST) {
					uprintf("WARNING: CreateDirRecursive mkdir 0 error %d\n",errno);
					return false;
				}
			}
		}
		*parent_dir='/';
		parent_dir++;
	}
	if(!::mkdir(my_dir_name,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		if(errno!=EEXIST) {
			uprintf("WARNING: CreateDirRecursive %s mkdir 1 error %d\n",strDirectoryName.c_str(),errno);
			return false;
		}
	}
	return true;
}
#endif

#ifdef WIN32
FileTime File::GetWriteTime() {
	XFILETIME lTime;
	HANDLE hHandle=CreateFileA(m_strFileName.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
	if(hHandle==INVALID_HANDLE_VALUE) return FileTime();
	BOOL bRes=::GetFileTime(hHandle,NULL,NULL,(LPFILETIME)&lTime);
	CloseHandle(hHandle);
	if(!bRes)return FileTime();
	return FileTime(lTime);
}
#endif

#if __linux__
FileTime File::GetWriteTime() {
	struct stat buf;
	if(stat(m_strFileName.c_str(),&buf)!=0) return FileTime();
	timespec* ts=&buf.st_mtim;
	XFILETIME* fileTime=(XFILETIME*)ts;
	FileTime ft(*fileTime);
	return ft;
}
#endif

#if __APPLE__
FileTime File::GetWriteTime() {
	struct stat buf;
	if(stat(m_strFileName.c_str(),&buf)!=0) return FileTime();
	timespec* ts=&buf.st_mtimespec;
	XFILETIME* fileTime=(XFILETIME*)ts;
	FileTime ft(*fileTime);
	return ft;
}
#endif

FileTime::FileTime(XFILETIME FileTime) {
	m_FileTime=FileTime;
	m_bValid=true;
}
FileTime::FileTime() {
    m_FileTime.dwLowDateTime=0;
    m_FileTime.dwHighDateTime=0;
	m_bValid=false;
}
bool FileTime::IsValid() {
	return m_bValid;
}
bool FileTime::operator>(const FileTime& ft)const {
	timespec* a=(timespec*)&m_FileTime;
	timespec* b=(timespec*)&ft.m_FileTime;
	if(a->tv_sec==b->tv_sec) {
		return a->tv_nsec>b->tv_nsec;
	}
	return a->tv_sec>b->tv_sec;
}
bool FileTime::operator<(const FileTime& ft)const {
	timespec* a=(timespec*)&m_FileTime;
	timespec* b=(timespec*)&ft.m_FileTime;
	if(a->tv_sec==b->tv_sec) {
		return a->tv_nsec<b->tv_nsec;
	}
	return a->tv_sec<b->tv_sec;
}
bool FileTime::operator>=(const FileTime& ft)const {
	timespec* a=(timespec*)&m_FileTime;
	timespec* b=(timespec*)&ft.m_FileTime;
	if(a->tv_sec==b->tv_sec) {
		return a->tv_nsec>=b->tv_nsec;
	}
	return a->tv_sec>=b->tv_sec;
}

bool FileTime::operator==(const FileTime& ft)const {
	timespec* a=(timespec*)&m_FileTime;
	timespec* b=(timespec*)&ft.m_FileTime;
	return a->tv_sec==b->tv_sec && a->tv_nsec==b->tv_nsec;
}

uint64 FileTime::AsEpoch()const {
	timespec* a=(timespec*)&m_FileTime;
	return a->tv_sec;
}
