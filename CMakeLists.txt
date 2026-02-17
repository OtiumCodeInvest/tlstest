cmake_minimum_required(VERSION 3.10)

project(tlspingpong)

set(CMAKE_DEBUG_POSTFIX d)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

set(CMAKE_CXX_STANDARD 17)

message(STATUS "CMAKE_SYSTEM_PROCESSOR = ${CMAKE_SYSTEM_PROCESSOR}")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(default_build_type "Debug")
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

if (MSVC)
	set(CMAKE_CXX_FLAGS "/nologo /DWIN32=1 /D_WINDOWS /W3 /GR /EHsc /MP /arch:AVX2 /GF /guard:cf- /wd4996 /wd4068 /wd5033 /w14388 /w14389 /w14101 /w14189 /std:c++17 /GS- /Gw /Qspectre- /fp:fast")
	set(CMAKE_CXX_FLAGS_DEBUG "/D_DEBUG /MDd /ZI /Ob0 /Od /RTC1 /Gy")
	set(CMAKE_C_FLAGS "/nologo /DWIN32=1 /D_WINDOWS /W3 /MP /arch:AVX2 /GF /guard:cf- /wd4996 /wd4068 /Qspectre-")
	set(CMAKE_C_FLAGS_DEBUG "/D_DEBUG /MDd /ZI /Ob0 /Od /RTC1 /Gy")
	add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_USE_MATH_DEFINES)
endif ()

if (CMAKE_COMPILER_IS_GNUCC)
	add_compile_options("-Wall")
	add_compile_options("-Wno-uninitialized")
	add_compile_options("-Wno-unused-function")
	add_compile_options("-Wno-unused-parameter")
	add_compile_options("-Wno-unused-but-set-variable")
	add_compile_options("-Wno-deprecated-declarations")
	add_compile_options("-fvisibility=hidden")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-undefined")
endif()


if (UNIX)
	# look for .so files next to the executable ($ORIGIN)
	set(CMAKE_SKIP_RPATH FALSE)
	set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
	set(CMAKE_INSTALL_RPATH $ORIGIN)

	add_definitions(-DUNIX)
	#add_compile_options("-std=c++17")
	find_package(Threads REQUIRED)
	link_libraries(${CMAKE_THREAD_LIBS_INIT})

endif ()

add_definitions(-DCMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

add_subdirectory(shared)
add_subdirectory(serverclient)

set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT "serverclient")
