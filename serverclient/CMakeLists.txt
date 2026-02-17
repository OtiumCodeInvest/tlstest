project(serverclient)

set(FILES
	serverclient.cpp
	socketservertls.cpp
	socketservertls.h
)

if(MSVC)
	include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/3rdparty ${CMAKE_SOURCE_DIR}/3rdparty/OpenSSL/include)
	link_directories(${CMAKE_SOURCE_DIR}/3rdparty/OpenSSL/lib)
	
	add_executable(${PROJECT_NAME} WIN32 ${FILES})
	target_link_libraries(${PROJECT_NAME} shared libcrypto libssl ws2_32.lib iphlpapi.lib ${LIBRARIES})
	set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different ${CMAKE_SOURCE_DIR}/3rdparty/OpenSSL/bin ${CMAKE_BINARY_DIR}/bin
)
else()
	find_package(OpenSSL REQUIRED)
	add_executable(${PROJECT_NAME} ${FILES})
	target_link_libraries(${PROJECT_NAME} shared crypto ssl ${CMAKE_DL_LIBS})
endif()

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/data ${CMAKE_BINARY_DIR}/bin/data
)
