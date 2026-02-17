# VTracerCpp

A pure C++ port of the [vtracer](https://github.com/visioncortex/vtracer) library, originally written in Rust by [visioncortex](https://github.com/visioncortex). Translated to C++ using Google Gemini Pro.

**VTracerCpp** is a C++ tool and library that converts raster images (such as PNG or JPEG) into vector graphics (SVG).

Replicates the hierarchical clustering, path simplification, and spline generation of the original Rust implementation.

Source code for GLEW, GLFW, ImGui, Some OpenCV drawing and stb_image.h is provided within the project

## Build command on Linux
```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

## Build command on Windows
```
$ mkdir build
$ cd build
$ cmake -DCMAKE_GENERATOR_PLATFORM=x64 ..
$ Open vtracercpp.sln project in Visual Studio and build
```

Alternative open as folder in visual studio

## Screenshot
<img width="772" height="569" alt="vtracercpp-shot" src="https://github.com/user-attachments/assets/c2d85f16-f90a-45f8-841c-41e15c0a5177" />





