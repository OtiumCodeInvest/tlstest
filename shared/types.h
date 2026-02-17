#pragma once

#include "shared/output.h"

#include <stdint.h>
#include <stddef.h>
/*
typedef int8_t i8;		///< \brief 8 bit signed integer
typedef uint8_t u8;		///< \brief 8 bit unsigned integer
typedef int16_t i16;	///< \brief 16 bit signed integer
typedef uint16_t u16;	///< \brief 16 bit unsigned integer
typedef int32_t i32;	///< \brief 32 bit signed integer
typedef uint32_t u32;	///< \brief 32 bit unsigned integer
typedef int64_t i64;	///< \brief 64 bit signed integer
typedef uint64_t u64;	///< \brief 64 bit unsigned integer
typedef intptr_t iptr;	///< \brief pointer sized integer
typedef size_t uptr;	///< \brief pointer sized unsigned integer
typedef float f32;		///< \brief 32 bit float
typedef double f64;		///< \brief 64 bit float
*/
typedef int8_t iint8;		///< \brief 8 bit signed integer
typedef uint8_t uint8;		///< \brief 8 bit unsigned integer
typedef int16_t iint16;	///< \brief 16 bit signed integer
typedef uint16_t uint16;	///< \brief 16 bit unsigned integer
typedef int32_t iint32;	///< \brief 32 bit signed integer
typedef uint32_t uint32;	///< \brief 32 bit unsigned integer
typedef int64_t iint64;	///< \brief 64 bit signed integer
typedef uint64_t uint64;	///< \brief 64 bit unsigned integer

typedef int8_t int8;	///< \brief 32 bit signed integer
typedef int16_t int16;	///< \brief 32 bit signed integer
typedef int32_t int32;	///< \brief 32 bit signed integer
typedef int64_t int64;	///< \brief 64 bit signed integer

#define countof(Array) ((int)(sizeof(Array)/sizeof(*Array)))
