
// Common header
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen)

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
//#define NO_OBSOLETE_FUNCS
#pragma warning(push)
#pragma warning(disable:4244) // "conversion from 'ssize_t' to 'int', possible loss of data"
#pragma warning(disable:4267) // "conversion from 'size_t' to 'uint32', possible loss of data"
#include <ida.hpp>
#include <dbg.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>
#pragma warning(pop)

#define MSG_TAG "Plugin: "
#include "Utility.h"

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 1, 0, 1)