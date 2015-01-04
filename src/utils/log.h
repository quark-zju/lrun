#pragma once

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>


#ifdef NDEBUG
  #define SHOW_SOURCE_LOCATION ;
  #define PRINT_TIMESTAMP ;
  #define INFO(...) ;
  #define PROGRESS_INFO(...) ;
  #define DEBUG_DO if (0)
  #define SCOPED_LOG_LOCK ;
  #define flog 0
#else
  #include <unistd.h>
  #include "now.h"
  extern int DEBUG_ENABLED;
  extern double DEBUG_START_TIME;
  extern int DEBUG_TIMESTAMP;
  extern int DEBUG_PROGRESS;
  extern int DEBUG_PID;
  extern FILE* flog;
  struct ScopedLogLock {
      ScopedLogLock();
      ~ScopedLogLock();
      int fd_;
  };

  #define TIMESTAMP (now() - DEBUG_START_TIME)
  #define SCOPED_LOG_LOCK ScopedLogLock lock;
  #define SHOW_SOURCE_LOCATION \
    if (DEBUG_ENABLED && flog) fprintf(flog, "  at %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
  #define PRINT_TIMESTAMP { \
    if (DEBUG_TIMESTAMP && flog) fprintf(flog, "[%8.3f]", TIMESTAMP); \
      if (DEBUG_PID && flog) fprintf(flog, "[%6lu] ", (unsigned long)getpid()); \
    }
  #define INFO(...) \
    if (__builtin_expect(DEBUG_ENABLED && flog, 0)) { \
        SCOPED_LOG_LOCK; \
        PRINT_TIMESTAMP; \
        fprintf(flog, "INFO: "); \
        fprintf(flog, __VA_ARGS__); \
        fprintf(flog, "\n"); \
        fflush(flog); }
  #define PROGRESS_INFO(...) \
    if (__builtin_expect(DEBUG_PROGRESS && flog, 0)) { \
        SCOPED_LOG_LOCK; \
        fprintf(flog, __VA_ARGS__); \
        fprintf(flog, "        \r"); \
        fflush(flog); }
  #define DEBUG_DO if (DEBUG_ENABLED)
#endif


#define FATAL(...) { \
        SCOPED_LOG_LOCK; \
        PRINT_TIMESTAMP; \
        FILE* fp = flog ? flog : stderr; \
        fprintf(fp, "FATAL: "); \
        fprintf(fp, __VA_ARGS__); \
        if (errno) fprintf(fp ? fp : stderr, " (%s)", strerror(errno)); \
        fprintf(fp, "\n"); \
        SHOW_SOURCE_LOCATION; \
        fflush(fp); \
        exit(-1); }

#define ERROR(...) { \
        SCOPED_LOG_LOCK; \
        PRINT_TIMESTAMP; \
        FILE* fp = flog ? flog : stderr; \
        fprintf(fp, "ERROR: "); \
        fprintf(fp, __VA_ARGS__); \
        if (errno) fprintf(fp, " (%s)", strerror(errno)); \
        fprintf(fp, "\n"); \
        SHOW_SOURCE_LOCATION; \
        fflush(fp); }

#define WARNING(...) { \
        SCOPED_LOG_LOCK; \
        PRINT_TIMESTAMP; \
        FILE* fp = flog ? flog : stderr; \
        fprintf(fp, "WARNING: "); \
        fprintf(fp, __VA_ARGS__); \
        fprintf(fp, "\n"); \
        SHOW_SOURCE_LOCATION; \
        fflush(fp); }
