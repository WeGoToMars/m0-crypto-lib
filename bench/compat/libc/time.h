/* Freestanding stub: wolfSSL's default port includes <time.h>; ChaCha never calls it. */
#ifndef M0C_STUB_TIME_H
#define M0C_STUB_TIME_H
typedef long time_t;
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };
#endif
