#pragma once
#include "log.h"

#define ensure(exp) { if ((exp) == 0) FATAL("%s", "ensure failed: " # exp); }
#define ensure_zero(exp) { if ((exp) != 0) FATAL("%s", "ensure_zero failed: " # exp); }
