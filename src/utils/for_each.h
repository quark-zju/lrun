#pragma once


// old compiler does not like for (auto i : v)
#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
# define FOR_EACH_CONST(i, v) \
    for (const auto& i : v)
# define FOR_EACH(i, v) \
    for (auto& i : v)
#else
# define VAR_CONCAT_(a, b) a ## b
# define VAR_CONCAT(a, b) VAR_CONCAT_(a ## _, b)
# define VAR_UNIQUE(a) VAR_CONCAT(a, __LINE__)
# define FOR_EACH(i, v) \
    __typeof(v.begin()) VAR_UNIQUE(_i) = v.begin(); \
    int VAR_UNIQUE(_fes) = 0; \
    for (; VAR_UNIQUE(_fes) = 1, VAR_UNIQUE(_i) != v.end(); ++VAR_UNIQUE(_i)) \
    for (__typeof(*(v.begin()))& i = *VAR_UNIQUE(_i); VAR_UNIQUE(_fes); VAR_UNIQUE(_fes) = 0)
# define FOR_EACH_CONST(i, v) \
    __typeof(v.begin()) VAR_UNIQUE(_i) = v.begin(); \
    int VAR_UNIQUE(_fes) = 0; \
    for (; VAR_UNIQUE(_fes) = 1, VAR_UNIQUE(_i) != v.end(); ++VAR_UNIQUE(_i)) \
    for (const __typeof(*(v.begin()))& i = *VAR_UNIQUE(_i); VAR_UNIQUE(_fes); VAR_UNIQUE(_fes) = 0)
#endif
