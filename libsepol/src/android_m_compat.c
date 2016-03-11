#include <stdio.h>

#include "android_m_compat.h"

unsigned int avtab_android_m_compat;

void avtab_android_m_compat_set(void)
{
	if (!avtab_android_m_compat) {
		fprintf(stderr, "(Android M policy compatibility mode)\n");
		avtab_android_m_compat = 1;
	}
}
