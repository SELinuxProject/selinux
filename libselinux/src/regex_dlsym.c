#include "regex_dlsym.h"

#ifdef USE_PCRE2_DLSYM

#include "callbacks.h"
#include "selinux_internal.h"

#include <dlfcn.h>
#include <pthread.h>


#define DLSYM_FUNC(symbol) typeof(symbol)* sym_##symbol = NULL

#define DLSYM_RESOLVE(handle, symbol) do {                                                            \
        sym_##symbol = dlsym(handle, #symbol);                                                        \
        if (!sym_##symbol) {                                                                          \
                selinux_log(SELINUX_ERROR, "Failed to resolve symbol %s: %s\n", #symbol, dlerror());  \
                goto err;                                                                             \
        }                                                                                             \
} while(0)

DLSYM_FUNC(pcre2_code_free_8);
DLSYM_FUNC(pcre2_compile_8);
DLSYM_FUNC(pcre2_config_8);
DLSYM_FUNC(pcre2_get_error_message_8);
DLSYM_FUNC(pcre2_match_8);
DLSYM_FUNC(pcre2_match_data_create_from_pattern_8);
DLSYM_FUNC(pcre2_match_data_free_8);
DLSYM_FUNC(pcre2_pattern_info_8);
DLSYM_FUNC(pcre2_serialize_decode_8);
DLSYM_FUNC(pcre2_serialize_encode_8);
DLSYM_FUNC(pcre2_serialize_free_8);
DLSYM_FUNC(pcre2_serialize_get_number_of_codes_8);

static void *libpcre2_handle = NULL;
static pthread_mutex_t libpcre2_lock = PTHREAD_MUTEX_INITIALIZER;


static void *load_impl(void) {
	void *handle;

	handle = dlopen("libpcre2-8.so", RTLD_LAZY);
	if (!handle) {
		handle = dlopen("libpcre2-8.so.0", RTLD_LAZY);
		if (!handle) {
			selinux_log(SELINUX_ERROR, "Failed to load libpcre2-8: %s\n", dlerror());
			return NULL;
		}
	}

	DLSYM_RESOLVE(handle, pcre2_code_free_8);
	DLSYM_RESOLVE(handle, pcre2_compile_8);
	DLSYM_RESOLVE(handle, pcre2_config_8);
	DLSYM_RESOLVE(handle, pcre2_get_error_message_8);
	DLSYM_RESOLVE(handle, pcre2_match_8);
	DLSYM_RESOLVE(handle, pcre2_match_data_create_from_pattern_8);
	DLSYM_RESOLVE(handle, pcre2_match_data_free_8);
	DLSYM_RESOLVE(handle, pcre2_pattern_info_8);
	DLSYM_RESOLVE(handle, pcre2_serialize_decode_8);
	DLSYM_RESOLVE(handle, pcre2_serialize_encode_8);
	DLSYM_RESOLVE(handle, pcre2_serialize_free_8);
	DLSYM_RESOLVE(handle, pcre2_serialize_get_number_of_codes_8);

	return handle;

err:
	sym_pcre2_code_free_8 = NULL;
	sym_pcre2_compile_8 = NULL;
	sym_pcre2_config_8 = NULL;
	sym_pcre2_get_error_message_8 = NULL;
	sym_pcre2_match_8 = NULL;
	sym_pcre2_match_data_create_from_pattern_8 = NULL;
	sym_pcre2_match_data_free_8 = NULL;
	sym_pcre2_pattern_info_8 = NULL;
	sym_pcre2_serialize_decode_8 = NULL;
	sym_pcre2_serialize_encode_8 = NULL;
	sym_pcre2_serialize_free_8 = NULL;
	sym_pcre2_serialize_get_number_of_codes_8 = NULL;

	if (handle)
		dlclose(handle);
	return NULL;
}

int regex_pcre2_load(void) {
	void *handle;

	handle = __atomic_load_n(&libpcre2_handle, __ATOMIC_ACQUIRE);
	if (handle)
		return 0;

	__pthread_mutex_lock(&libpcre2_lock);

	/* Check if another thread validated the context while we waited on the mutex */
	handle = __atomic_load_n(&libpcre2_handle, __ATOMIC_ACQUIRE);
	if (handle) {
		__pthread_mutex_unlock(&libpcre2_lock);
		return 0;
	}

	handle = load_impl();
	if (handle)
		__atomic_store_n(&libpcre2_handle, handle, __ATOMIC_RELEASE);

	__pthread_mutex_unlock(&libpcre2_lock);

	return handle ? 0 : -1;
}

#endif /* USE_PCRE2_DLSYM */
