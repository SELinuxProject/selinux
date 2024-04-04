#ifndef LIBSELINUX_REGEX_DLSYM_H
#define LIBSELINUX_REGEX_DLSYM_H

#ifdef USE_PCRE2

#ifdef USE_PCRE2_DLSYM

#include <stdint.h>

#include <pcre2.h>


int regex_pcre2_load(void);

#define DLSYM_PROTO(symbol) extern typeof(symbol)* sym_##symbol
DLSYM_PROTO(pcre2_code_free_8);
DLSYM_PROTO(pcre2_compile_8);
DLSYM_PROTO(pcre2_config_8);
DLSYM_PROTO(pcre2_get_error_message_8);
DLSYM_PROTO(pcre2_match_8);
DLSYM_PROTO(pcre2_match_data_create_from_pattern_8);
DLSYM_PROTO(pcre2_match_data_free_8);
DLSYM_PROTO(pcre2_pattern_info_8);
DLSYM_PROTO(pcre2_serialize_decode_8);
DLSYM_PROTO(pcre2_serialize_encode_8);
DLSYM_PROTO(pcre2_serialize_free_8);
DLSYM_PROTO(pcre2_serialize_get_number_of_codes_8);
#undef DLSYM_PROTO

#undef  pcre2_code_free
#define pcre2_code_free                       sym_pcre2_code_free_8
#undef  pcre2_compile
#define pcre2_compile                         sym_pcre2_compile_8
#undef  pcre2_config
#define pcre2_config                          sym_pcre2_config_8
#undef  pcre2_get_error_message
#define pcre2_get_error_message               sym_pcre2_get_error_message_8
#undef  pcre2_match
#define pcre2_match                           sym_pcre2_match_8
#undef  pcre2_match_data_create_from_pattern
#define pcre2_match_data_create_from_pattern  sym_pcre2_match_data_create_from_pattern_8
#undef  pcre2_match_data_free
#define pcre2_match_data_free                 sym_pcre2_match_data_free_8
#undef  pcre2_pattern_info
#define pcre2_pattern_info                    sym_pcre2_pattern_info_8
#undef  pcre2_serialize_decode
#define pcre2_serialize_decode                sym_pcre2_serialize_decode_8
#undef  pcre2_serialize_encode
#define pcre2_serialize_encode                sym_pcre2_serialize_encode_8
#undef  pcre2_serialize_free
#define pcre2_serialize_free                  sym_pcre2_serialize_free_8
#undef  pcre2_serialize_get_number_of_codes
#define pcre2_serialize_get_number_of_codes   sym_pcre2_serialize_get_number_of_codes_8

#else

static inline int regex_pcre2_load(void)
{
	return 0;
}

#endif /* USE_PCRE2_DLSYM */

#endif /* USE_PCRE2 */
#endif /* LIBSELINUX_REGEX_DLSYM_H */
