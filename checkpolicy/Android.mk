LOCAL_PATH:= $(call my-dir)

common_src_files := \
	policy_parse.y \
	policy_scan.l \
	queue.c \
	module_compiler.c \
	parse_util.c \
	policy_define.c

common_cflags := \
	-Wall -Wshadow -O2 \
	-pipe -fno-strict-aliasing \
	-Wno-return-type

ifeq ($(HOST_OS),darwin)
common_cflags += -DDARWIN
endif

common_includes := \
	$(LOCAL_PATH)/ \
	$(LOCAL_PATH)/../libsepol/include/ \
	$(LOCAL_PATH)/../libsepol/src/ \

##
# "-x c" forces the lex/yacc files to be compiled as c
# the build system otherwise forces them to be c++
yacc_flags := -x c


##
# checkpolicy
#
include $(CLEAR_VARS)

LOCAL_MODULE := checkpolicy
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(common_includes) 
LOCAL_CFLAGS := $(yacc_flags) $(common_cflags)
LOCAL_SRC_FILES := $(common_src_files) checkpolicy.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_YACCFLAGS := -v
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)


##
# checkmodule
#
include $(CLEAR_VARS)

LOCAL_MODULE := checkmodule
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(common_includes) 
LOCAL_CFLAGS := $(yacc_flags) $(common_cflags)
LOCAL_SRC_FILES := $(common_src_files) checkmodule.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_YACCFLAGS := -v
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)

##
# dispol
#
include $(CLEAR_VARS)

LOCAL_MODULE := dispol
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(common_includes)
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := test/dispol.c
LOCAL_STATIC_LIBRARIES := libsepol
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)
