LOCAL_PATH:= $(call my-dir)

common_src_files := secilc.c

common_cflags := \
	-Wall -Wshadow -O2 \
	-pipe -fno-strict-aliasing \

ifeq ($(HOST_OS), darwin)
common_cflags += -DDARWIN
endif

common_includes := \
	$(LOCAL_PATH)/../libsepol/cil/include/ \
	$(LOCAL_PATH)/../libsepol/include/ \

##
# secilc
#
include $(CLEAR_VARS)

LOCAL_MODULE := secilc
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(common_includes)
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := secilc.c
LOCAL_SHARED_LIBRARIES := libsepol
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)
