LOCAL_PATH:= $(call my-dir)

common_src_files := \
	src/assertion.c \
	src/avrule_block.c \
	src/avtab.c \
	src/boolean_record.c \
	src/booleans.c \
	src/conditional.c \
	src/constraint.c \
	src/context.c \
	src/context_record.c \
	src/debug.c \
	src/ebitmap.c \
	src/expand.c \
	src/genbools.c \
	src/genusers.c \
	src/handle.c \
	src/hashtab.c \
	src/hierarchy.c \
	src/iface_record.c \
	src/interfaces.c \
	src/link.c \
	src/mls.c \
	src/module.c \
	src/node_record.c \
	src/nodes.c \
	src/polcaps.c \
	src/policydb.c \
	src/policydb_convert.c \
	src/policydb_public.c \
	src/port_record.c \
	src/ports.c \
	src/roles.c \
	src/services.c \
	src/sidtab.c \
	src/symtab.c \
	src/user_record.c \
	src/users.c \
	src/util.c \
	src/write.c

common_cflags := \
	-Wall -W -Wundef \
	-Wshadow -Wmissing-noreturn \
	-Wmissing-format-attribute

ifeq ($(HOST_OS), darwin)
common_cflags += -DDARWIN
endif

common_includes := \
	$(LOCAL_PATH)/include/ \
	$(LOCAL_PATH)/src/

##
# libsepol.so
#
include $(CLEAR_VARS)

LOCAL_MODULE := libsepol
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(common_includes) 
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_MODULE_CLASS := SHARED_LIBRARIES

include $(BUILD_HOST_SHARED_LIBRARY)

##
# libsepol.a
#
include $(CLEAR_VARS)

LOCAL_MODULE := libsepol
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(common_includes) 
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_HOST_STATIC_LIBRARY)

##
# chkcon
#
include $(CLEAR_VARS)

LOCAL_MODULE := chkcon
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(common_includes) 
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := utils/chkcon.c
LOCAL_SHARED_LIBRARIES := libsepol
LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)
