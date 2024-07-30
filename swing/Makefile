# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

SRCS := swing.c
APP  := swing

PKG_CONFIG?=pkg-config

CFLAGS += $(shell $(PKG_CONFIG) --cflags libtpa)
LDFLAGS+=$(shell $(PKG_CONFIG) --libs --static libtpa)
LDFLAGS += -lm

all: $(APP)

$(APP):
	$(Q)echo "  LD $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c $(SRCS) -o $(APP).o
	$(Q)$(CC) $(APP).o -o $@ $(LDFLAGS)
	rm $(APP).o $(APP).d

clean:
	rm $(APP).o $(APP).d $(APP)
