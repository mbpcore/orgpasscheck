# Makefile for orgpasscheck
#
# Usage:
#   make                                  # build against pg_config on PATH
#   make PG_CONFIG=/usr/pgsql-16/bin/pg_config
#   sudo make install
#   make installcheck                     # run regression tests

MODULE_big = orgpasscheck
OBJS       = orgpasscheck.o
EXTENSION  = orgpasscheck
DATA       = orgpasscheck--5.0.sql \

REGRESS    = 01_basic_complexity \
             02_sequence_check   \
             03_username_check   \
             04_dictionary       \
             05_blacklist        \
             06_history_reuse    \
             07_min_age          \
             08_expiry           \
                          10_admin_api

PG_CONFIG ?= pg_config

ifeq ($(shell which $(PG_CONFIG) 2>/dev/null),)
$(error pg_config not found. Provide an explicit path: make PG_CONFIG=/usr/pgsql-16/bin/pg_config)
endif

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Minimum version check at build time
PG_VERSION_NUM := $(shell $(PG_CONFIG) --version | sed 's/[^0-9.]//g' | awk -F. '{printf "%d%04d", $$1, $$2}')
ifeq ($(shell test $(PG_VERSION_NUM) -lt 160000 && echo yes),yes)
$(error orgpasscheck 5.0 requires PostgreSQL 16 or later.)
endif

.PHONY: secure-permissions
# secure-permissions: run as root after install if needed
# Derives the PostgreSQL OS user dynamically rather than hardcoding a fixed OS username
secure-permissions:
	$(eval PG_USER := $(shell ls -ld $(shell $(PG_CONFIG) --pkglibdir) | awk '{print $$3":"$$4}'))
	@echo "Fixing ownership to $(PG_USER)..."
	chown $(PG_USER) "$$($(PG_CONFIG) --pkglibdir)/$(MODULE_big).so"
	chown $(PG_USER) "$$($(PG_CONFIG) --sharedir)/extension/$(EXTENSION)"*
