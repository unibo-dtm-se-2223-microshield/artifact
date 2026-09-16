# MicroShield Edge C99 Toolchain Makefile (Native Host Verification)

CC ?= gcc
AR ?= ar
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -O2 -Iinclude -Imodel
LDFLAGS ?=
LDLIBS ?= -lm

SRC_DIR = src
INC_DIR = include
MODEL_DIR = model
TEST_DIR = tests
BUILD_DIR = build

SRCS = $(SRC_DIR)/microshield_cobs.c \
       $(SRC_DIR)/microshield_engine.c \
       $(SRC_DIR)/microshield_features.c

OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
LIB = $(BUILD_DIR)/libmicroshield.a

TEST_SRCS = $(TEST_DIR)/test_cobs.c \
            $(TEST_DIR)/test_engine.c \
            $(TEST_DIR)/test_features.c

TEST_BINS = $(BUILD_DIR)/test_cobs_bin \
            $(BUILD_DIR)/test_engine_bin \
            $(BUILD_DIR)/test_features_bin

.PHONY: all lib test clean

all: lib test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Static Library Target
lib: $(LIB)

$(LIB): $(BUILD_DIR) $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/microshield.h $(MODEL_DIR)/transpiled_model.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Test Targets
$(BUILD_DIR)/test_cobs_bin: $(TEST_DIR)/test_cobs.c $(SRC_DIR)/microshield_cobs.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD_DIR)/test_engine_bin: $(TEST_DIR)/test_engine.c $(SRC_DIR)/microshield_engine.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD_DIR)/test_features_bin: $(TEST_DIR)/test_features.c $(SRC_DIR)/microshield_features.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

test: $(TEST_BINS)
	@echo "=== Running MicroShield Edge C99 Test Suite ==="
	@$(BUILD_DIR)/test_cobs_bin
	@$(BUILD_DIR)/test_engine_bin
	@$(BUILD_DIR)/test_features_bin
	@echo "=== All Edge C99 Unit Tests Passed Successfully ==="

clean:
	rm -rf $(BUILD_DIR) $(TEST_DIR)/*_bin
