CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -I../dependencies/include
LDFLAGS  := -L../dependencies/lib
LIBS     := -lgmpxx -lgmp

TARGET_NAME := rsa_app
BUILD_DIR   := target
TARGET		:= $(BUILD_DIR)/$(TARGET_NAME)

SRCS     := main.cpp rsa/rsa.cpp
DEPS     := rsa/rsa.h

OBJS     := $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/%.o: %.cpp $(DEPS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) public.key private.key encrypted.txt

.PHONY: clean