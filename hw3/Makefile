CC := gcc
SRCD := src
BLDD := build
BIND := bin
INCD := include

ALL_SRCF := $(shell find $(SRCD) -type f -name *.c)
ALL_OBJF := $(patsubst $(SRCD)/%,$(BLDD)/%,$(ALL_SRCF:.c=.o))
INC := -I $(INCD)

LIBS := -lcrypto -lpthread
EXEC := pbproxy


.PHONY: all debug clean setup

CFLAGS := -DCOLOR
DFLAGS := -g -DDEBUG 
#-Wall -Werror
all: setup $(EXEC) 

debug: CFLAGS += -g -DDEBUG
debug: all

setup:
	mkdir -p bin build

$(BLDD)/%.o: $(SRCD)/%.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(EXEC): $(ALL_OBJF)
	$(CC) $(CFLAGS) $^ -o $(BIND)/$@ $(LIBS)

# 

clean: 
	rm -rf $(BLDD) $(BIND)
