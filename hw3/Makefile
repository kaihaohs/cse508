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

CFLAGS := -Wall -Werror -DCOLOR
DFLAGS := -g -DDEBUG 

all: setup $(EXEC) 

debug: CFLAGS += -g -DDEBUG
debug: all

setup:
	mkdir -p bin build

$(BLDD)/%.o: $(SRCD)/%.c
	$(CC) $(INC) -c -o $@ $<

$(EXEC): $(ALL_OBJF)
	$(CC)  $^ -o $(BIND)/$@ $(LIBS)

#$(CFLAGS)  $(CFLAGS)

clean: 
	rm -rf $(BLDD) $(BIND)
