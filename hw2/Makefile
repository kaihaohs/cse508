CC := gcc
SRCD := src
BLDD := build
BIND := bin
INCD := include

ALL_SRCF := $(shell find $(SRCD) -type f -name *.c)
ALL_OBJF := $(patsubst $(SRCD)/%,$(BLDD)/%,$(ALL_SRCF:.c=.o))
INC := -I $(INCD)

LIBS := -lpcap
EXEC := mydump


.PHONY: all debug clean setup

CFLAGS := 
#-Wall -Werror
DFLAGS := -g -DDEBUG -DCOLOR

all: setup $(EXEC) 

debug: CFLAGS += -g -DDEBUG
debug: all

setup:
	mkdir -p bin build

$(EXEC): $(ALL_OBJF)
	$(CC) $(CFLAGS) $(STD) $^ -o $(BIND)/$@ $(LIBS)

$(BLDD)/%.o: $(SRCD)/%.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean: 
	rm -rf $(BLDD) $(BIND)
