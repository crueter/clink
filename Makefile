CC			:= gcc
CFLAGS		:= -O2

BIN			:= linkserv

SOURCE	:= main.c mongoose.c
OBJ		:= mongoose.o main.o
DEPS	:= mongoose.h

all: $(BIN)

clean:
	rm -f $(OBJ)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^
