CC			:= gcc
CFLAGS		:= -O2

BIN			:= linkserv

SOURCE	:= main.c mongoose.c
OBJ		:= mongoose.o main.o
DEPS	:= mongoose.h

CGI_BIN 	:= index.cgi

CGI_SOURCE 	:= index.c ccgi.c
CGI_OBJ 	:= ccgi.o index.o
CGI_DEPS 	:= ccgi.h

all: $(BIN) $(CGI_BIN)

clean:
	rm -f $(OBJ) $(CGI_OBJ)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(CGI_BIN): $(CGI_OBJ)
	$(CC) $(CFLAGS) -o $@ $^
