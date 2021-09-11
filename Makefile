CC			:= gcc
CFLAGS		:= -O2

BIN			:= clink

SOURCE	:= main.c mongoose.c
OBJ		:= mongoose.o main.o
DEPS	:= mongoose.h index.h
LIBS	:= -lcrypt

all: $(BIN)

clean:
	rm -f $(OBJ)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

install-nginx:
	@install -Dm644 doc/clink.nginx ${nginx_dir}/sites-available/clink

install-systemd:
	@install -Dm644 doc/clink.service ${systemd_dir}/clink.service
	@install -Dm644 doc/clink.conf ${DESTDIR}/${confdir}/clink.conf

install-bin:
	@install -Dm755 ${BIN} ${bindir}/${BIN}

install: build install-bin install-nginx install-systemd
