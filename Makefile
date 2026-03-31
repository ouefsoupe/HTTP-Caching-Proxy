CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lssl -lcrypto

TARGET = proxy
SRCS = proxy.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

debug:
	$(MAKE) CFLAGS="$(CFLAGS) -g -DDEBUG"

clean:
	rm -f $(TARGET)


