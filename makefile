CC = gcc
CFLAGS = -fPIC -Iinclude
LDFLAGS = -lcrypto -lssl -lblkid -lutil
TARGET = usb_crypto
SRC = ./usb_crypto.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) /usr/local/lib/
	cp include/license.h /usr/local/include/
	ldconfig
