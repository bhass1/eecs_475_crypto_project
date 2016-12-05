CC = g++
CFLAGS = -std=c++11 -g
SRC = lib/libcrypto.a src/*.cpp
LIBS = -I../openssl/include -Llib -lcrypto -ldl -lpthread
TARGET = test

all:
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)

clean:
	rm -rf $(TARGET)
