CC = g++
CFLAGS = -std=c++11 -g
SRC = lib/libcrypto.a src/test.cpp
LIBS = -I../openssl/include -Llib -lcrypto -ldl -lpthread
TARGET = test

all:
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)
	$(CC) $(CFLAGS) src/server.cpp $(LIBS) -o server
	$(CC) $(CFLAGS) src/client.cpp $(LIBS) -o client

clean:
	rm -rf $(TARGET)
