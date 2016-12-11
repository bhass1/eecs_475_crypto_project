CC = g++
CFLAGS = -std=c++11 -g
SRC = lib/libcrypto_old.a src/test.cpp
SRC1 = lib/libcrypto_old.a src/test_oracle.cpp
SRC2 = lib/libcrypto_old.a src/cbc-mac-oracle.cpp
LIBS = -I../openssl/include -Llib -lcrypto -ldl -lpthread
TARGET = test

all:
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)
	$(CC) $(CFLAGS) $(SRC1) $(LIBS) -o oracle
	$(CC) $(CFLAGS) $(SRC2) $(LIBS) -o mac_attack
	$(CC) $(CFLAGS) src/server.cpp $(LIBS) -o server
	$(CC) $(CFLAGS) src/client.cpp $(LIBS) -o client

clean:
	rm -rf $(TARGET)
