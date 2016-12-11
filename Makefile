CC = g++
CFLAGS = -std=c++11 -g
SRC = lib/libcrypto_old.a src/test.cpp
SRC1 = lib/libcrypto_old.a src/test_oracle.cpp
SRC2 = lib/libcrypto_old.a src/cbc-mac-oracle.cpp
LIBS = -I../openssl/include -Llib -lcrypto -ldl -lpthread
TARGET = test

all: test oracle mac_attack server client

test: $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o test

oracle: $(SRC1)
	$(CC) $(CFLAGS) $(SRC1) $(LIBS) -o oracle

mac_attack: $(SRC2)
	$(CC) $(CFLAGS) $(SRC2) $(LIBS) -o mac_attack

server: src/server.cpp	
	$(CC) $(CFLAGS) src/server.cpp $(LIBS) -o server

client: src/client.cpp
	$(CC) $(CFLAGS) src/client.cpp $(LIBS) -o client

clean:
	rm -rf $(TARGET)
