CC = g++
CFLAGS = -std=c++11 -g
SRC = lib/libcrypto_old.a src/test.cpp
SRC1 = lib/libcrypto_old.a src/oracle.cpp
SRC2 = lib/libcrypto_old.a src/mac_attack.cpp
LIBS = -I../openssl/include -Llib -lcrypto -ldl -lpthread
TARGET = test

all: test oracle mac_attack server side_channel ctr_attack

test: $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o test

oracle: $(SRC1)
	$(CC) $(CFLAGS) $(SRC1) $(LIBS) -o oracle

mac_attack: $(SRC2)
	$(CC) $(CFLAGS) $(SRC2) $(LIBS) -o mac_attack

server: src/server.cpp	
	$(CC) $(CFLAGS) src/server.cpp $(LIBS) -o server

side_channel: src/side_channel.cpp
	$(CC) $(CFLAGS) src/side_channel.cpp $(LIBS) -o side_channel
	
ctr_attack: src/CTRModeReusedIVAttack.cpp
	$(CC) $(CFLAGS) src/CTRModeReusedIVAttack.cpp -o ctr_attack

clean:
	rm -rf $(TARGET)
