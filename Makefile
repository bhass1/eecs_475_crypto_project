CC = g++
CFLAGS = -std=c++11 -g
SRC = src/*.cpp
LIBS = -lssl -lcrypto -ldl
TARGET = test

all:
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)

clean:
	rm -rf $(TARGET)
