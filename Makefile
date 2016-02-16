CC=gcc
CFLAGS=
LIBS=-lpcap
OBJ = udpbeamer.o
TARGET=udpbeamer

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm *.o
	rm $(TARGET)
