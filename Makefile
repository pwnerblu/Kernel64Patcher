CC = gcc
CFLAGS = -arch x86_64 -arch arm64 -O2
TARGET = MobileActivationPatcher
SOURCES = MobileActivationPatcher.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)
