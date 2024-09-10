SRC=$(wildcard *.c)
LIB=./libbpf/libbpf.a -lelf -lz -lm
OBJ=$(addprefix ./, $(addsuffix .o, $(basename $(SRC))))
TARGET=ebpf-ssh
all: $(TARGET)
$(TARGET): $(SRC)
	$(CC)  -w -o $@  $^ $(CFLAGS) $(LDFLAGS) $(LIB)  -I./libbpf/  -Wno-stringop-overflow
clean:
	rm -f $(TARGET) $(OBJ)

