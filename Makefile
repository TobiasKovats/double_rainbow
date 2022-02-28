PREFIX ?= arm-none-eabi-
CC      = $(PREFIX)gcc
LD      = $(PREFIX)gcc
AR      = $(PREFIX)ar
OBJCOPY = $(PREFIX)objcopy
OBJDUMP = $(PREFIX)objdump

DEST = bin
include BuildMake.mk

LDFLAGS  =  $(ARCH_FLAGS) -Wl,--gc-sections -fno-builtin -ffunction-sections -fdata-sections \
           -fomit-frame-pointer -lgcc -lc -lnosys -lm \

CFLAGS += -O3 -Wall -Wextra -Wimplicit-function-declaration -Wredundant-decls -Wmissing-prototypes  -Wstrict-prototypes -Wundef -Wshadow -ffunction-sections -fdata-sections -fno-common -fno-unroll-loops -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mthumb

# if we wanted to analyse different variants...
# TARGET_NAME = $(shell echo $(IMPLEMENTATION_PATH) | sed 's@/@_@g')

TARGET_NAME = rainbow

ELF_DIR = elf
DIS_DIR = dis

# VICTIM_CFILES := $(filter-out main.c,$(VICTIM_CFILES))
.PHONY: all

all: 
	$(info DEST: $(DEST))
	$(info TARGET_NAME: $(TARGET_NAME))
	$(info VICTIM_AFILES: $(VICTIM_AFILES))
	$(info VICTIM_CFILES: $(VICTIM_CFILES))
	$(info includes: $(INCLUDES))

build: $(ELF_DIR)/$(TARGET_NAME).elf

$(ELF_DIR)/%.elf: $(VICTIM_CFILES) $(VICTIM_AFILES)
	mkdir -p $(ELF_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(INCLUDES) $^ -o $@

disassemble: $(ELF_DIR)/$(TARGET_NAME).elf
	mkdir -p $(DIS_DIR)
	$(OBJDUMP) -d -x -S $^ > $(DIS_DIR)/disassembly_with_source.S
	$(OBJDUMP) -d -x $^ > $(DIS_DIR)/disassembly.S

clean:
	rm -r $(ELF_DIR)