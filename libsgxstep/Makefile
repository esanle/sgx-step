-include Makefile.config

CC          = gcc
AS          = gcc
AR          = ar
ARFLAGS     = -rcs


ifeq ($(M32), 1)
	ASFLAGS = -m32 -DM32=1
	CFLAGS += -m32 -DM32=1
endif

# PIC 模式：产出 libsgx-step-pic.a（位置无关），供共享库 libdnr.so 链接。
# 用法：make PIC=1  → libsgx-step-pic.a（对象带 -fPIC，独立命名不冲突）
ifeq ($(PIC), 1)
	OUTPUT      = libsgx-step-pic.a
	CFLAGS      += -fPIC
	ASFLAGS     += -fPIC
	PIC_OBJDIR  = pic_obj
	OBJECTS     = $(addprefix $(PIC_OBJDIR)/, $(SOURCES:.c=.o) $(ASM:.S=.o))
else
	OUTPUT      = libsgx-step.a
	OBJECTS     = $(SOURCES:.c=.o) $(ASM:.S=.o)
endif

SOURCES     = $(shell ls *.c)
ASM         = $(shell ls *.S)

ifeq ($(GRAMINE), 1)
	CFLAGS += -DSGX_SSAFRAMESIZE=16384
	SOURCES += ./../sdk/gramine/aep.c
endif

all: $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	echo "$(INDENT)[AR] " $(OUTPUT)
	$(AR) $(ARFLAGS) $(OUTPUT) $(OBJECTS)

ifeq ($(PIC), 1)
$(PIC_OBJDIR):
	mkdir -p $(PIC_OBJDIR)

$(PIC_OBJDIR)/%.o : %.c | $(PIC_OBJDIR)
	echo "$(INDENT)[CC] " $<
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(PIC_OBJDIR)/%.o : %.S | $(PIC_OBJDIR)
	echo "$(INDENT)[AS] " $<
	$(AS) $(ASFLAGS) $(INCLUDE) -c $< -o $@
else
%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDE) -c $< -o $@

%.o : %.S
	echo "$(INDENT)[AS] " $<
	$(AS) $(ASFLAGS) $(INCLUDE) -c $< -o $@
endif

clean:
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT)
	rm -rf $(PIC_OBJDIR)

