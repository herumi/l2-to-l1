include ../mcl/common.mk

SRC=bootstrap.cpp
ALL_SRC=$(SRC)

TARGET=bootstrap
all: $(TARGET)

CFLAGS+=-I../mcl/include -std=c++14
ifeq ($(OS),mac)
  CFLAGS+=-Xpreprocessor -fopenmp
  LDFLAGS+=-lomp
else
  CFLAGS+=-fopenmp
  LDFLAGS+=-fopenmp
endif
bootstrap.o: bootstrap.cpp
	$(PRE)$(CXX) $(CFLAGS) -c $< -o $@ -MMD -MP -MF $(@:.o=.d)

$(TARGET): bootstrap.o
	$(PRE)$(CXX) $< -o $@ ../mcl/lib/libmcl.a $(LDFLAGS)

clean:
	rm -rf $(TARGET) *.o *.d

DEPEND_FILE=$(ALL_SRC:.cpp=.d)
-include $(DEPEND_FILE)

# don't remove these files automatically
.SECONDARY: $(ALL_SRC:.cpp=.o)

