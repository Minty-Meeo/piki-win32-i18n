MenuSliderAdjust: MenuSliderAdjust.s
	as MenuSliderAdjust.s -o MenuSliderAdjust.o --32
	objcopy --only-section=.text --output-target binary MenuSliderAdjust.o MenuSliderAdjust.bin

all: MenuSliderAdjust

clean:
	rm MenuSliderAdjust.o MenuSliderAdjust.bin
