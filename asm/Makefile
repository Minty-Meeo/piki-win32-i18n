all: MenuSliderAdjust ComboBoxAdjust

clean:
	rm MenuSliderAdjust.o MenuSliderAdjust.bin
	rm ComboBoxAdjust.o ComboBoxAdjust.bin

MenuSliderAdjust: MenuSliderAdjust.s
	as MenuSliderAdjust.s -o MenuSliderAdjust.o --32
	objcopy --only-section=.text --output-target binary MenuSliderAdjust.o MenuSliderAdjust.bin

ComboBoxAdjust: ComboBoxAdjust.s
	as ComboBoxAdjust.s -o ComboBoxAdjust.o --32
	objcopy --only-section=.text --output-target binary ComboBoxAdjust.o ComboBoxAdjust.bin
