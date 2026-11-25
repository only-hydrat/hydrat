//go:build ignore

package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: go run windows-icon.go input.png output.ico")
	}
	input, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	source, err := png.Decode(input)
	_ = input.Close()
	if err != nil {
		log.Fatal(err)
	}

	sizes := []int{16, 32, 48, 256}
	var headers, images bytes.Buffer
	write := func(v any) { _ = binary.Write(&headers, binary.LittleEndian, v) }
	write([3]uint16{0, 1, uint16(len(sizes))})
	for _, size := range sizes {
		var data bytes.Buffer
		if err := png.Encode(&data, scale(source, size)); err != nil {
			log.Fatal(err)
		}
		write([4]byte{byte(size), byte(size), 0, 0})
		write([2]uint16{1, 32})
		write([2]uint32{uint32(data.Len()), uint32(6 + 16*len(sizes) + images.Len())})
		images.Write(data.Bytes())
	}
	if err := os.WriteFile(os.Args[2], append(headers.Bytes(), images.Bytes()...), 0644); err != nil {
		log.Fatal(err)
	}
}

func scale(src image.Image, size int) image.Image {
	bounds := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := range size {
		for x := range size {
			left, top := x*bounds.Dx()/size, y*bounds.Dy()/size
			right, bottom := max(left+1, (x+1)*bounds.Dx()/size), max(top+1, (y+1)*bounds.Dy()/size)
			var red, green, blue, alpha uint32
			for sy := top; sy < bottom; sy++ {
				for sx := left; sx < right; sx++ {
					r, g, b, a := src.At(bounds.Min.X+sx, bounds.Min.Y+sy).RGBA()
					red, green, blue, alpha = red+r, green+g, blue+b, alpha+a
				}
			}
			denominator := uint32((right-left)*(bottom-top)) * 257
			dst.SetRGBA(x, y, color.RGBA{uint8(red / denominator), uint8(green / denominator),
				uint8(blue / denominator), uint8(alpha / denominator)})
		}
	}
	return dst
}
