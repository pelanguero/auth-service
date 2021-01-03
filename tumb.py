import sys
import fitz

print("llego a 0")
print(sys.argv[1])
doc = fitz.open(sys.argv[1])
print("llego a 1")
page = doc.loadPage(0)  # number of page
print("llego a 2")
pix = page.getPixmap()
print("llego a 3")
output =sys.argv[2]+sys.argv[3] +".png"
print("llego a 4")
pix.writePNG(output)
print("llego a 5")
