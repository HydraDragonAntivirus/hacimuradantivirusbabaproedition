from PIL import Image

# PNG dosyasının yolunu ve dönüştürülecek ICO dosyasının yolunu belirtin
png_path = "shield-antivirus.png"
ico_path = "hacimuradantivirusbabaproedition.ico"

# PNG dosyasını açın
img = Image.open(png_path)

# ICO için desteklenen boyutlarda kaydedin (örneğin 16x16, 32x32, 48x48, 64x64, 128x128, 256x256)
img.save(ico_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

print(f"{ico_path} olarak kaydedildi.")
