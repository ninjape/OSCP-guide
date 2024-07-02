# Steganography

{% hint style="info" %}
[https://book.hacktricks.xyz/crypto-and-stego/stego-tricks](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks)
{% endhint %}

## Image tools

### Steghide

it only works on jpgs

```
steghide extract -sh <filepath>
```

## Stegcracker

### OpenStego

```
openstego extract -sf <file>
```

### Zsteg

works on png

```
// zsteg -a <filename>
zsteg -E 
```

### Stegoveritas

supports all image files

```
stegoveritas <file>
```

### QuickStego

## Stegsolve

{% hint style="info" %}
[https://stegonline.georgeom.net/upload](https://stegonline.georgeom.net/upload)
{% endhint %}



## Exiftool

view and edit image metadata

##

## Whitespace Tools

### Snow

```
snow.exe -C -p "password" stegfile.txt
```
