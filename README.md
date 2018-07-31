# vimage

You ever get stressed out about someone discovering your encrypted text files full of password dumps and incriminating evidence casually laying around on your desktop? Now hide all that stuff in your memes!

## Installation

If you're cool and already have go installed...

```
go install github.com/eatonchips/vimage
```

There are also binaries that will soon available in the releases tab. This has only been tested on Linux and Windows.

## Usage

This is fairly straightforward...

```
vimage [pathToFile]
```

That ^ will open up an image and attempt to decrypt the contents hidden inside.

```
vimage -init [pathToFile]
```

That ^ will open an image, encrypt the contents with a password of your choice, then open it in the editor.

To close the editor and save the contents, press the ESCAPE key.

Give it a test run with the provided cat pic (password is "pass"):

```
vimage ./cat.jpg

vimage -init ./cat.jpg
```
