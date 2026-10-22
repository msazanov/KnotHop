#!/usr/bin/env python3
"""Offline XML, raster topology, safe-zone and optional aapt2 compile/link checks."""
from pathlib import Path
from collections import deque
from io import BytesIO
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from PIL import Image

ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT/'android-res').rglob('*.xml'):
    ET.parse(path)
print('All Android XML files: well formed')
for size in (512,48):
    im=Image.open(ROOT/f'previews/bretzel-mono-{size}.png').convert('RGBA')
    remaining={(x,y) for y in range(size) for x in range(size) if im.getpixel((x,y))[3]<128}
    holes=[]
    while remaining:
        start=remaining.pop(); queue=deque([start]); area=0; border=False
        while queue:
            x,y=queue.popleft(); area+=1
            border |= x in (0,size-1) or y in (0,size-1)
            for p in ((x-1,y),(x+1,y),(x,y-1),(x,y+1)):
                if p in remaining: remaining.remove(p); queue.append(p)
        if not border: holes.append(area)
    assert len(holes)==3,(size,holes)
    print(f'Monochrome {size}px: three holes, areas {sorted(holes)} px')

text=(ROOT/'bretzel-foreground.svg').read_bytes()
im=Image.open(BytesIO(subprocess.run(['rsvg-convert','-w','1080','-h','1080'],input=text,stdout=subprocess.PIPE,check=True).stdout)).convert('RGBA')
radius=max((((x+.5)/10-54)**2+((y+.5)/10-54)**2)**.5 for y in range(1080) for x in range(1080) if im.getpixel((x,y))[3]>127)
assert radius<=33,radius
print(f'Color foreground safe radius: {radius:.2f}/33')
sdks=[Path(os.environ.get('ANDROID_HOME',str(Path.home()/'Android/Sdk')))]
for sdk in sdks:
    aapts=sorted(sdk.glob('build-tools/*/aapt2')); jars=sorted(sdk.glob('platforms/*/android.jar'))
    if not aapts or not jars: continue
    with tempfile.TemporaryDirectory(prefix='.validate-',dir=ROOT) as tmp:
        tmp=Path(tmp)
        manifest=tmp/'AndroidManifest.xml'
        manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.knothop.iconpreview"><application android:icon="@mipmap/ic_launcher" android:roundIcon="@mipmap/ic_launcher_round"/></manifest>')
        subprocess.run([str(aapts[-1]),'compile','--dir',str(ROOT/'android-res'),'-o',str(tmp/'res.zip')],check=True)
        subprocess.run([str(aapts[-1]),'link','-o',str(tmp/'validation.apk'),'-I',str(jars[-1]),'--manifest',str(manifest),'--min-sdk-version','26','--target-sdk-version','35',str(tmp/'res.zip')],check=True)
    print('aapt2 compile + link: OK (temporary test APK removed)')
    break
else:
    print('SDK unavailable: aapt2 compile/link NOT checked')
