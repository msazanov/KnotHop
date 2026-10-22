#!/usr/bin/env python3
"""Offline SVG + Android resources from one hand-drawn, continuous dough rope."""
from pathlib import Path
from io import BytesIO
import argparse
import math
import random
import subprocess
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--iteration', type=int, default=3)
args = parser.parse_args()
ITER = args.iteration
# One rope: left cut end → first twist → left shoulder → belly →
# right shoulder → second twist → right cut end. No closed ring + cross.
ROPE = ('M 32,73 C 39,65 52,65 57,49 '
        'C 62,32 45,18 35,31 C 25,44 26,62 39,71 '
        'C 52,88 68,83 76,62 C 85,47 79,32 69,33 '
        'C 58,33 48,45 50,56 C 51,65 63,68 70,78')
BELLY = 'M 34,66 C 43,78 60,81 72,68'
LEFT_END = 'M 32,73 C 39,65 52,65 57,49'
TOP = 'M 57,40 C 59,46 51,50 50,56 C 49,65 63,68 70,78'
if ITER == 1:
    TOP = 'M 57,42 C 56,49 50,51 50,56 C 51,65 63,68 70,78'
WIDTH = 9.4 if ITER < 3 else 9.8
SCALE = .91
TRANSFORM = f'translate(54 54) scale({SCALE}) translate(-54 -54)'
GRADIENTS = {
    'baked': (25, 26, 77, 77, [(0,'#F2B868'),(.24,'#DA913D'),(.50,'#C8782A'),(.76,'#DE963F'),(1,'#994C19')]),
    'belly': (50, 67, 52, 81, [(0,'#FFD18A'),(.24,'#F2B868'),(.55,'#D68A34'),(1,'#99501A')]),
    'twist': (46, 48, 59, 58, [(0,'#9A4A17'),(.30,'#D78A31'),(.56,'#F5BF70'),(.78,'#E5A14A'),(1,'#B26322')]),
    'end': (31, 64, 39, 74, [(0,'#F4BF72'),(.46,'#DD9137'),(1,'#A4531C')]),
}
layers = []
def mono_layers():
    return [dict(d=d,color='#FFFFFF',width=w,opacity=1) for d,w in
            [(ROPE,WIDTH+1),(LEFT_END,WIDTH+.4),(TOP,WIDTH+.6)]]
def path(d, color, width=0, opacity=1):
    layers.append(dict(d=d, color=color, width=width, opacity=opacity))
def tube(d, gradient, width=WIDTH):
    path(d,'#783F19',width+1.0)
    path(d,'@'+gradient,width)
    if ITER >= 3:
        path(d,'#F4B35A',width*.68,.29)
        path(d,'#FFD08A',width*.36,.18)

tube(ROPE,'baked')
if ITER == 1:
    tube(BELLY,'belly',WIDTH+.7)
# Local shadows are on the lower rope, not a uniform cross-shaped outline.
path('M 32,69 C 37,71 40,74 42,75','#713812',5,.65)
path('M 63,72 L 70,76','#713812',7,.65)
tube(LEFT_END,'end',WIDTH-.6)
path('M 51,49 C 48,53 48,58 53,62','#743911',WIDTH+1.6,.75)
tube(TOP,'twist',WIDTH-.4)
# Soft longitudinal glaze, following the rounded dough rather than a flat strip.
path('M 31,54 C 29,42 33,29 40,28 C 46,27 51,32 53,36','#FFD18A',1.5,.70)
path('M 64,37 C 71,33 77,39 77,46','#F9CC85',1.3,.65)
path('M 74,52 C 73,59 71,64 67,68','#EDAF5C',1.0,.65)
path('M 38,70 C 45,75 56,78 64,74','#FFCF84',1.1,.60)
path('M 54,51 C 51,55 52,60 56,63','#FFE0A0',1.3,.80)
path('M 61,68 C 65,71 68,74 69,77','#F8C77F',1.0,.8)
# Rounded, oblique cut faces on the free ends (not round dots).
path('M 29.5,73 L 33,76','#AD6225',2.0)
path('M 67,79 L 71,77','#AB5E22',2.0)

# 27 coarse, irregular salt crystals; deterministic and all on the dough.
SALT = [(37,28),(41,29),(46,31),(33,34),(31,40),(30,47),(31,55),
        (33,61),(37,67),(43,73),(49,76),(56,76),(63,74),(72,64),
        (76,56),(78,48),(77,41),(72,36),(66,36),(60,40),(56,45),
        (53,54),(54,60),(59,65),(64,70),(34,71),(69,75)]
rng = random.Random(733)
if ITER >= 2:
    for i,(x,y) in enumerate(SALT):
        if ITER >= 3:
            x+=rng.uniform(-1.25,1.25); y+=rng.uniform(-1.15,1.15)
        w=rng.uniform(.48,1.02); h=rng.uniform(.65,1.35)
        angle=rng.uniform(-math.pi,math.pi)
        verts=[(-w,-h),(.75*w,-1.12*h),(1.2*w,.53*h),(-.5*w,1.05*h)]
        verts=[(x+u*math.cos(angle)-v*math.sin(angle),y+u*math.sin(angle)+v*math.cos(angle)) for u,v in verts]
        d='M '+' L '.join(f'{u:.3f},{v:.3f}' for u,v in verts)+' Z'
        path(d,'#935A2D',0,.4)
        # Light face displaced slightly upward from its tiny contact shadow.
        d='M '+' L '.join(f'{u:.3f},{v-.22:.3f}' for u,v in verts)+' Z'
        path(d,['#FFF9E9','#FFFFFF','#E8E5DF'][i%3])
        if ITER >= 3 and i % 12 == 0:
            path(f'M {x+1.3},{y+.5} l .65,-.3 .4,.8 -.8,.3 Z','#FFF9E9')

def svg(bg=None, mono=False):
    defs='<defs>'
    for name,(x1,y1,x2,y2,stops) in GRADIENTS.items():
        defs+=f'<linearGradient id="{name}" gradientUnits="userSpaceOnUse" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}">'
        defs+=''.join(f'<stop offset="{o}" stop-color="{c}"/>' for o,c in stops)+'</linearGradient>'
    defs+='</defs>'
    out=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 108 108">{defs}'
    if bg: out+=f'<path fill="{bg}" d="M0 0H108V108H0Z"/>'
    out+=f'<g transform="{TRANSFORM}" stroke-linecap="round" stroke-linejoin="round">'
    seq=mono_layers() if mono else layers
    for p in seq:
        c='url(#'+p['color'][1:]+')' if p['color'].startswith('@') else p['color']
        out+=f'<path d="{p["d"]}" opacity="{p["opacity"]}" '
        out+=(f'fill="none" stroke="{c}" stroke-width="{p["width"]}"/>' if p['width'] else f'fill="{c}"/>')
    return out+'</g></svg>'

def render(text,size):
    return Image.open(BytesIO(subprocess.run(['rsvg-convert','-w',str(size),'-h',str(size)],input=text.encode(),stdout=subprocess.PIPE,check=True).stdout)).convert('RGBA')

pre=ROOT/'previews'; pre.mkdir(exist_ok=True)
variants={'navy':'#0D2538','cream':'#F5E6CA'}
for name,bg in variants.items():
    text=svg(bg)
    (ROOT/('bretzel.svg' if name=='navy' else 'bretzel-cream.svg')).write_text(text+'\n')
    for size in (512,192,48):
        im=render(text,size); im.save(pre/f'bretzel-{name}-{size}.png')
        mask=Image.new('L',(size,size)); ImageDraw.Draw(mask).ellipse((0,0,size-1,size-1),fill=255)
        im.putalpha(mask); im.save(pre/f'bretzel-{name}-circle-{size}.png')
(ROOT/'bretzel-foreground.svg').write_text(svg()+'\n')
(ROOT/'bretzel-monochrome.svg').write_text(svg(mono=True)+'\n')
for size in (512,192,48):
    render(svg(mono=True),size).save(pre/f'bretzel-mono-{size}.png')

sheet=Image.new('RGB',(1190,1030),'#D9DDE0'); draw=ImageDraw.Draw(sheet)
font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',17)
draw.text((24,15),f'KnotHop / baked bretzel / iteration {ITER} — continuous dough rope',font=font,fill='#243342')
for row,name in enumerate(variants):
    y=55+row*470
    for x,size in [(24,512),(560,192),(780,48)]:
        # 512 artwork displayed at 430; other thumbnails at exact native sizes.
        im=Image.open(pre/f'bretzel-{name}-circle-{size}.png')
        if size==512: im=im.resize((430,430),Image.Resampling.LANCZOS)
        sheet.paste(im,(x,y),im)
        draw.text((x,y+im.height+5),f'{name} / {size}px'+(' (shown 430)' if size==512 else ''),font=font,fill='#243342')
    mono=Image.open(pre/'bretzel-mono-192.png'); sheet.paste(mono,(890,y),mono)
    draw.text((890,y+197),'monochrome / 192',font=font,fill='#243342')
    mono=Image.open(pre/'bretzel-mono-48.png'); sheet.paste(mono,(890,y+250),mono)
    draw.text((890,y+303),'monochrome / 48',font=font,fill='#243342')
sheet.save(ROOT/'preview-sheet-bretzel.png')
sheet.save(pre/f'bretzel-iteration-{ITER}.png')

A='http://schemas.android.com/apk/res/android'; AP='http://schemas.android.com/aapt'
ET.register_namespace('android',A); ET.register_namespace('aapt',AP)
def attrs(**kw): return {f'{{{A}}}{k}':str(v) for k,v in kw.items()}
def vector(mono=False):
    root=ET.Element('vector',attrs(width='108dp',height='108dp',viewportWidth=108,viewportHeight=108))
    g=ET.SubElement(root,'group',attrs(pivotX=54,pivotY=54,scaleX=SCALE,scaleY=SCALE))
    seq=mono_layers() if mono else layers
    for p in seq:
        at=attrs(pathData=p['d'])
        prop='strokeColor' if p['width'] else 'fillColor'
        if p['width']: at.update(attrs(fillColor='#00000000',strokeWidth=p['width'],strokeLineCap='round',strokeLineJoin='round',strokeAlpha=p['opacity']))
        else: at.update(attrs(fillAlpha=p['opacity']))
        if not p['color'].startswith('@'): at.update(attrs(**{prop:p['color']}))
        el=ET.SubElement(g,'path',at)
        if p['color'].startswith('@'):
            x1,y1,x2,y2,stops=GRADIENTS[p['color'][1:]]
            aa=ET.SubElement(el,f'{{{AP}}}attr',{'name':'android:'+prop})
            gr=ET.SubElement(aa,'gradient',attrs(type='linear',startX=x1,startY=y1,endX=x2,endY=y2,tileMode='clamp'))
            for o,c in stops: ET.SubElement(gr,'item',attrs(offset=o,color=c))
    return root
res=ROOT/'android-res'; (res/'drawable').mkdir(parents=True,exist_ok=True)
def write_xml(path,el):
    ET.indent(el); ET.ElementTree(el).write(path,encoding='utf-8',xml_declaration=True)
write_xml(res/'drawable/ic_launcher_foreground.xml',vector())
write_xml(res/'drawable/ic_launcher_monochrome.xml',vector(True))
for name,bg in variants.items():
    el=ET.Element('shape',attrs(shape='rectangle')); ET.SubElement(el,'solid',attrs(color=bg))
    write_xml(res/('drawable/ic_launcher_background.xml' if name=='navy' else 'drawable/ic_launcher_background_cream.xml'),el)
for qualifier in ('mipmap-anydpi-v26','mipmap-anydpi-v33'):
    dest=res/qualifier; dest.mkdir(exist_ok=True)
    for name in ('ic_launcher','ic_launcher_round'):
        el=ET.Element('adaptive-icon')
        ET.SubElement(el,'background',attrs(drawable='@drawable/ic_launcher_background'))
        ET.SubElement(el,'foreground',attrs(drawable='@drawable/ic_launcher_foreground'))
        if qualifier.endswith('v33'): ET.SubElement(el,'monochrome',attrs(drawable='@drawable/ic_launcher_monochrome'))
        write_xml(dest/(name+'.xml'),el)
for density,size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
    dest=res/('mipmap-'+density); dest.mkdir(exist_ok=True)
    im=render(svg(variants['navy']),size); im.save(dest/'ic_launcher.png')
    mask=Image.new('L',(size,size)); ImageDraw.Draw(mask).ellipse((0,0,size-1,size-1),fill=255)
    im.putalpha(mask); im.save(dest/'ic_launcher_round.png')
for f in res.rglob('*.xml'): ET.parse(f)
# Check actual antialiased silhouette, not just centerline control points.
im=render(svg(mono=True),1080)
points=[math.hypot((x+.5)/10-54,(y+.5)/10-54) for y in range(1080) for x in range(1080) if im.getpixel((x,y))[3]>127]
radius=max(points)
assert radius<=33, f'Outside adaptive safe circle: {radius:.2f}'
print(f'Iteration {ITER}: {len(layers)} paths; safe radius {radius:.2f}/33; XML well formed')
