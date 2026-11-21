"""Writes the AppIcon.icon layers (sage teal palette): full-bleed 1024 px SVGs that Icon
Composer stacks over the red fill. macOS applies the shape and glass."""
import sys

out = sys.argv[1]
S = 1.15  # content scale from the old 824 px tile to the full canvas


def arch(x0, w, spring, bottom):
    return (f'M{x0},{bottom} L{x0},{spring} '
            f'A{w/2},{w/2} 0 0 1 {x0+w},{spring} L{x0+w},{bottom} Z')


A1, A2 = arch(296, 176, 610, 790), arch(552, 176, 610, 790)
MERLONS = ' '.join(
    f'M{x:.1f},441 L{x:.1f},350 L{x+100:.1f},350 L{x+100:.1f},441 Z'
    for x in (216 + i * (492 / 3) for i in range(4)))


def svg(body):
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="1024" '
            'height="1024" viewBox="0 0 1024 1024">'
            f'<g transform="translate(512 512) scale({S}) translate(-512 -512)">'
            f'{body}</g></svg>\n')


bridge = (f'<path d="M216,440 L808,440 L808,790 L216,790 Z {A1} {A2}" '
          f'fill="#f8f6ef" fill-rule="evenodd"/><path d="{MERLONS}" fill="#f8f6ef"/>')

bars = []
for x0 in (296, 552):
    for k in (1, 2, 3):
        x = x0 + k * 44
        bars.append(f'<rect x="{x-9}" y="500" width="18" height="230"/>')
        bars.append(f'<path d="M{x-14},730 L{x},762 L{x+14},730 Z"/>')
    bars.append(f'<rect x="{x0}" y="600" width="176" height="18"/>')
grille = (f'<clipPath id="a"><path d="{A1} {A2}"/></clipPath>'
          f'<g clip-path="url(#a)" fill="#ecd9a2">{"".join(bars)}</g>')

gateway = f'<path d="{A1} {A2}" fill="#22463f"/>'
river = '<rect x="-200" y="790" width="1424" height="600" fill="#2e5d56"/>'

for name, body in (('bridge', bridge), ('grille', grille),
                   ('gateway', gateway), ('river', river)):
    with open(f'{out}/{name}.svg', 'w') as f:
        f.write(svg(body))
