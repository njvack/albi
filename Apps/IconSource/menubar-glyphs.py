import sys
# Writes the menu-bar template glyphs (22x16 pt) into the given directory.
out = sys.argv[1]
A = 'A3.1,3.1 0 0 0'
full = f'M1,16 L1,2.8 L4,2.8 L4,6 L6.667,6 L6.667,2.8 L9.667,2.8 L9.667,6 L12.333,6 L12.333,2.8 L15.333,2.8 L15.333,6 L18,6 L18,2.8 L21,2.8 L21,16 L18.6,16 L18.6,11.6 {A} 12.4,11.6 L12.4,16 L9.6,16 L9.6,11.6 {A} 3.4,11.6 L3.4,16 Z'
left = f'M1,16 L1,2.8 L4,2.8 L4,6 L6.667,6 L6.667,2.8 L9.667,2.8 L9.667,6 L11,6 L11,16 L9.6,16 L9.6,11.6 {A} 3.4,11.6 L3.4,16 Z'
right = f'M11,6 L12.333,6 L12.333,2.8 L15.333,2.8 L15.333,6 L18,6 L18,2.8 L21,2.8 L21,16 L18.6,16 L18.6,11.6 {A} 12.4,11.6 L12.4,16 L11,16 Z'
head = '<svg xmlns="http://www.w3.org/2000/svg" width="22" height="16" viewBox="0 0 22 16">'
svgs = {
 'connected': f'<path d="{full}" fill="#000"/>',
 'connecting': f'<path d="{left}" fill="#000"/><path d="{right}" fill="#000" fill-opacity="0.35"/>',
 'disconnected': f'<path d="{full}" fill="#000" fill-opacity="0.35"/>',
}
for k, v in svgs.items():
    open(f'{out}/bridge-{k}.svg', 'w').write(head + v + '</svg>\n')
