# Icon sources

The app icon and menu-bar glyphs come from the bridge in Albi's coat of arms. These are test icons.

- `app-icon.svg` is the source for `Albi/Assets.xcassets/AppIcon.appiconset`. Rasterize it to 16–1024 px PNGs to regenerate the set.
- `menubar-glyphs.py` writes the three template glyphs (`MenuBarConnected`, `MenuBarConnecting`, `MenuBarDisconnected`). They are vector, template-rendered image sets, so `Image("MenuBarConnected")` tints for light and dark menu bars. Connecting is half solid; disconnected is the whole bridge at 35% opacity.
