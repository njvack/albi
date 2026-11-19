# Icon sources

The app icon and menu-bar glyphs come from the bridge in Albi's coat of arms. These are test icons. Both apps take them from `Apps/Shared`.

- `Shared/AppIcon.icon` is an Icon Composer icon: a red fill and three layer groups (bridge, gates, river). macOS draws the shape, the glass and the dark, tinted and clear variants. Open it in Icon Composer to adjust it. `app-icon-layers.py` regenerates the layer SVGs, and `app-icon.svg` is the flat original.
- `menubar-glyphs.py` writes the three template glyphs in `Shared/Assets.xcassets` (`MenuBarConnected`, `MenuBarConnecting`, `MenuBarDisconnected`). They are vector, template-rendered image sets, so `Image("MenuBarConnected")` tints for light and dark menu bars. Connecting is half solid; disconnected is the whole bridge at 35% opacity.
