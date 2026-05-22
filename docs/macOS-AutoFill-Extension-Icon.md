# macOS AutoFill Extension Icon (`ASCredentialProviderExtension`)

## The Problem: The White Icon Bug
When developing a credential provider extension (`ASCredentialProviderExtension`) for macOS, you may encounter an issue where the extension's icon appears as a solid white block (or generic document placeholder) in **System Settings -> Passwords -> Password Options**.

This happens due to two primary reasons:
1. **Template Rendering:** macOS renders AutoFill extension icons as **Template Images**. When rendering a template image, macOS completely ignores the RGB color data of the icon and relies exclusively on the **alpha channel (transparency)** to create a mask. If your main application icon is a solid square with no transparency (e.g., an opaque black background), its alpha mask is a solid block. The system tints this solid alpha mask with white, resulting in a featureless white square.
2. **Aggressive System Caching:** The macOS `iconservices` daemon caches extension icons very aggressively. Even if you update the icon, macOS may stubbornly hold onto the previous generic white icon until the extension's bundle version (`CFBundleVersion`) is incremented, and the cache is forcibly cleared.

## The Solution

To resolve this issue, you must supply a dedicated, fully transparent icon specifically for the AutoFill extension, rather than allowing the system to inherit the main app's opaque icon.

### 1. Create a Transparent Icon
Generate a custom icon specifically for the extension where the background is completely transparent (`alpha = 0`) and only the shape of your logo/glyph is opaque (`alpha = 255`). Do not include any solid backgrounds or squircle canvases.

### 2. Configure an Extension-Specific Asset Catalog
Create a dedicated `appiconset` (e.g., `ExtensionIcon.appiconset`) in your asset catalog (`Assets.xcassets`) and populate it with your transparent icon at all standard macOS resolutions (16x16 up to 512x512@2x). 

### 3. Update the Xcode Project & Info.plist
Ensure your extension target is configured to use this specific icon catalog instead of the default app icon.
- In `project.yml` (XcodeGen), specify the new asset catalog name for the extension target:
  ```yaml
  ASSETCATALOG_COMPILER_APPICON_NAME: ExtensionIcon
  ```
- In the extension's `Info.plist`, explicitly point to the new icon by setting:
  ```xml
  <key>CFBundleIconName</key>
  <string>ExtensionIcon</string>
  <key>CFBundleIconFile</key>
  <string>ExtensionIcon</string>
  ```

### 4. Overcoming macOS Caching
If you have applied the transparent icon but still see a white block during local development, macOS caching is likely to blame. 
To force an update:
1. Bump the `CFBundleVersion` in both your main app's and your extension's `Info.plist`.
2. Clean your Xcode build folder (`⇧⌘K`) and completely remove the old `.app` from your `/Applications` directory.
3. Unregister the old extension explicitly using `pluginkit -r <path_to_old_appex>`.
4. Clear the macOS Icon Services cache by running:
   ```bash
   sudo rm -rf /Library/Caches/com.apple.iconservices.store
   killall cfprefsd
   killall Finder
   killall System\ Settings
   ```
5. Rebuild and launch the application.
