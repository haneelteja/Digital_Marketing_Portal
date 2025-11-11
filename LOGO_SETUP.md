# Logo Setup Instructions

## Using Your Logo Image

Your login page is now configured to use your logo image file. Here's how to set it up:

### Step 1: Save Your Logo Image

1. Save your logo image file (PNG, SVG, or JPG) with the name: **`elma-logo.png`**
   - PNG format is recommended for best quality with transparency
   - SVG format works great if you have a vector version
   - JPG also works if PNG is not available

### Step 2: Place in Public Folder

Place your logo file in the `public` folder:

```
public/
  └── elma-logo.png
```

### Step 3: Verify

Once you place the file, refresh the login page (http://localhost:3000/login) and your logo should appear automatically.

## Supported File Names

The login page will look for:
- `elma-logo.png` (primary)
- `elma-logo.svg`
- `elma-logo.jpg` or `elma-logo.jpeg`

## Logo Specifications

- The logo image should include both the icon and text ("elma" and "defines purity")
- Recommended dimensions: 400-600px wide (height auto)
- White or transparent background works best
- The logo will automatically scale to fit the login card

## Current Status

The login page is ready to display your logo image. Just place the file in the `public` folder with the name `elma-logo.png` and it will appear automatically!
