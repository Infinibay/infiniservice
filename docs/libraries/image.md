# image Library Documentation

## Overview
`image` is a comprehensive image processing library for Rust that provides encoding and decoding for various image formats. In our infiniservice project, it's used primarily for processing extracted application icons and converting them to standardized formats.

## Version
- **Current Version**: 0.25.6
- **Trust Level**: ✅ **TRUSTABLE** - Well-established image processing library

## Key Features
- **Multiple formats**: PNG, JPEG, GIF, BMP, ICO, TIFF, WebP, and more
- **Image manipulation**: Resize, crop, rotate, filter operations
- **Color space support**: RGB, RGBA, grayscale, and other color formats
- **Memory efficient**: Streaming and lazy loading capabilities
- **Cross-platform**: Works consistently across all platforms

## Use Cases in Infiniservice
1. **Icon Processing**
   - Convert extracted Windows icons to standard formats (PNG, JPEG)
   - Resize icons to consistent dimensions
   - Process ICO files with multiple icon sizes

2. **Image Standardization**
   - Convert various image formats to a common format for storage
   - Normalize icon sizes for consistent display
   - Generate thumbnails and previews

3. **Image Analysis**
   - Extract image metadata and properties
   - Analyze image characteristics for categorization
   - Validate image integrity

## Basic Usage Examples

### Icon Format Conversion
```rust
use image::{ImageFormat, DynamicImage, ImageError};
use std::io::Cursor;

struct IconProcessor;

impl IconProcessor {
    fn convert_ico_to_png(ico_data: &[u8]) -> Result<Vec<u8>, ImageError> {
        // Load ICO file
        let img = image::load_from_memory_with_format(ico_data, ImageFormat::Ico)?;
        
        // Convert to PNG
        let mut png_data = Vec::new();
        let mut cursor = Cursor::new(&mut png_data);
        img.write_to(&mut cursor, ImageFormat::Png)?;
        
        Ok(png_data)
    }

    fn resize_icon(image_data: &[u8], target_size: u32) -> Result<Vec<u8>, ImageError> {
        let img = image::load_from_memory(image_data)?;
        
        // Resize maintaining aspect ratio
        let resized = img.resize(target_size, target_size, image::imageops::FilterType::Lanczos3);
        
        // Convert to PNG
        let mut output = Vec::new();
        let mut cursor = Cursor::new(&mut output);
        resized.write_to(&mut cursor, ImageFormat::Png)?;
        
        Ok(output)
    }

    fn extract_icon_sizes_from_ico(ico_data: &[u8]) -> Result<Vec<(u32, u32)>, ImageError> {
        // ICO files can contain multiple sizes
        let img = image::load_from_memory_with_format(ico_data, ImageFormat::Ico)?;
        let dimensions = img.dimensions();
        
        // For now, return the main dimensions
        // In a full implementation, you'd parse the ICO header to get all sizes
        Ok(vec![dimensions])
    }
}
```

### Image Metadata Extraction
```rust
use image::{ImageFormat, ImageResult};
use std::fs::File;
use std::io::BufReader;

struct ImageAnalyzer;

impl ImageAnalyzer {
    fn get_image_info(file_path: &str) -> ImageResult<ImageInfo> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        
        // Try to determine format from file extension or content
        let format = image::guess_format(&std::fs::read(file_path)?)?;
        let img = image::load(reader, format)?;
        
        Ok(ImageInfo {
            width: img.width(),
            height: img.height(),
            format,
            color_type: img.color(),
            file_size: std::fs::metadata(file_path)?.len(),
        })
    }

    fn is_valid_icon_size(width: u32, height: u32) -> bool {
        // Common icon sizes
        matches!((width, height), 
            (16, 16) | (24, 24) | (32, 32) | (48, 48) | 
            (64, 64) | (96, 96) | (128, 128) | (256, 256)
        )
    }

    fn analyze_image_quality(image_data: &[u8]) -> Result<ImageQuality, ImageError> {
        let img = image::load_from_memory(image_data)?;
        let (width, height) = img.dimensions();
        
        // Simple quality assessment based on size and format
        let quality = if width >= 256 && height >= 256 {
            ImageQuality::High
        } else if width >= 64 && height >= 64 {
            ImageQuality::Medium
        } else {
            ImageQuality::Low
        };

        Ok(quality)
    }
}

struct ImageInfo {
    width: u32,
    height: u32,
    format: ImageFormat,
    color_type: image::ColorType,
    file_size: u64,
}

enum ImageQuality {
    Low,
    Medium,
    High,
}
```

### Batch Icon Processing
```rust
use image::{ImageFormat, DynamicImage, ImageError};
use std::path::{Path, PathBuf};
use std::collections::HashMap;

struct BatchIconProcessor {
    processed_icons: HashMap<PathBuf, ProcessedIcon>,
}

impl BatchIconProcessor {
    fn new() -> Self {
        Self {
            processed_icons: HashMap::new(),
        }
    }

    fn process_application_icons(&mut self, app_paths: &[PathBuf]) -> Result<(), ImageError> {
        for app_path in app_paths {
            if let Ok(icon_data) = self.extract_icon_from_exe(app_path) {
                let processed = self.process_icon_data(&icon_data)?;
                self.processed_icons.insert(app_path.clone(), processed);
            }
        }
        Ok(())
    }

    fn extract_icon_from_exe(&self, exe_path: &Path) -> Result<Vec<u8>, std::io::Error> {
        // This would integrate with winapi icon extraction
        // For now, return placeholder
        Ok(vec![])
    }

    fn process_icon_data(&self, icon_data: &[u8]) -> Result<ProcessedIcon, ImageError> {
        let img = image::load_from_memory(icon_data)?;
        
        // Generate multiple sizes
        let sizes = vec![16, 24, 32, 48, 64, 128, 256];
        let mut processed_sizes = HashMap::new();
        
        for size in sizes {
            let resized = img.resize_exact(size, size, image::imageops::FilterType::Lanczos3);
            
            let mut png_data = Vec::new();
            let mut cursor = std::io::Cursor::new(&mut png_data);
            resized.write_to(&mut cursor, ImageFormat::Png)?;
            
            processed_sizes.insert(size, png_data);
        }

        Ok(ProcessedIcon {
            original_dimensions: img.dimensions(),
            processed_sizes,
            format: ImageFormat::Png,
        })
    }

    fn get_icon_for_size(&self, app_path: &Path, size: u32) -> Option<&Vec<u8>> {
        self.processed_icons
            .get(app_path)?
            .processed_sizes
            .get(&size)
    }

    fn save_processed_icons(&self, output_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(output_dir)?;
        
        for (app_path, processed_icon) in &self.processed_icons {
            let app_name = app_path.file_stem().unwrap().to_string_lossy();
            
            for (size, icon_data) in &processed_icon.processed_sizes {
                let filename = format!("{}_{}.png", app_name, size);
                let output_path = output_dir.join(filename);
                std::fs::write(output_path, icon_data)?;
            }
        }
        
        Ok(())
    }
}

struct ProcessedIcon {
    original_dimensions: (u32, u32),
    processed_sizes: HashMap<u32, Vec<u8>>,
    format: ImageFormat,
}
```

### Image Validation and Error Handling
```rust
use image::{ImageError, ImageFormat};

struct ImageValidator;

impl ImageValidator {
    fn validate_image_data(data: &[u8]) -> Result<ValidationResult, ImageError> {
        // Try to load the image to validate it
        let img = image::load_from_memory(data)?;
        let (width, height) = img.dimensions();
        
        let mut issues = Vec::new();
        
        // Check for common issues
        if width == 0 || height == 0 {
            issues.push("Invalid dimensions".to_string());
        }
        
        if width > 4096 || height > 4096 {
            issues.push("Image too large".to_string());
        }
        
        if data.len() > 10 * 1024 * 1024 { // 10MB
            issues.push("File size too large".to_string());
        }

        Ok(ValidationResult {
            is_valid: issues.is_empty(),
            dimensions: (width, height),
            file_size: data.len(),
            issues,
        })
    }

    fn is_supported_format(data: &[u8]) -> bool {
        image::guess_format(data).is_ok()
    }

    fn get_format_info(data: &[u8]) -> Option<FormatInfo> {
        if let Ok(format) = image::guess_format(data) {
            Some(FormatInfo {
                format,
                supports_transparency: matches!(format, ImageFormat::Png | ImageFormat::Gif | ImageFormat::WebP),
                supports_animation: matches!(format, ImageFormat::Gif | ImageFormat::WebP),
            })
        } else {
            None
        }
    }
}

struct ValidationResult {
    is_valid: bool,
    dimensions: (u32, u32),
    file_size: usize,
    issues: Vec<String>,
}

struct FormatInfo {
    format: ImageFormat,
    supports_transparency: bool,
    supports_animation: bool,
}
```

## Integration Strategy
1. **Icon Pipeline**: Extract → Validate → Process → Store
2. **Format Standardization**: Convert all icons to PNG for consistency
3. **Size Optimization**: Generate multiple sizes for different use cases
4. **Quality Control**: Validate images before processing

## Performance Considerations
- **Memory Usage**: Process images in batches to manage memory
- **Caching**: Cache processed images to avoid reprocessing
- **Streaming**: Use streaming for large images when possible
- **Parallel Processing**: Process multiple images concurrently

## Error Handling
- **Format Support**: Handle unsupported image formats gracefully
- **Corruption**: Detect and handle corrupted image data
- **Memory Limits**: Handle out-of-memory conditions
- **File Access**: Handle file permission and access errors

## Common Image Formats in Windows
- **ICO**: Windows icon format (multiple sizes in one file)
- **PNG**: Preferred format for processed icons
- **BMP**: Common in older Windows applications
- **JPEG**: Sometimes used for application images

## Documentation Links
- [Official Documentation](https://docs.rs/image/)
- [GitHub Repository](https://github.com/image-rs/image)
- [Crates.io Page](https://crates.io/crates/image)
