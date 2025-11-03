# APK Decompiler

## Overview
A web-based APK decompiler tool that extracts and displays the contents of Android APK files. Users can upload APK files to view manifest information, browse file contents, and download extracted resources.

## Tech Stack
- **Frontend**: React + Vite, Tailwind CSS, React Dropzone
- **Backend**: Python Flask
- **Deployment**: Port 5000 (frontend), Port 8000 (backend)

## Project Structure
```
/
├── src/           # React frontend source
├── public/        # Static assets
├── server/        # Flask backend
├── package.json   # Node dependencies
└── requirements.txt # Python dependencies
```

## Recent Changes
- 2025-11-03: Initial project setup with React frontend and Flask backend
- 2025-11-03: Implemented secure APK extraction with path validation and symlink protection
- 2025-11-03: Added androguard library for binary AndroidManifest.xml parsing
- 2025-11-03: Implemented file download functionality with hover buttons

## Features
- APK file upload with drag-and-drop interface
- Binary AndroidManifest.xml parsing using androguard
- Display APK information (package name, version, permissions, activities)
- Interactive file tree navigation with expand/collapse
- Individual file download with secure path validation
- Security features: directory traversal protection, zip-slip prevention, symlink blocking

## Architecture
- Frontend runs on port 5000 (Vite dev server with proxy to backend)
- Backend runs on port 8000 (Flask API)
- APK files are uploaded to backend, extracted securely, and analyzed
- Androguard library handles binary manifest parsing
- Results returned as JSON to frontend for display
- Download endpoint validates all paths and rejects symlinks

## Security Features
- Filename sanitization on upload
- Safe ZIP extraction with path validation
- Symlink detection and rejection
- Directory traversal prevention on downloads
- Proper error handling and cleanup on failures
