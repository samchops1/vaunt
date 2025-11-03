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

## Features
- APK file upload with drag-and-drop
- Extract and parse AndroidManifest.xml
- Display APK information (package name, version, permissions)
- File tree navigation of APK contents
- Download extracted files

## Architecture
- Frontend runs on port 5000 (Vite dev server)
- Backend runs on port 8000 (Flask API)
- APK files are uploaded to backend, extracted, and analyzed
- Results returned as JSON to frontend for display
