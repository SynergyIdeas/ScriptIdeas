// server.js
const express = require('express');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload({
  createParentPath: true,
  limits: { 
    fileSize: 1024 * 1024 * 1024 // 1GB max file size
  },
}));

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Main upload endpoint
app.post('/upload', async (req, res) => {
  try {
    // Check if files were uploaded
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No files were uploaded.'
      });
    }

    // Get destination folder from request
    const destinationFolder = req.body.destinationFolder;
    if (!destinationFolder) {
      return res.status(400).json({ 
        success: false, 
        message: 'Destination folder is required.'
      });
    }

    // Check if we need to clean the folder first
    const cleanFolder = req.body.cleanFolder === 'true';
    const overwriteFiles = req.body.overwriteFiles === 'true';
    
    // Process folder path (handle UNC paths for network folders)
    let folderPath = destinationFolder;
    
    // Ensure the directory exists or map the network drive
    const directoryExists = await checkDirectoryExists(folderPath);
    
    if (!directoryExists) {
      // Try to map network drive if it's a UNC path
      if (folderPath.startsWith('\\\\')) {
        const mapped = await mapNetworkDrive(folderPath);
        if (!mapped) {
          return res.status(400).json({ 
            success: false, 
            message: 'Cannot access the specified network folder. Check path and permissions.'
          });
        }
      } else {
        // For local paths, try to create the directory
        try {
          fs.mkdirSync(folderPath, { recursive: true });
        } catch (err) {
          return res.status(400).json({ 
            success: false, 
            message: `Failed to create directory: ${err.message}`
          });
        }
      }
    }
    
    // Clean folder if requested
    if (cleanFolder) {
      try {
        const files = fs.readdirSync(folderPath);
        for (const file of files) {
          fs.unlinkSync(path.join(folderPath, file));
        }
      } catch (err) {
        return res.status(500).json({ 
          success: false, 
          message: `Failed to clean folder: ${err.message}`
        });
      }
    }
    
    // Upload files
    const uploadedFiles = [];
    const failedFiles = [];
    
    // Handle multiple files
    const files = Array.isArray(req.files.files) ? req.files.files : [req.files.files];
    
    for (const file of files) {
      const filePath = path.join(folderPath, file.name);
      
      // Check if file exists and overwrite is false
      if (fs.existsSync(filePath) && !overwriteFiles) {
        failedFiles.push({
          name: file.name,
          reason: 'File already exists and overwrite option is disabled'
        });
        continue;
      }
      
      try {
        // Move the uploaded file to the destination
        await file.mv(filePath);
        uploadedFiles.push(file.name);
      } catch (err) {
        failedFiles.push({
          name: file.name,
          reason: err.message
        });
      }
    }
    
    return res.status(200).json({
      success: true,
      message: `${uploadedFiles.length} files uploaded successfully${failedFiles.length > 0 ? `, ${failedFiles.length} failed` : ''}`,
      uploadedFiles,
      failedFiles
    });
    
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: `Server error: ${err.message}`
    });
  }
});

// Helper function to check if a directory exists
async function checkDirectoryExists(dirPath) {
  try {
    const stats = fs.statSync(dirPath);
    return stats.isDirectory();
  } catch (err) {
    return false;
  }
}

// Helper function to map a network drive (Windows specific)
async function mapNetworkDrive(uncPath) {
  return new Promise((resolve) => {
    // This is Windows-specific - for Linux/Mac, different approaches would be needed
    if (process.platform === 'win32') {
      // Generate a random drive letter (X:, Y:, Z:)
      const driveLetter = String.fromCharCode(88 + Math.floor(Math.random() * 3));
      
      exec(`net use ${driveLetter}: "${uncPath}" /persistent:no`, (error) => {
        if (error) {
          console.error(`Error mapping network drive: ${error.message}`);
          resolve(false);
        } else {
          // Store the mapping so we can disconnect later
          console.log(`Mapped ${uncPath} to ${driveLetter}:`);
          resolve(true);
        }
      });
    } else {
      // For non-Windows systems, would need to implement mounting of SMB/CIFS shares
      // This is a simplified example and might need adjustment for production
      resolve(false);
    }
  });
}

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
