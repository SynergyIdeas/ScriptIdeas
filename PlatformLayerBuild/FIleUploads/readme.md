# Network Folder Uploader

This application provides a web interface for uploading files to network folders with options to clean destination folders and handle file overwrite scenarios.

## Features

- Upload multiple files to network shares (UNC paths supported)
- Clean destination folder option (removes all existing files before upload)
- Overwrite existing files option
- Real-time upload progress tracking
- Error handling and reporting
- Support for large file uploads (configurable limits)

## Setup Instructions

### Prerequisites

- [Node.js](https://nodejs.org/) (v14 or newer)
- Network access to the destination folders with appropriate permissions

### Installation

1. Clone or download this repository
2. Navigate to the project directory
3. Install dependencies:

```bash
npm install
```

### Configuration

You can modify the following settings in `server.js`:

- `PORT`: The port the server will run on (default: 3000)
- File size limits (default: 1GB)
- CORS settings

### Project Structure

```
/network-folder-uploader
  ├── server.js         # Node.js server implementation
  ├── package.json      # Project dependencies
  ├── public/           # Static files directory
  │   └── index.html    # Web interface
  └── README.md         # This file
```

## Running the Application

### Development Mode

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

The application will be available at http://localhost:3000 (or your configured port).

## Usage

1. Open the web interface in a browser
2. Enter a destination network folder path (e.g., `\\server\share\folder`)
3. Select files to upload
4. Choose options:
   - Check "Clean destination folder" to remove existing files before upload
   - Check "Overwrite existing files" to replace files with the same name
5. Click "Upload Files" to start the upload process
6. Monitor progress and status messages

## Network Path Considerations

### Windows UNC Paths

The server supports Windows UNC paths in the format `\\server\share\folder`. The server needs appropriate permissions to access these network locations.

### Domain Authentication

For network folders requiring domain authentication, ensure the server is running under a user account with appropriate network access permissions.

## Security Considerations

- This application does not implement authentication - add appropriate security measures for production use
- Ensure proper file validation and scanning in production environments
- Consider implementing file type restrictions based on your requirements
- Set appropriate file size limits to prevent server overload

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Ensure the server is running with sufficient permissions to access the network share
   - Check that the network path is correctly formatted
   - Verify domain/user credentials have access to the destination folder

2. **Network Path Not Found**
   - Verify the network share exists and is accessible
   - Check for typos in the path
   - Ensure network connectivity between the server and the network share

3. **File Upload Errors**
   - Check for sufficient disk space
   - Verify file permissions at the destination
   - Ensure file size is within configured limits

## License

This project is open-source and available under the MIT License.
