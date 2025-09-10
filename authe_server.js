const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const FormData = require('form-data');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = './uploads';
        // Create uploads directory if it doesn't exist
        require('fs').mkdirSync(uploadDir, { recursive: true });
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Generate unique filename
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'apk-' + uniqueSuffix + '.apk');
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.originalname.toLowerCase().endsWith('.apk')) {
            cb(null, true);
        } else {
            cb(new Error('Only APK files are allowed'), false);
        }
    }
});

// Serve static files
app.use(express.static('public'));

// Official bank app metadata (this would typically come from a database)
const officialBankApps = {
    'com.chase.sig.android': {
        name: 'Chase Mobile',
        packageName: 'com.chase.sig.android',
        trustedVersions: ['5.30.0', '5.29.0', '5.28.0'],
        trustedCertificateFingerprint: 'A1:B2:C3:D4...' // SHA-256 fingerprint
    },
    'com.bankofamerica.mobilebanking': {
        name: 'Bank of America Mobile Banking',
        packageName: 'com.bankofamerica.mobilebanking',
        trustedVersions: ['22.5.0', '22.4.0', '22.3.0'],
        trustedCertificateFingerprint: 'E5:F6:G7:H8...'
    },
    'com.wellsfargo.mobilebanking': {
        name: 'Wells Fargo Mobile',
        packageName: 'com.wellsfargo.mobilebanking',
        trustedVersions: ['7.5.0', '7.4.0', '7.3.0'],
        trustedCertificateFingerprint: 'I9:J0:K1:L2...'
    },
    'com.citi.citimobile': {
        name: 'Citi Mobile',
        packageName: 'com.citi.citimobile',
        trustedVersions: ['15.4.0', '15.3.0', '15.2.0'],
        trustedCertificateFingerprint: 'M3:N4:O5:P6...'
    }
};

// VirusTotal API functions
async function uploadToVirusTotal(filePath) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
        throw new Error('VirusTotal API key not configured');
    }

    const form = new FormData();
    const fileBuffer = await fs.readFile(filePath);
    form.append('file', fileBuffer, {
        filename: path.basename(filePath),
        contentType: 'application/vnd.android.package-archive'
    });

    const response = await fetch('https://www.virustotal.com/vtapi/v2/file/scan', {
        method: 'POST',
        body: form,
        headers: {
            'apikey': apiKey
        }
    });

    if (!response.ok) {
        throw new Error(`VirusTotal upload failed: ${response.statusText}`);
    }

    const result = await response.json();
    return result.resource; // This is the scan ID
}

async function getVirusTotalReport(resource) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    
    const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${resource}`);
    
    if (!response.ok) {
        throw new Error(`VirusTotal report failed: ${response.statusText}`);
    }

    const result = await response.json();
    return result;
}

// APK metadata extraction (simplified version)
async function extractAPKMetadata(filePath) {
    try {
        // This is a simplified metadata extraction
        // In a real application, you would use a proper APK parser like 'node-apk-parser'
        const stats = await fs.stat(filePath);
        const fileBuffer = await fs.readFile(filePath);
        
        // Calculate file hash
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        
        // Simplified metadata (in real app, parse AndroidManifest.xml)
        return {
            fileSize: stats.size,
            filePath: filePath,
            sha256: hash,
            packageName: 'unknown', // Would be extracted from AndroidManifest.xml
            versionName: 'unknown',
            versionCode: 'unknown',
            targetSdk: 'unknown',
            permissions: [], // Would be extracted from AndroidManifest.xml
            certificates: [] // Would be extracted from META-INF/
        };
    } catch (error) {
        console.error('Metadata extraction error:', error);
        return null;
    }
}

// Enhanced APK metadata extraction with basic manifest parsing
async function extractAPKMetadataEnhanced(filePath) {
    try {
        const stats = await fs.stat(filePath);
        const fileBuffer = await fs.readFile(filePath);
        
        // Calculate file hash
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        
        // Basic APK structure analysis (simplified)
        // In a production app, you'd use libraries like yauzl for ZIP parsing
        // and aapt2 or similar for proper manifest parsing
        
        const metadata = {
            fileSize: stats.size,
            filePath: filePath,
            sha256: hash,
            packageName: await extractPackageName(fileBuffer),
            versionName: 'unknown',
            versionCode: 'unknown',
            targetSdk: 'unknown',
            permissions: [],
            certificates: []
        };
        
        return metadata;
    } catch (error) {
        console.error('Enhanced metadata extraction error:', error);
        return null;
    }
}

// Simplified package name extraction (in real app, parse AndroidManifest.xml properly)
async function extractPackageName(buffer) {
    // This is a very basic approach - in production, use proper APK parsing
    const bufferStr = buffer.toString('binary');
    
    // Look for common banking package names in the binary
    const bankingPatterns = [
        'com.chase.sig.android',
        'com.bankofamerica.mobilebanking',
        'com.wellsfargo.mobilebanking',
        'com.citi.citimobile',
        'com.usaa.mobile.android.usaa',
        'com.td.mytd.ca',
        'com.rbc.mobile.android'
    ];
    
    for (const pattern of bankingPatterns) {
        if (bufferStr.includes(pattern)) {
            return pattern;
        }
    }
    
    return 'unknown.package';
}

// Verify against official metadata
function verifyMetadata(metadata) {
    if (!metadata || !metadata.packageName) {
        return {
            isOfficial: false,
            details: 'Could not extract package information'
        };
    }

    const officialApp = officialBankApps[metadata.packageName];
    
    if (!officialApp) {
        return {
            isOfficial: false,
            details: 'Package not found in official banking apps database'
        };
    }

    // In a real application, you would also verify:
    // - Certificate fingerprint
    // - Version number
    // - File size ranges
    // - Other security markers

    return {
        isOfficial: true,
        details: `Verified as ${officialApp.name}`,
        officialName: officialApp.name
    };
}

// Clean up uploaded files
async function cleanupFile(filePath) {
    try {
        await fs.unlink(filePath);
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}

// Main analysis endpoint
app.post('/api/analyze', upload.single('apk'), async (req, res) => {
    let filePath = null;
    
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No APK file uploaded' });
        }

        filePath = req.file.path;
        console.log('Analyzing APK:', req.file.originalname);

        // Extract metadata
        const metadata = await extractAPKMetadataEnhanced(filePath);
        
        // Verify against official apps
        const verification = verifyMetadata(metadata);

        // Upload to VirusTotal and get scan results
        let virusTotalResults = null;
        
        try {
            if (process.env.VIRUSTOTAL_API_KEY) {
                console.log('Uploading to VirusTotal...');
                const scanId = await uploadToVirusTotal(filePath);
                
                // Wait a bit for scan to process
                await new Promise(resolve => setTimeout(resolve, 15000)); // 15 seconds
                
                // Get report
                const report = await getVirusTotalReport(scanId);
                
                if (report.response_code === 1) {
                    virusTotalResults = {
                        scan_date: report.scan_date,
                        total: report.total,
                        malicious: report.positives || 0,
                        suspicious: 0, // VirusTotal v2 doesn't separate suspicious
                        permalink: report.permalink
                    };
                } else {
                    console.log('VirusTotal report not ready yet');
                }
            }
        } catch (vtError) {
            console.error('VirusTotal error:', vtError.message);
            // Continue without VirusTotal results
        }

        // Return combined results
        res.json({
            success: true,
            metadata: metadata,
            verification: verification,
            virusTotal: virusTotalResults,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({ 
            error: 'Analysis failed: ' + error.message 
        });
    } finally {
        // Clean up uploaded file
        if (filePath) {
            setTimeout(() => cleanupFile(filePath), 5000); // Clean up after 5 seconds
        }
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        virusTotalEnabled: !!process.env.VIRUSTOTAL_API_KEY
    });
});

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 100MB.' });
        }
    }
    
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Authe server running on port ${PORT}`);
    console.log(`VirusTotal integration: ${process.env.VIRUSTOTAL_API_KEY ? 'Enabled' : 'Disabled (set VIRUSTOTAL_API_KEY)'}`);
});

module.exports = app;