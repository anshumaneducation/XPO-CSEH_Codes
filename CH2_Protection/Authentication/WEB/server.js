const http = require('http');
const fs = require('fs');
const path = require('path');

// Allowed IPs
const allowedIPs = ["192.168.2.132", "127.0.0.1", "203.0.113.5"];

const PORT = 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

const server = http.createServer((req, res) => {
    const clientIP = req.socket.remoteAddress.replace('::ffff:', '');
    console.log("Client IP:", clientIP);

    if (req.url === '/check-ip') {
        const isAllowed = allowedIPs.includes(clientIP);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            success: isAllowed,
            message: isAllowed ? "Your IP is allowed. Welcome!" : "Your IP is not allowed. Access denied.",
        }));
    } else {
        // Serve static files from 'public' folder
        let filePath = path.join(PUBLIC_DIR, req.url === '/' ? 'index.html' : req.url);
        
        // Normalize to prevent directory traversal
        filePath = path.normalize(filePath);
        
        fs.readFile(filePath, (err, content) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('404 Not Found');
            } else {
                const ext = path.extname(filePath).toLowerCase();
                const mimeTypes = {
                    '.html': 'text/html',
                    '.js': 'application/javascript',
                    '.css': 'text/css',
                    '.json': 'application/json',
                    '.png': 'image/png',
                    '.jpg': 'image/jpeg',
                    '.gif': 'image/gif'
                };
                res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
                res.end(content);
            }
        });
    }
});

server.listen(PORT,'0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
