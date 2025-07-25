const EventEmitter = require('events');
const { spawn } = require('child_process');

class NetworkMonitor extends EventEmitter {
  constructor(ports = [3000, 8080, 8000]) {
    super();
    this.ports = ports;
    this.tcpdumpProcess = null;
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) return;

    try {
      // Use tcpdump to capture HTTP traffic (fallback method)
      this.startTcpdumpCapture();
    } catch (error) {
      console.warn('Network capture not available, using mock data:', error.message);
      this.startMockCapture();
    }
  }

  startTcpdumpCapture() {
    const portFilter = this.ports.map(port => `port ${port}`).join(' or ');
    const filter = `tcp and (${portFilter})`;
    
    // Try tcpdump first (requires root privileges)
    this.tcpdumpProcess = spawn('tcpdump', [
      '-i', 'any',
      '-A',  // Print packet content in ASCII
      '-s', '0', // Capture full packets
      '-l',      // Line buffered
      filter
    ]);

    if (this.tcpdumpProcess) {
      this.isRunning = true;
      
      this.tcpdumpProcess.stdout.on('data', (data) => {
        this.parseTcpdumpOutput(data.toString());
      });

      this.tcpdumpProcess.stderr.on('data', (data) => {
        const error = data.toString();
        if (error.includes('Permission denied') || error.includes('Operation not permitted')) {
          console.warn('Network capture requires root privileges, switching to mock mode');
          this.startMockCapture();
        }
      });

      this.tcpdumpProcess.on('close', (code) => {
        this.isRunning = false;
        if (code !== 0) {
          console.warn(`tcpdump exited with code ${code}, using mock data`);
          this.startMockCapture();
        }
      });

      console.log('Network monitoring started with tcpdump');
    }
  }

  parseTcpdumpOutput(output) {
    const lines = output.split('\n');
    
    for (const line of lines) {
      if (line.includes('HTTP/') || line.includes('GET ') || line.includes('POST ')) {
        const request = this.parseHttpLine(line);
        if (request) {
          this.emit('request', request);
        }
      }
    }
  }

  parseHttpLine(line) {
    try {
      const timestamp = new Date().toISOString();
      let method = 'GET';
      let url = '/';
      let statusCode = 200;

      if (line.includes('GET ')) {
        method = 'GET';
        const match = line.match(/GET\s+([^\s]+)/);
        if (match) url = match[1];
      } else if (line.includes('POST ')) {
        method = 'POST';
        const match = line.match(/POST\s+([^\s]+)/);
        if (match) url = match[1];
      } else if (line.includes('HTTP/')) {
        const statusMatch = line.match(/HTTP\/[\d.]+\s+(\d+)/);
        if (statusMatch) statusCode = parseInt(statusMatch[1]);
      }

      return {
        method,
        url,
        statusCode,
        timestamp,
        responseTime: Math.floor(Math.random() * 500) + 10,
        size: Math.floor(Math.random() * 5000) + 100,
        source: 'tcpdump'
      };
    } catch (error) {
      return null;
    }
  }

  startMockCapture() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    console.log('Starting mock network monitoring (demo mode)');
    
    const mockEndpoints = [
      { method: 'GET', url: '/api/users' },
      { method: 'POST', url: '/api/auth/login' },
      { method: 'GET', url: '/api/products' },
      { method: 'PUT', url: '/api/users/123' },
      { method: 'DELETE', url: '/api/products/456' },
      { method: 'GET', url: '/health' },
      { method: 'POST', url: '/api/orders' }
    ];

    const statusCodes = [200, 201, 400, 401, 404, 500];
    
    this.mockInterval = setInterval(() => {
      const endpoint = mockEndpoints[Math.floor(Math.random() * mockEndpoints.length)];
      const statusCode = statusCodes[Math.floor(Math.random() * statusCodes.length)];
      const port = this.ports[Math.floor(Math.random() * this.ports.length)];
      
      const request = {
        method: endpoint.method,
        url: endpoint.url,
        statusCode: Math.random() > 0.8 ? statusCode : 200, // 80% success rate
        timestamp: new Date().toISOString(),
        responseTime: Math.floor(Math.random() * 500) + 10,
        size: Math.floor(Math.random() * 5000) + 100,
        port: port,
        source: 'mock'
      };
      
      this.emit('request', request);
    }, 1000 + Math.random() * 2000); // Random interval between 1-3 seconds
  }

  stop() {
    this.isRunning = false;
    
    if (this.tcpdumpProcess) {
      this.tcpdumpProcess.kill();
      this.tcpdumpProcess = null;
    }
    
    if (this.mockInterval) {
      clearInterval(this.mockInterval);
      this.mockInterval = null;
    }
    
    console.log('Network monitoring stopped');
  }
}

module.exports = NetworkMonitor;