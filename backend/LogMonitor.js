const EventEmitter = require('events');
const chokidar = require('chokidar');
const fs = require('fs');
const path = require('path');

class LogMonitor extends EventEmitter {
  constructor(logPaths = []) {
    super();
    this.logPaths = logPaths;
    this.watchers = [];
    this.filePositions = new Map();
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    
    if (this.logPaths.length === 0) {
      console.log('No log paths specified, starting mock log monitoring');
      this.startMockLogs();
      return;
    }

    console.log('Starting log monitoring for paths:', this.logPaths);
    
    this.logPaths.forEach(logPath => {
      this.watchLogPath(logPath);
    });
  }

  watchLogPath(logPath) {
    try {
      // Check if path exists
      if (!fs.existsSync(logPath)) {
        console.warn(`Log path does not exist: ${logPath}`);
        return;
      }

      const watcher = chokidar.watch(logPath, {
        ignored: /^\./, // ignore dotfiles
        persistent: true,
        ignoreInitial: false
      });

      watcher.on('add', (filePath) => {
        console.log(`Watching new log file: ${filePath}`);
        this.initializeFilePosition(filePath);
      });

      watcher.on('change', (filePath) => {
        this.readNewLogEntries(filePath);
      });

      watcher.on('error', (error) => {
        console.error(`Log watcher error for ${logPath}:`, error.message);
      });

      this.watchers.push(watcher);
    } catch (error) {
      console.error(`Failed to watch log path ${logPath}:`, error.message);
    }
  }

  initializeFilePosition(filePath) {
    try {
      const stats = fs.statSync(filePath);
      this.filePositions.set(filePath, stats.size);
      
      // Read last few lines for initial display
      this.readLastLines(filePath, 5);
    } catch (error) {
      console.error(`Failed to initialize position for ${filePath}:`, error.message);
    }
  }

  readLastLines(filePath, lineCount = 5) {
    try {
      const data = fs.readFileSync(filePath, 'utf8');
      const lines = data.split('\n').filter(line => line.trim());
      const lastLines = lines.slice(-lineCount);
      
      lastLines.forEach(line => {
        const logEntry = this.parseLogLine(line, filePath);
        if (logEntry) {
          this.emit('log', logEntry);
        }
      });
    } catch (error) {
      console.error(`Failed to read last lines from ${filePath}:`, error.message);
    }
  }

  readNewLogEntries(filePath) {
    try {
      const stats = fs.statSync(filePath);
      const lastPosition = this.filePositions.get(filePath) || 0;
      
      if (stats.size <= lastPosition) {
        return; // File was truncated or no new content
      }

      const stream = fs.createReadStream(filePath, {
        start: lastPosition,
        encoding: 'utf8'
      });

      let buffer = '';
      
      stream.on('data', (chunk) => {
        buffer += chunk;
        const lines = buffer.split('\n');
        buffer = lines.pop(); // Keep incomplete line in buffer
        
        lines.forEach(line => {
          if (line.trim()) {
            const logEntry = this.parseLogLine(line, filePath);
            if (logEntry) {
              this.emit('log', logEntry);
            }
          }
        });
      });

      stream.on('end', () => {
        this.filePositions.set(filePath, stats.size);
      });

      stream.on('error', (error) => {
        console.error(`Failed to read new entries from ${filePath}:`, error.message);
      });
    } catch (error) {
      console.error(`Failed to read new log entries from ${filePath}:`, error.message);
    }
  }

  parseLogLine(line, filePath) {
    try {
      // Try to parse as JSON first
      if (line.trim().startsWith('{')) {
        try {
          const parsed = JSON.parse(line);
          return {
            level: parsed.level || 'info',
            message: parsed.message || parsed.msg || line,
            timestamp: parsed.timestamp || parsed.time || new Date().toISOString(),
            source: path.basename(filePath),
            raw: line,
            type: 'json'
          };
        } catch (e) {
          // Not valid JSON, continue with text parsing
        }
      }

      // Parse common log formats
      const logLevel = this.extractLogLevel(line);
      const timestamp = this.extractTimestamp(line) || new Date().toISOString();
      
      return {
        level: logLevel,
        message: line,
        timestamp: timestamp,
        source: path.basename(filePath),
        raw: line,
        type: 'text'
      };
    } catch (error) {
      return {
        level: 'info',
        message: line,
        timestamp: new Date().toISOString(),
        source: path.basename(filePath),
        raw: line,
        type: 'text'
      };
    }
  }

  extractLogLevel(line) {
    const levelPatterns = [
      /\[(ERROR|FATAL)\]/i,
      /\[(WARN|WARNING)\]/i,
      /\[(INFO|INFORMATION)\]/i,
      /\[(DEBUG|TRACE)\]/i,
      /(ERROR|FATAL):/i,
      /(WARN|WARNING):/i,
      /(INFO|INFORMATION):/i,
      /(DEBUG|TRACE):/i
    ];

    for (const pattern of levelPatterns) {
      const match = line.match(pattern);
      if (match) {
        const level = match[1].toLowerCase();
        if (level === 'fatal') return 'error';
        if (level === 'warning') return 'warn';
        if (level === 'information') return 'info';
        return level;
      }
    }

    // Determine level by keywords
    if (/error|exception|fail|fatal/i.test(line)) return 'error';
    if (/warn|warning/i.test(line)) return 'warn';
    if (/debug|trace/i.test(line)) return 'debug';
    
    return 'info';
  }

  extractTimestamp(line) {
    // Common timestamp patterns
    const patterns = [
      /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?)/,
      /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/,
      /(\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2})/,
      /(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})/
    ];

    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match) {
        try {
          return new Date(match[1]).toISOString();
        } catch (e) {
          continue;
        }
      }
    }

    return null;
  }

  startMockLogs() {
    const logLevels = ['info', 'warn', 'error', 'debug'];
    const mockMessages = [
      'User authentication successful',
      'Database connection established',
      'API request processed',
      'Cache miss for key: user_123',
      'File uploaded successfully',
      'Payment processing started',
      'Email notification sent',
      'Background job completed',
      'Session expired for user',
      'Configuration loaded',
      'Server health check passed',
      'Rate limit exceeded for IP',
      'Invalid request parameter',
      'Database query timeout',
      'Service temporarily unavailable'
    ];

    this.mockInterval = setInterval(() => {
      const level = logLevels[Math.floor(Math.random() * logLevels.length)];
      const message = mockMessages[Math.floor(Math.random() * mockMessages.length)];
      
      const logEntry = {
        level: Math.random() > 0.8 ? 'error' : level, // 20% error rate
        message: message,
        timestamp: new Date().toISOString(),
        source: 'mock-app.log',
        raw: `[${new Date().toISOString()}] [${level.toUpperCase()}] ${message}`,
        type: 'mock'
      };
      
      this.emit('log', logEntry);
    }, 500 + Math.random() * 1500); // Random interval between 0.5-2 seconds
  }

  stop() {
    this.isRunning = false;
    
    this.watchers.forEach(watcher => {
      watcher.close();
    });
    this.watchers = [];
    
    if (this.mockInterval) {
      clearInterval(this.mockInterval);
      this.mockInterval = null;
    }
    
    this.filePositions.clear();
    console.log('Log monitoring stopped');
  }
}

module.exports = LogMonitor;