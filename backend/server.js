const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
const NetworkMonitor = require('./NetworkMonitor');
const LogMonitor = require('./LogMonitor');
const ProcessMonitor = require('./ProcessMonitor');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// In-memory storage
let networkData = [];
let logData = [];
let processData = [];
let monitoringConfig = {
  network: { enabled: false, ports: [3000, 8080, 8000] },
  logs: { enabled: false, paths: [] },
  processes: { enabled: false }
};

// Services
let networkMonitor = null;
let logMonitor = null;
let processMonitor = null;

// Socket connection
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Send current data to new client
  socket.emit('initial-data', {
    network: networkData.slice(-100), // Last 100 entries
    logs: logData.slice(-100),
    processes: processData,
    config: monitoringConfig
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// API Routes
app.get('/api/status', (req, res) => {
  res.json({
    status: 'running',
    monitoring: monitoringConfig,
    dataCount: {
      network: networkData.length,
      logs: logData.length,
      processes: processData.length
    }
  });
});

app.post('/api/config', (req, res) => {
  const { network, logs, processes } = req.body;
  
  try {
    // Update configuration
    if (network) {
      monitoringConfig.network = { ...monitoringConfig.network, ...network };
      if (network.enabled && !networkMonitor) {
        startNetworkMonitoring();
      } else if (!network.enabled && networkMonitor) {
        stopNetworkMonitoring();
      }
    }
    
    if (logs) {
      monitoringConfig.logs = { ...monitoringConfig.logs, ...logs };
      if (logs.enabled && logs.paths && logs.paths.length > 0 && !logMonitor) {
        startLogMonitoring();
      } else if (!logs.enabled && logMonitor) {
        stopLogMonitoring();
      }
    }
    
    if (processes) {
      monitoringConfig.processes = { ...monitoringConfig.processes, ...processes };
      if (processes.enabled && !processMonitor) {
        startProcessMonitoring();
      } else if (!processes.enabled && processMonitor) {
        stopProcessMonitoring();
      }
    }
    
    io.emit('config-updated', monitoringConfig);
    res.json({ success: true, config: monitoringConfig });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/clear', (req, res) => {
  const { type } = req.body;
  
  switch (type) {
    case 'network':
      networkData = [];
      break;
    case 'logs':
      logData = [];
      break;
    case 'all':
      networkData = [];
      logData = [];
      break;
  }
  
  io.emit('data-cleared', { type });
  res.json({ success: true });
});

app.get('/api/discover-processes', async (req, res) => {
  try {
    const processes = await ProcessMonitor.discoverProcesses();
    res.json(processes);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Monitoring functions
function startNetworkMonitoring() {
  try {
    networkMonitor = new NetworkMonitor(monitoringConfig.network.ports);
    networkMonitor.on('request', (data) => {
      networkData.push({
        ...data,
        id: Date.now() + Math.random(),
        timestamp: new Date().toISOString()
      });
      
      // Keep only last 1000 entries
      if (networkData.length > 1000) {
        networkData = networkData.slice(-1000);
      }
      
      io.emit('network-data', data);
    });
    
    networkMonitor.start();
    console.log('Network monitoring started');
  } catch (error) {
    console.error('Failed to start network monitoring:', error.message);
  }
}

function stopNetworkMonitoring() {
  if (networkMonitor) {
    networkMonitor.stop();
    networkMonitor = null;
    console.log('Network monitoring stopped');
  }
}

function startLogMonitoring() {
  try {
    logMonitor = new LogMonitor(monitoringConfig.logs.paths);
    logMonitor.on('log', (data) => {
      logData.push({
        ...data,
        id: Date.now() + Math.random(),
        timestamp: new Date().toISOString()
      });
      
      // Keep only last 1000 entries
      if (logData.length > 1000) {
        logData = logData.slice(-1000);
      }
      
      io.emit('log-data', data);
    });
    
    logMonitor.start();
    console.log('Log monitoring started for paths:', monitoringConfig.logs.paths);
  } catch (error) {
    console.error('Failed to start log monitoring:', error.message);
  }
}

function stopLogMonitoring() {
  if (logMonitor) {
    logMonitor.stop();
    logMonitor = null;
    console.log('Log monitoring stopped');
  }
}

function startProcessMonitoring() {
  try {
    processMonitor = new ProcessMonitor();
    processMonitor.on('processes', (data) => {
      processData = data;
      io.emit('process-data', data);
    });
    
    processMonitor.start();
    console.log('Process monitoring started');
  } catch (error) {
    console.error('Failed to start process monitoring:', error.message);
  }
}

function stopProcessMonitoring() {
  if (processMonitor) {
    processMonitor.stop();
    processMonitor = null;
    console.log('Process monitoring stopped');
  }
}

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down...');
  stopNetworkMonitoring();
  stopLogMonitoring();
  stopProcessMonitoring();
  process.exit(0);
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Note: Network monitoring requires root privileges on Linux/Mac');
});