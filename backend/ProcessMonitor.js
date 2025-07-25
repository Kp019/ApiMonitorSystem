const EventEmitter = require('events');
const ps = require('ps-node');
const { spawn } = require('child_process');

class ProcessMonitor extends EventEmitter {
  constructor() {
    super();
    this.interval = null;
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    console.log('Starting process monitoring');
    
    // Initial scan
    this.scanProcesses();
    
    // Periodic scans every 5 seconds
    this.interval = setInterval(() => {
      this.scanProcesses();
    }, 5000);
  }

  async scanProcesses() {
    try {
      const processes = await this.getRunningProcesses();
      this.emit('processes', processes);
    } catch (error) {
      console.error('Failed to scan processes:', error.message);
    }
  }

  getRunningProcesses() {
    return new Promise((resolve, reject) => {
      ps.lookup({}, (err, resultList) => {
        if (err) {
          reject(err);
          return;
        }

        const filteredProcesses = resultList
          .filter(process => this.isTargetProcess(process))
          .map(process => this.formatProcessInfo(process));

        resolve(filteredProcesses);
      });
    });
  }

  isTargetProcess(process) {
    const targetKeywords = [
      'node', 'python', 'java', 'go', 'php', 'ruby',
      'nginx', 'apache', 'httpd', 'tomcat', 'express',
      'docker', 'postgres', 'mysql', 'mongodb', 'redis'
    ];

    const command = (process.command || '').toLowerCase();
    const args = (process.arguments || []).join(' ').toLowerCase();
    const fullCommand = `${command} ${args}`;

    return targetKeywords.some(keyword => 
      fullCommand.includes(keyword) && 
      !fullCommand.includes('grep') && 
      !fullCommand.includes('ps ')
    );
  }

  formatProcessInfo(process) {
    return {
      pid: process.pid,
      ppid: process.ppid,
      command: process.command,
      arguments: process.arguments || [],
      cpu: process.cpu || 0,
      memory: process.memory || 0,
      startTime: process.start_time || new Date().toISOString(),
      status: this.determineProcessType(process.command, process.arguments)
    };
  }

  determineProcessType(command, args = []) {
    const fullCommand = `${command} ${args.join(' ')}`.toLowerCase();
    
    if (fullCommand.includes('node')) {
      if (fullCommand.includes('express') || fullCommand.includes('server')) {
        return 'Node.js Server';
      }
      return 'Node.js App';
    }
    
    if (fullCommand.includes('python')) {
      if (fullCommand.includes('flask') || fullCommand.includes('django') || fullCommand.includes('fastapi')) {
        return 'Python Web Server';
      }
      return 'Python App';
    }
    
    if (fullCommand.includes('java')) {
      if (fullCommand.includes('spring') || fullCommand.includes('tomcat')) {
        return 'Java Web Server';
      }
      return 'Java App';
    }
    
    if (fullCommand.includes('nginx')) return 'Nginx Server';
    if (fullCommand.includes('apache') || fullCommand.includes('httpd')) return 'Apache Server';
    if (fullCommand.includes('docker')) return 'Docker Container';
    if (fullCommand.includes('postgres')) return 'PostgreSQL Database';
    if (fullCommand.includes('mysql')) return 'MySQL Database';
    if (fullCommand.includes('mongodb')) return 'MongoDB Database';
    if (fullCommand.includes('redis')) return 'Redis Cache';
    if (fullCommand.includes('go ')) return 'Go Application';
    if (fullCommand.includes('php')) return 'PHP Application';
    if (fullCommand.includes('ruby')) return 'Ruby Application';
    
    return 'Application';
  }

  static async discoverProcesses() {
    try {
      const monitor = new ProcessMonitor();
      const processes = await monitor.getRunningProcesses();
      
      // Group by process type
      const grouped = {};
      processes.forEach(proc => {
        const type = proc.status;
        if (!grouped[type]) {
          grouped[type] = [];
        }
        grouped[type].push(proc);
      });
      
      return {
        total: processes.length,
        processes: processes,
        grouped: grouped,
        discovered: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to discover processes: ${error.message}`);
    }
  }

  async getProcessPorts(pid) {
    return new Promise((resolve) => {
      // Try to get ports using netstat (Unix/Linux)
      const netstat = spawn('netstat', ['-tulpn']);
      let output = '';
      
      netstat.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      netstat.on('close', () => {
        const ports = this.parseNetstatOutput(output, pid);
        resolve(ports);
      });
      
      netstat.on('error', () => {
        // Fallback: return empty array if netstat fails
        resolve([]);
      });
    });
  }

  parseNetstatOutput(output, pid) {
    const ports = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      if (line.includes(`${pid}/`)) {
        const parts = line.split(/\s+/);
        if (parts.length > 3) {
          const address = parts[3];
          const portMatch = address.match(/:(\d+)$/);
          if (portMatch) {
            ports.push(parseInt(portMatch[1]));
          }
        }
      }
    }
    
    return [...new Set(ports)]; // Remove duplicates
  }

  stop() {
    this.isRunning = false;
    
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    
    console.log('Process monitoring stopped');
  }
}

module.exports = ProcessMonitor;