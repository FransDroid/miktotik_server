const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { RouterOSAPI } = require('node-routeros');
const { Client: SSHClient } = require('ssh2');

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());

async function executeRouterCommand(options) {
  const {
    host,
    user,
    password,
    port = 8728,
    command = '/interface/print',
    args = []
  } = options;

  console.log(`[DEBUG] Starting RouterOS command execution:`, {
    host,
    user,
    port,
    command,
    args: args.length > 0 ? args : 'none'
  });

  // Wrap the entire operation in a try-catch to handle any uncaught errors
  try {
    const connection = new RouterOSAPI({
      host,
      user,
      password,
      port: Number(port),
      timeout: 10000
    });

    // Add error handlers to the connection to catch unhandled errors
    connection.on('error', (err) => {
      console.warn(`[WARN] RouterOS connection error:`, err.message);
    });

    // Add a handler for unknown replies to prevent crashes
    connection.on('unknown', (data) => {
      console.warn(`[WARN] RouterOS unknown reply received:`, data);
    });

    console.log(`[DEBUG] RouterOSAPI connection object created for ${host}:${port}`);

    try {
    console.log(`[DEBUG] Attempting to connect to ${host}:${port}...`);
    await connection.connect();
    console.log(`[DEBUG] Successfully connected to ${host}:${port}`);
    
    console.log(`[DEBUG] Executing command: ${command} with args:`, args);
    
    // Wrap the write operation in a promise to catch all errors
    const result = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        console.warn(`[WARN] Command timeout for ${command}, treating as empty result`);
        resolve([]); // Return empty array instead of rejecting
      }, 5000); // Reduced timeout to 5 seconds
      
      try {
        connection.write(command, args)
          .then((res) => {
            clearTimeout(timeout);
            resolve(res);
          })
          .catch((err) => {
            clearTimeout(timeout);
            // Handle !empty and unknown reply errors gracefully
            if (err.message?.includes('!empty') || 
                err.message?.includes('Tried to process unknown reply') ||
                err.message?.includes('unknown reply')) {
              console.warn(`[WARN] RouterOS returned !empty/unknown reply for ${command}, treating as empty result`);
              resolve([]);
            } else {
              reject(err);
            }
          });
      } catch (syncError) {
        clearTimeout(timeout);
        reject(syncError);
      }
    });
    
    console.log(`[DEBUG] Command executed successfully, result length:`, result ? result.length : 'null');
    return result;
  } catch (error) {
    console.error(`[ERROR] RouterOS command failed:`, {
      host,
      port,
      command,
      errorType: error.constructor.name,
      errno: error.errno,
      message: error.message,
      stack: error.stack
    });

    // Handle specific RouterOS API errors
    if (error.errno === 'UNKNOWNREPLY' || error.message?.includes('unknown reply')) {
      console.warn(`[WARN] RouterOS API unknown reply for command: ${command}`, error.message);
      console.warn(`[WARN] This usually means the command is not supported or router returned unexpected data`);
      // For unknown replies, return empty array instead of throwing
      return [];
    }
    
    // Handle !empty replies specifically
    if (error.message?.includes('!empty') || error.message?.includes('Tried to process unknown reply')) {
      console.warn(`[WARN] RouterOS returned !empty reply for command: ${command}`);
      console.warn(`[WARN] This usually means no results found or command not applicable`);
      // For !empty replies, return empty array instead of throwing
      return [];
    }
    
    // Handle connection errors
    if (error.message && error.message.includes('timeout')) {
      console.error(`[ERROR] Connection timeout to ${host}:${port}`);
      throw new Error(`Connection timeout to ${host}:${port}. Check network connectivity and router settings.`);
    }
    
    // Handle authentication errors
    if (error.message && error.message.includes('invalid user name or password')) {
      console.error(`[ERROR] Authentication failed for ${user}@${host}`);
      throw new Error(`Authentication failed for ${user}@${host}. Check username and password.`);
    }
    
    // Re-throw other errors
    console.error(`[ERROR] Unhandled RouterOS error:`, error);
    throw error;
  } finally {
    try { 
      console.log(`[DEBUG] Closing connection to ${host}:${port}`);
      await connection.close(); 
      console.log(`[DEBUG] Connection closed successfully`);
    } catch (closeError) {
      console.warn(`[WARN] Error closing connection:`, closeError.message);
    }
  }
  } catch (outerError) {
      console.error(`[ERROR] Outer RouterOS operation failed:`, {
        error: outerError.message,
        stack: outerError.stack,
        command,
        host,
        port
      });
      
      // Handle !empty and unknown reply errors at the outer level
      if (outerError.message?.includes('!empty') || 
          outerError.message?.includes('Tried to process unknown reply') ||
          outerError.message?.includes('unknown reply')) {
        console.warn(`[WARN] RouterOS returned !empty or unknown reply for command: ${command}`);
        return [];
      }
      
      // Re-throw other errors
      throw outerError;
    }
  }

// Minimal allowlist for VPN setup only
const allowedCommands = new Set([
  // System info
  '/system/identity/print',
  '/system/resource/print',
  
  // WireGuard VPN commands
  '/interface/wireguard/print',
  '/interface/wireguard/add',
  '/interface/wireguard/set',
  '/interface/wireguard/remove',
  '/interface/wireguard/peers/print',
  '/interface/wireguard/peers/add',
  '/interface/wireguard/peers/set',
  '/interface/wireguard/peers/remove',
  
  // IP management for VPN
  '/ip/address/print',
  '/ip/address/add',
  '/ip/address/set',
  '/ip/address/remove',
  '/ip/route/print',
  '/ip/route/add',
  '/ip/route/remove',
  
  // Interface management for VPN
  '/interface/print',
  '/interface/list/member/add',
  '/interface/list/member/print',
  '/interface/list/member/remove',
  
  // Connection test
  '/ping'
]);

// Health check
app.get('/health', (_req, res) => {
  return res.json({ 
    status: 'ok', 
    host: process.env.SERVER_HOST || '127.0.0.1',
    port: Number(process.env.SERVER_PORT || process.env.PORT) || 8080,
    backend_url: process.env.BACKEND_URL || null,
    log_level: process.env.LOG_LEVEL || 'info',
    mode: 'vpn-only'
  });
});

// Test VPN connection
app.post('/api/vpn/test-connection', async (req, res) => {
  try {
    const { host, username, user, password, port, connection_type } = req.body || {};
    const u = user || username;
    if (!host || !u || !password) {
      return res.status(400).json({ success: false, message: 'host, user/username, password are required' });
    }

    console.log(`Testing VPN connection to ${host}:${port || (connection_type === 'ssh' ? 22 : 8728)} via ${connection_type || 'api'}`);

    if ((connection_type || 'api') === 'ssh') {
      const conn = new SSHClient();
      const connectionPromise = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          conn.end();
          reject(new Error(`SSH connection timeout - unable to reach ${host}:${port || 22}. Make sure the router is on the same network and SSH is enabled.`));
        }, 15000);

        conn
          .on('ready', () => {
            clearTimeout(timeout);
            resolve();
          })
          .on('error', (err) => {
            clearTimeout(timeout);
            reject(new Error(`SSH error: ${err.message}`));
          })
          .connect({
            host,
            port: Number(port) || 22,
            username: u,
            password,
            readyTimeout: 15000
          });
      });

      await connectionPromise;
      conn.end();
      console.log(`SSH connection successful to ${host}`);
      return res.json({ success: true, message: 'SSH connection successful' });
    } else {
      const data = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/system/identity/print'
      });
      console.log(`API connection successful to ${host}`);
      return res.json({ success: true, message: 'API connection successful', data });
    }
  } catch (error) {
    console.error(`VPN connection test failed: ${error?.message}`);
    return res.status(200).json({ success: false, message: error?.message || 'connection failed' });
  }
});

// Get router basic info for VPN setup
app.post('/api/vpn/router-info', async (req, res) => {
  try {
    const { host, user, username, password, port } = req.body || {};
    const u = user || username;
    if (!host || !u || !password) {
      return res.status(400).json({ error: 'host, user/username, password are required' });
    }

    const identity = await executeRouterCommand({ host, user: u, password, port, command: '/system/identity/print' });
    const resource = await executeRouterCommand({ host, user: u, password, port, command: '/system/resource/print' });
    const interfaces = await executeRouterCommand({ host, user: u, password, port, command: '/interface/print' });

    const routerInfo = {
      identity: identity?.[0] || null,
      resource: resource?.[0] || null,
      interfaces: interfaces || [],
      last_sync: new Date().toISOString()
    };

    return res.json({ success: true, data: routerInfo });
  } catch (error) {
    return res.status(500).json({ success: false, message: error?.message || 'failed to get router info' });
  }
});

// Setup WireGuard VPN
app.post('/api/vpn/setup', async (req, res) => {
  console.log(`[DEBUG] VPN setup request received:`, {
    body: req.body ? Object.keys(req.body) : 'no body',
    timestamp: new Date().toISOString()
  });

  try {
    const { 
      host, 
      user, 
      username, 
      password, 
      port, 
      vpnConfig 
    } = req.body || {};
    
    console.log(`[DEBUG] Parsed request parameters:`, {
      host,
      user: user || username,
      port,
      hasPassword: !!password,
      hasVpnConfig: !!vpnConfig
    });
    
    const u = user || username;
    if (!host || !u || !password || !vpnConfig) {
      console.error(`[ERROR] Missing required parameters:`, {
        host: !!host,
        user: !!u,
        password: !!password,
        vpnConfig: !!vpnConfig
      });
      return res.status(400).json({ 
        success: false, 
        message: 'host, user/username, password, and vpnConfig are required' 
      });
    }

    const { 
      server_public_key, 
      endpoint_host, 
      endpoint_port, 
      client_address, 
      allowed_ips, 
      persistent_keepalive 
    } = vpnConfig;

    if (!server_public_key || !endpoint_host || !endpoint_port || !client_address) {
      return res.status(400).json({ 
        success: false, 
        message: 'vpnConfig must include server_public_key, endpoint_host, endpoint_port, and client_address' 
      });
    }

    const results = [];
    const errors = [];

    console.log(`[DEBUG] Starting VPN setup process for ${host}:${port || 8728}`);

    try {
      // Step 1: Check if WireGuard interface already exists
      console.log(`[DEBUG] Step 1: Checking for existing WireGuard interface...`);
      const existingInterfaces = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/interface/wireguard/print',
        args: ['?name=wg_mmtech']
      });
      console.log(`[DEBUG] Step 1 completed. Found ${existingInterfaces ? existingInterfaces.length : 0} existing interfaces`);

      let interfaceId;
      if (!existingInterfaces || existingInterfaces.length === 0) {
        // Step 2: Create WireGuard interface
        console.log(`[DEBUG] Step 2: Creating new WireGuard interface...`);
        const interfaceResult = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/wireguard/add',
          args: ['=name=wg_mmtech', '=listen-port=13231']
        });
        interfaceId = interfaceResult.ret;
        console.log(`[DEBUG] Step 2 completed. Interface created with ID: ${interfaceId}`);
        results.push({ step: 'create_interface', success: true, id: interfaceId });
      } else {
        interfaceId = existingInterfaces[0]['.id'];
        console.log(`[DEBUG] Step 2: Using existing interface with ID: ${interfaceId}`);
        results.push({ step: 'interface_exists', success: true, id: interfaceId });
      }

      // Step 3: Add IP address to WireGuard interface
      console.log(`[DEBUG] Step 3: Adding IP address ${client_address} to WireGuard interface...`);
      const addressResult = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/ip/address/add',
        args: [`=address=${client_address}`, '=interface=wg_mmtech']
      });
      console.log(`[DEBUG] Step 3 completed. Address added with ID: ${addressResult.ret}`);
      results.push({ step: 'add_address', success: true, id: addressResult.ret });

      // Step 4: Add peer configuration
      console.log(`[DEBUG] Step 4: Adding peer configuration...`);
      const peerArgs = [
        '=interface=wg_mmtech',
        `=public-key=${server_public_key}`,
        `=endpoint-address=${endpoint_host}`,
        `=endpoint-port=${endpoint_port}`,
        `=allowed-address=${allowed_ips}`,
        `=persistent-keepalive=${persistent_keepalive || 25}s`
      ];
      console.log(`[DEBUG] Peer args:`, peerArgs);

      const peerResult = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/interface/wireguard/peers/add',
        args: peerArgs
      });
      console.log(`[DEBUG] Step 4 completed. Peer added with ID: ${peerResult.ret}`);
      results.push({ step: 'add_peer', success: true, id: peerResult.ret });

      // Step 5: Add explicit route to the peer address
      console.log(`[DEBUG] Step 5: Adding route to peer address...`);
      try {
        const peerIp = (client_address || '').split('/')[0] === '10.66.0.2' ? '10.66.0.1/32' : '10.66.0.1/32';
        console.log(`[DEBUG] Adding route for peer IP: ${peerIp}`);
        const routeResult = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/ip/route/add',
          args: [`=dst-address=${peerIp}`, '=gateway=wg_mmtech', '=comment=WG peer route']
        });
        console.log(`[DEBUG] Step 5 completed. Route added with ID: ${routeResult.ret}`);
        results.push({ step: 'add_route', success: true, id: routeResult.ret });
      } catch (routeError) {
        console.warn(`[WARN] Step 5 failed:`, routeError?.message);
        results.push({ step: 'add_route', success: false, error: routeError?.message || 'failed' });
      }

      // Step 6: Add WireGuard interface to LAN list
      console.log(`[DEBUG] Step 6: Adding WireGuard interface to LAN list...`);
      try {
        const lanListResult = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/list/member/add',
          args: ['=list=LAN', '=interface=wg_mmtech']
        });
        console.log(`[DEBUG] Step 6 completed. LAN list member added with ID: ${lanListResult.ret}`);
        results.push({ step: 'add_to_lan_list', success: true, id: lanListResult.ret });
      } catch (lanListError) {
        console.warn(`[WARN] Step 6 failed:`, lanListError?.message);
        results.push({ step: 'add_to_lan_list', success: false, error: lanListError?.message || 'failed' });
      }

      // Step 7: Get the router's public key
      console.log(`[DEBUG] Step 7: Getting router's public key...`);
      const interfaceDetails = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/interface/wireguard/print',
        args: ['?name=wg_mmtech', '=.proplist=public-key']
      });

      const routerPublicKey = interfaceDetails?.[0]?.['public-key'] || null;
      console.log(`[DEBUG] Step 7 completed. Router public key: ${routerPublicKey ? 'found' : 'not found'}`);

      console.log(`[DEBUG] VPN setup completed successfully for ${host}`);
      return res.json({ 
        success: true, 
        message: 'WireGuard VPN configuration completed successfully',
        results,
        router_public_key: routerPublicKey
      });

    } catch (stepError) {
      console.error(`[ERROR] VPN setup failed during configuration:`, {
        error: stepError.message,
        stack: stepError.stack,
        step: 'configuration'
      });
      errors.push({ step: 'configuration', error: stepError.message });
      return res.status(500).json({ 
        success: false, 
        message: 'WireGuard VPN configuration failed',
        results,
        errors
      });
    }

  } catch (error) {
    console.error(`[ERROR] VPN setup failed with unhandled error:`, {
      error: error?.message,
      stack: error?.stack,
      type: error?.constructor?.name
    });
    return res.status(500).json({ 
      success: false, 
      message: error?.message || 'VPN setup failed' 
    });
  }
});


// Execute specific command (for advanced operations)
app.post('/api/execute', async (req, res) => {
  try {
    const { host, user, username, password, port, command, args = [] } = req.body || {};
    const u = user || username;
    if (!host || !u || !password || !command) {
      return res.status(400).json({ success: false, message: 'host, user/username, password, command required' });
    }

    // Check if command is allowed
    if (!allowedCommands.has(command)) {
      return res.status(403).json({ success: false, message: `Command ${command} is not allowed` });
    }

    const result = await executeRouterCommand({ 
      host, 
      user: u, 
      password, 
      port: Number(port) || 8728, 
      command, 
      args 
    });

    return res.json({ 
      success: true, 
      message: 'Command executed successfully',
      result: result
    });
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      message: error?.message || 'Failed to execute command' 
    });
  }
});

// Global error handlers
process.on('uncaughtException', (error) => {
  console.error(`[FATAL] Uncaught Exception:`, {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  // Don't exit for RouterOS-specific errors, just log them
  if (error.message?.includes('!empty') || 
      error.message?.includes('Tried to process unknown reply') ||
      error.message?.includes('unknown reply')) {
    console.warn(`[WARN] RouterOS-specific error caught globally, continuing...`);
    return;
  }
  
  // Exit for other critical errors
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error(`[FATAL] Unhandled Rejection:`, {
    reason: reason,
    promise: promise,
    timestamp: new Date().toISOString()
  });
  
  // Don't exit for RouterOS-specific errors
  if (reason?.message?.includes('!empty') || 
      reason?.message?.includes('Tried to process unknown reply') ||
      reason?.message?.includes('unknown reply')) {
    console.warn(`[WARN] RouterOS-specific rejection caught globally, continuing...`);
    return;
  }
  
  // Exit for other critical rejections
  process.exit(1);
});

const host = process.env.SERVER_HOST || '127.0.0.1';
const port = process.env.SERVER_PORT || process.env.PORT || 9876;

app.listen(port, host, () => {
  console.log(`MikroTik VPN Server listening on ${host}:${port}`);
  console.log('Mode: VPN Setup Only');
  console.log(`Log level: ${process.env.LOG_LEVEL || 'info'}`);
  console.log(`[DEBUG] Server started with comprehensive logging enabled`);
});
