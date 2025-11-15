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

/**
 * Compare RouterOS version strings
 * @param {string} version1 - First version (e.g., "7.20.2")
 * @param {string} version2 - Second version (e.g., "7.20.3")
 * @returns {number} - Returns 1 if version1 > version2, -1 if version1 < version2, 0 if equal
 */
function compareRouterOSVersion(version1, version2) {
  const v1Parts = version1.split('.').map(Number);
  const v2Parts = version2.split('.').map(Number);
  
  // Pad shorter version with zeros
  const maxLength = Math.max(v1Parts.length, v2Parts.length);
  while (v1Parts.length < maxLength) v1Parts.push(0);
  while (v2Parts.length < maxLength) v2Parts.push(0);
  
  for (let i = 0; i < maxLength; i++) {
    if (v1Parts[i] > v2Parts[i]) return 1;
    if (v1Parts[i] < v2Parts[i]) return -1;
  }
  
  return 0;
}

/**
 * Get the next version by incrementing the patch version
 * @param {string} version - Version string (e.g., "7.20.2")
 * @returns {string} - Next version (e.g., "7.20.3")
 */
function getNextVersion(version) {
  const parts = version.split('.').map(Number);
  if (parts.length >= 3) {
    parts[2] = (parts[2] || 0) + 1;
  } else if (parts.length === 2) {
    parts.push(1);
  } else {
    parts.push(0, 1);
  }
  return parts.join('.');
}

async function executeRouterCommand(options) {
  const {
    host,
    user,
    password,
    port = 8728,
    command = '/interface/print',
    args = []
  } = options;

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

    try {
    const isDebugMode = process.env.DEBUG_MODE === 'true';
    
    console.log(`[DEBUG] Attempting to connect to ${host}:${port}...`);
    await connection.connect();
    console.log(`[DEBUG] Successfully connected to ${host}:${port}`);
    
    if (isDebugMode) {
      console.log(`[DEBUG] Executing command: ${command}`);
      console.log(`[DEBUG] Command arguments:`, JSON.stringify(args, null, 2));
    }
    
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
            if (isDebugMode) {
              console.log(`[DEBUG] Command response:`, JSON.stringify(res, null, 2));
            }
            resolve(res);
          })
          .catch((err) => {
            clearTimeout(timeout);
            if (isDebugMode) {
              console.log(`[DEBUG] Command error:`, {
                message: err.message,
                errno: err.errno,
                stack: err.stack
              });
            }
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
    
    return result;
  } catch (error) {
    // Handle connection errors by errno code (e.g., -4039 for connection refused/failed)
    if (error.errno === -4039 || error.errno === 'ECONNREFUSED' || error.errno === 'ETIMEDOUT') {
      console.error(`[ERROR] Connection failed to ${host}:${port} (errno: ${error.errno})`);
      throw new Error(`Cannot connect to MikroTik router at ${host}:${port}. Please verify: 1) Router is powered on and reachable, 2) API service is enabled on the router, 3) Firewall allows connections to port ${port}, 4) Host and port are correct.`);
    }
    
    // Handle specific RouterOS API errors
    if (error.errno === 'UNKNOWNREPLY' || error.message?.includes('unknown reply')) {
      console.warn(`[WARN] This usually means the command is not supported or router returned unexpected data`);
      // For unknown replies, return empty array instead of throwing
      return [];
    }
    
    // Handle !empty replies specifically
    if (error.message?.includes('!empty') || error.message?.includes('Tried to process unknown reply')) {
      console.warn(`[WARN] This usually means no results found or command not applicable`);
      // For !empty replies, return empty array instead of throwing
      return [];
    }
    
    // Handle connection timeout errors
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
      await connection.close(); 
      console.log(`[DEBUG] Connection closed successfully`);
    } catch (closeError) {
      console.warn(`[WARN] Error closing connection:`, closeError.message);
    }
  }
  } catch (outerError) {
      
      // Handle connection errors at outer level
      if (outerError.errno === -4039 || outerError.errno === 'ECONNREFUSED' || outerError.errno === 'ETIMEDOUT') {
        console.error(`[ERROR] Connection failed at outer level (errno: ${outerError.errno})`);
        throw outerError; // Let inner handler's error message propagate
      }
      
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
    min_routeros_version: process.env.MIN_ROUTEROS_VERSION || '7.1',
    debug_mode: process.env.DEBUG_MODE === 'true',
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
      return res.json({ success: true, message: 'SSH connection successful' });
    } else {
      const data = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/system/identity/print'
      });
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

  try {
    const { 
      host, 
      user, 
      username, 
      password, 
      port, 
      vpnConfig 
    } = req.body || {};
  
    
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

    // Step 0: Check RouterOS firmware version (must be >= 7.20.2)
    console.log(`[DEBUG] Step 0: Checking RouterOS firmware version...`);
    try {
      const resource = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/system/resource/print'
      });

      const routerVersion = resource?.[0]?.version || null;
      console.log(`[DEBUG] RouterOS version detected: ${routerVersion}`);

      if (!routerVersion) {
        console.error(`[ERROR] Could not determine RouterOS version`);
        return res.status(400).json({
          success: false,
          message: 'Unable to determine RouterOS version. Please ensure the router is accessible and try again.'
        });
      } else {
        const minRequiredVersion = process.env.MIN_ROUTEROS_VERSION || '7.1';
        const majorVersion = parseInt(routerVersion.split('.')[0], 10);
        
        // WireGuard requires RouterOS v7.x or higher (not available in v6.x)
        if (majorVersion < 7) {
          console.error(`[ERROR] RouterOS version ${routerVersion} does not support WireGuard. Required: v7.x or higher`);
          return res.status(400).json({
            success: false,
            message: `RouterOS firmware version ${routerVersion} does not support WireGuard. WireGuard requires RouterOS v7.1 or higher. Please upgrade your RouterOS firmware to v7.1+ before proceeding with VPN setup.`,
            router_version: routerVersion,
            required_version: '>= 7.1'
          });
        }
        
        // Optional: Check against specific minimum version if set (e.g., 7.20.2 for stability)
        const versionComparison = compareRouterOSVersion(routerVersion, minRequiredVersion);
        if (versionComparison < 0) {
          console.warn(`[WARN] RouterOS version ${routerVersion} is below recommended version ${minRequiredVersion}, but WireGuard should still work`);
        }
        
        console.log(`[DEBUG] RouterOS version ${routerVersion} supports WireGuard (v7.x detected)`);
      }
    } catch (versionError) {
      console.error(`[ERROR] Failed to check RouterOS version:`, versionError?.message);
      // Block setup if we can't verify version - WireGuard only works on v7.x
      return res.status(500).json({
        success: false,
        message: `Unable to verify RouterOS version: ${versionError?.message || 'Connection failed'}. WireGuard requires RouterOS v7.1 or higher. Please verify the router is accessible and running RouterOS v7.1+ before proceeding.`
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

      // Step 3: Add IP address to WireGuard interface (remove and recreate if exists)
      console.log(`[DEBUG] Step 3: Configuring IP address ${client_address} on WireGuard interface...`);
      try {
        // Check if IP address already exists on wg_mmtech interface
        const existingAddresses = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/ip/address/print',
          args: ['?interface=wg_mmtech']
        });

        // Remove existing IP addresses on wg_mmtech interface
        if (existingAddresses && existingAddresses.length > 0) {
          console.log(`[DEBUG] Found ${existingAddresses.length} existing IP address(es), removing...`);
          for (const addr of existingAddresses) {
            try {
              await executeRouterCommand({
                host,
                user: u,
                password,
                port: Number(port) || 8728,
                command: '/ip/address/remove',
                args: [`=.id=${addr['.id']}`]
              });
            } catch (removeError) {
              console.warn(`[WARN] Failed to remove existing IP address:`, removeError?.message);
            }
          }
        }

        // Add the IP address
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
      } catch (addressError) {
        console.warn(`[WARN] Step 3 failed:`, addressError?.message);
        results.push({ step: 'add_address', success: false, error: addressError?.message || 'failed' });
      }

      // Step 4: Add peer configuration (remove and recreate if exists)
      console.log(`[DEBUG] Step 4: Configuring peer...`);
      try {
        // Check if peer with same public key already exists
        const existingPeers = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/wireguard/peers/print',
          args: [`?public-key=${server_public_key}`]
        });

        // Remove existing peer(s) with same public key
        if (existingPeers && existingPeers.length > 0) {
          for (const peer of existingPeers) {
            try {
              await executeRouterCommand({
                host,
                user: u,
                password,
                port: Number(port) || 8728,
                command: '/interface/wireguard/peers/remove',
                args: [`=.id=${peer['.id']}`]
              });
            } catch (removeError) {
              console.warn(`[WARN] Failed to remove existing peer:`, removeError?.message);
            }
          }
        }

        // Add the peer configuration
        const peerArgs = [
          '=interface=wg_mmtech',
          `=public-key=${server_public_key}`,
          `=endpoint-address=${endpoint_host}`,
          `=endpoint-port=${endpoint_port}`,
          `=allowed-address=${allowed_ips}`,
          `=persistent-keepalive=${persistent_keepalive || 25}s`
        ];
       
        const peerResult = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/wireguard/peers/add',
          args: peerArgs
        });
        results.push({ step: 'add_peer', success: true, id: peerResult.ret });
      } catch (peerError) {
        console.warn(`[WARN] Step 4 failed:`, peerError?.message);
        results.push({ step: 'add_peer', success: false, error: peerError?.message || 'failed' });
      }

      try {
        const peerIp = (client_address || '').split('/')[0] === '10.66.0.2' ? '10.66.0.1/32' : '10.66.0.1/32';
        // Check if route already exists
        const existingRoutes = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/ip/route/print',
          args: [`?dst-address=${peerIp}`, '?gateway=wg_mmtech']
        });

        // Remove existing route(s)
        if (existingRoutes && existingRoutes.length > 0) {
          for (const route of existingRoutes) {
            try {
              await executeRouterCommand({
                host,
                user: u,
                password,
                port: Number(port) || 8728,
                command: '/ip/route/remove',
                args: [`=.id=${route['.id']}`]
              });
            } catch (removeError) {
              console.warn(`[WARN] Failed to remove existing route:`, removeError?.message);
            }
          }
        }

        // Add the route
        const routeResult = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/ip/route/add',
          args: [`=dst-address=${peerIp}`, '=gateway=wg_mmtech', '=comment=WG peer route']
        });
        results.push({ step: 'add_route', success: true, id: routeResult.ret });
      } catch (routeError) {
        console.warn(`[WARN] Step 5 failed:`, routeError?.message);
        results.push({ step: 'add_route', success: false, error: routeError?.message || 'failed' });
      }

      // Step 6: Add WireGuard interface to LAN list (skip if already exists)
      try {
        // Check if interface is already in LAN list
        const existingLanMembers = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/list/member/print',
          args: ['?list=LAN', '?interface=wg_mmtech']
        });

        if (existingLanMembers && existingLanMembers.length > 0) {
          results.push({ step: 'add_to_lan_list', success: true, id: existingLanMembers[0]['.id'], skipped: true });
        } else {
          // Add to LAN list
          const lanListResult = await executeRouterCommand({
            host,
            user: u,
            password,
            port: Number(port) || 8728,
            command: '/interface/list/member/add',
            args: ['=list=LAN', '=interface=wg_mmtech']
          });
          results.push({ step: 'add_to_lan_list', success: true, id: lanListResult.ret });
        }
      } catch (lanListError) {
        console.warn(`[WARN] Step 6 failed:`, lanListError?.message);
        results.push({ step: 'add_to_lan_list', success: false, error: lanListError?.message || 'failed' });
      }

      // Step 7: Get the router's public key
      let routerPublicKey = null;
      try {
        const interfaceDetails = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/wireguard/print',
          args: ['?name=wg_mmtech', '=.proplist=public-key']
        });

        routerPublicKey = interfaceDetails?.[0]?.['public-key'] || null;
        results.push({ step: 'get_public_key', success: true, public_key: routerPublicKey || 'not found' });
      } catch (publicKeyError) {
        console.warn(`[WARN] Step 7 failed:`, publicKeyError?.message);
        results.push({ step: 'get_public_key', success: false, error: publicKeyError?.message || 'failed' });
      }

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
  console.log(`[DEBUG] Server started with comprehensive logging enabled`);
  if (process.env.DEBUG_MODE === 'true') {
    console.log(`[DEBUG] DEBUG_MODE is ENABLED - All command outputs will be logged`);
  }
});
