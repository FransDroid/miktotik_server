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

  const connection = new RouterOSAPI({
    host,
    user,
    password,
    port: Number(port),
    timeout: 10000
  });

  await connection.connect();
  try {
    const result = await connection.write(command, args);
    return result;
  } finally {
    try { await connection.close(); } catch (_) {}
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

    try {
      // Step 1: Check if WireGuard interface already exists
      const existingInterfaces = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/interface/wireguard/print',
        args: ['?name=wg_mmtech']
      });

      let interfaceId;
      if (!existingInterfaces || existingInterfaces.length === 0) {
        // Step 2: Create WireGuard interface
        const interfaceResult = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/wireguard/add',
          args: ['=name=wg_mmtech', '=listen-port=13231']
        });
        interfaceId = interfaceResult.ret;
        results.push({ step: 'create_interface', success: true, id: interfaceId });
      } else {
        interfaceId = existingInterfaces[0]['.id'];
        results.push({ step: 'interface_exists', success: true, id: interfaceId });
      }

      // Step 3: Add IP address to WireGuard interface
      const addressResult = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/ip/address/add',
        args: [`=address=${client_address}`, '=interface=wg_mmtech']
      });
      results.push({ step: 'add_address', success: true, id: addressResult.ret });

      // Step 4: Add peer configuration
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

      // Step 5: Add explicit route to the peer address
      try {
        const peerIp = (client_address || '').split('/')[0] === '10.66.0.2' ? '10.66.0.1/32' : '10.66.0.1/32';
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
        results.push({ step: 'add_route', success: false, error: routeError?.message || 'failed' });
      }

      // Step 6: Add WireGuard interface to LAN list
      try {
        const lanListResult = await executeRouterCommand({
          host,
          user: u,
          password,
          port: Number(port) || 8728,
          command: '/interface/list/member/add',
          args: ['=list=LAN', '=interface=wg_mmtech']
        });
        results.push({ step: 'add_to_lan_list', success: true, id: lanListResult.ret });
      } catch (lanListError) {
        results.push({ step: 'add_to_lan_list', success: false, error: lanListError?.message || 'failed' });
      }

      // Step 7: Get the router's public key
      const interfaceDetails = await executeRouterCommand({
        host,
        user: u,
        password,
        port: Number(port) || 8728,
        command: '/interface/wireguard/print',
        args: ['?name=wg_mmtech', '=.proplist=public-key']
      });

      const routerPublicKey = interfaceDetails?.[0]?.['public-key'] || null;

      return res.json({ 
        success: true, 
        message: 'WireGuard VPN configuration completed successfully',
        results,
        router_public_key: routerPublicKey
      });

    } catch (stepError) {
      errors.push({ step: 'configuration', error: stepError.message });
      return res.status(500).json({ 
        success: false, 
        message: 'WireGuard VPN configuration failed',
        results,
        errors
      });
    }

  } catch (error) {
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

const host = process.env.SERVER_HOST || '127.0.0.1';
const port = process.env.SERVER_PORT || process.env.PORT || 8080;

app.listen(port, host, () => {
  console.log(`MikroTik VPN Server listening on ${host}:${port}`);
  console.log('Mode: VPN Setup Only');
  console.log(`Log level: ${process.env.LOG_LEVEL || 'info'}`);
});
