#!/usr/bin/env node

import fs from 'fs';
import { execSync } from 'child_process';

const CONFIG_FILE = 'config.json';

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch (error) {
    console.error('❌ Error loading config.json:', error.message);
    process.exit(1);
  }
}

function saveConfig(config) {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
    console.log('✅ Configuration saved to config.json');
  } catch (error) {
    console.error('❌ Error saving config.json:', error.message);
    process.exit(1);
  }
}

function deployToKV(key, value) {
  try {
    const command = `wrangler kv key put --remote --binding=AUTH_KV "config:${key}" "${value}"`;
    execSync(command, { stdio: 'inherit' });
    console.log(`✅ Deployed ${key} = ${value} to KV store`);
  } catch (error) {
    console.error(`❌ Error deploying ${key} to KV store:`, error.message);
    process.exit(1);
  }
}

function displayHelp() {
  console.log(`
🔐 Auth Service Configuration Manager

Usage: node manage-config.js <command> [options]

Commands:
  show                              Show current configuration
  set <key> <value>                Set a configuration value
  deploy                           Deploy all configurations to KV store
  enable-registration              Enable user registration
  disable-registration             Disable user registration
  help                             Show this help message

Examples:
  node manage-config.js show
  node manage-config.js set User.Registration.Allowed false
  node manage-config.js enable-registration
  node manage-config.js disable-registration
  node manage-config.js deploy
`);
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args[0] === 'help') {
    displayHelp();
    return;
  }

  const command = args[0];
  
  switch (command) {
    case 'show': {
      const config = loadConfig();
      console.log('📋 Current Configuration:');
      console.log(JSON.stringify(config, null, 2));
      break;
    }
    
    case 'set': {
      if (args.length < 3) {
        console.error('❌ Usage: node manage-config.js set <key> <value>');
        process.exit(1);
      }
      
      const key = args[1];
      const value = args[2] === 'true' ? true : args[2] === 'false' ? false : args[2];
      
      const config = loadConfig();
      config[key] = value;
      saveConfig(config);
      
      console.log(`🔧 Updated ${key} to ${value}`);
      console.log('💡 Run "node manage-config.js deploy" to deploy to KV store');
      break;
    }
    
    case 'deploy': {
      const config = loadConfig();
      console.log('🚀 Deploying configuration to KV store...');
      
      // Deploy each configuration key
      Object.entries(config).forEach(([key, value]) => {
        if (key !== 'description' && key !== 'version') {
          deployToKV(key, value);
        }
      });
      
      console.log('✅ All configurations deployed successfully!');
      break;
    }
    
    case 'enable-registration': {
      const config = loadConfig();
      config['User.Registration.Allowed'] = true;
      saveConfig(config);
      deployToKV('User.Registration.Allowed', 'true');
      console.log('✅ User registration has been enabled');
      break;
    }
    
    case 'disable-registration': {
      const config = loadConfig();
      config['User.Registration.Allowed'] = false;
      saveConfig(config);
      deployToKV('User.Registration.Allowed', 'false');
      console.log('🚫 User registration has been disabled');
      break;
    }
    
    default:
      console.error(`❌ Unknown command: ${command}`);
      displayHelp();
      process.exit(1);
  }
}

main(); 