// src/pages/api/scan.js
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Call our Python script
    const { stdout } = await execPromise('python3 skills/security_scan/security_logic.py');
    
    // Parse the JSON output
    const scanResults = JSON.parse(stdout);
    
    // Return the results
    res.status(200).json(scanResults);
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      error: 'Failed to perform security scan',
      details: error.message 
    });
  }
}