import fetch from 'node-fetch';

/**
 * API Module for Oculus nonce validation
 * Validates nonce against Oculus API using app credentials from env variables
 * Requires OCULUS_APP_ID and OCULUS_APP_SECRET environment variables
 * @route POST /api/validateoculus
 * @param {Object} req - Express request object with userId and nonce in body
 * @param {Object} res - Express response object
 * @returns {Object} JSON response with validation result or error
 */
export default async function handler(req, res) {
    console.log('Received Oculus validation request:', req.body);
    
    try {
        if (req.method !== 'POST') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        const { userId, nonce } = req.body;
        if (!userId || !nonce) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing userId or nonce' 
            });
        }

        const appId = process.env.OCULUS_APP_ID;
        const appSecret = process.env.OCULUS_APP_SECRET;
        if (!appId || !appSecret) {
            return res.status(500).json({ 
                success: false, 
                error: 'Server configuration error' 
            });
        }

        const accessToken = `OC|${appId}|${appSecret}`;
        const url = `https://graph.oculus.com/user_nonce_validate?nonce=${nonce}&user_id=${userId}&access_token=${accessToken}`;

        const response = await fetch(url, {
            method: 'POST'
        });

        const body = await response.text();  // Use text() to handle non-JSON errors safely
        
        if (!response.ok) {
            console.error('Oculus validation failed:', body);
            return res.status(response.status).json({
                success: false,
                error: 'Oculus API error',
                details: body
            });
        }

        let result;
        try {
            result = JSON.parse(body);
        } catch (e) {
            return res.status(500).json({
                success: false,
                error: 'Invalid response from Oculus',
                details: body
            });
        }

        return res.status(200).json({
            success: true,
            isValid: result.is_valid
        });

    } catch (err) {
        console.error('Error processing Oculus validation:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Internal Server Error'
        });
    }
}