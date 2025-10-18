import fetch from 'node-fetch';
import crypto from 'crypto';

/**
 * API Module for automated token rotation
 * Generates and stores a new validation token in PlayFab TitleInternalData
 * Called via Vercel Cron every 3 hours
 * Requires PLAYFAB_TITLE_ID, PLAYFAB_DEV_SECRET_KEY env vars
 * @route POST /api/rotatetoken
 */
export default async function handler(req, res) {
    try {
        if (req.method !== 'POST') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        const titleId = process.env.PLAYFAB_TITLE_ID;
        const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;
        
        if (!titleId || !secretKey) {
            return res.status(500).json({ 
                success: false, 
                error: 'Internal Server Error' 
            });
        }

        // Generate a new cryptographically secure token
        const newToken = crypto.randomBytes(32).toString('base64');
        
        // Store the new token in PlayFab TitleInternalData
        const updateUrl = `https://${titleId}.playfabapi.com/Admin/SetTitleInternalData`;
        const updateBody = JSON.stringify({
            Key: 'ValidationToken',
            Value: newToken
        });

        const updateResponse = await fetch(updateUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: updateBody
        });

        if (!updateResponse.ok) {
            const errorData = await updateResponse.json();
            console.error('Failed to update validation token:', errorData);
            return res.status(500).json({
                success: false,
                error: 'Failed to rotate token',
                details: errorData
            });
        }

        console.log(`Token rotated successfully at ${new Date().toISOString()}`);
        
        return res.status(200).json({
            success: true,
            message: 'Token rotated successfully',
            timestamp: new Date().toISOString()
        });

    } catch (err) {
        console.error('Error rotating token:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Internal Server Error' 
        });
    }
}