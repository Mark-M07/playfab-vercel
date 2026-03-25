import fetch from 'node-fetch';
import crypto from 'crypto';

/**
 * API Module for automated ValidationToken rotation.
 * Generates a cryptographically random token and stores it in PlayFab public
 * TitleData — intentionally public so authenticated clients can read it via
 * GetTitleData for matchmaking isolation (see Security Architecture §7.2).
 *
 * Called via Vercel Cron every 1 hour.
 * Requires PLAYFAB_TITLE_ID, PLAYFAB_DEV_SECRET_KEY, CRON_SECRET env vars.
 *
 * NOTE: This endpoint does NOT use DoH-pinned connections for PlayFab traffic.
 * DoH pinning is implemented in /api/verifyoculuslogin only.
 *
 * @route GET /api/rotatetoken
 */
export default async function handler(req, res) {
    try {
        if (req.method !== 'GET') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        // Verify the request is from Vercel's cron scheduler
        const cronSecret = process.env.CRON_SECRET;
        if (cronSecret && req.headers['authorization'] !== `Bearer ${cronSecret}`) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized'
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

        // Store the new token in PlayFab public TitleData — readable by any client
        // with a valid SessionTicket (i.e. only Vercel-authenticated clients)
        const updateUrl = `https://${titleId}.playfabapi.com/Admin/SetTitleData`;
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
                error: 'Failed to rotate token'
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