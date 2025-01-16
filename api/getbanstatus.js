import fetch from 'node-fetch';

/**
 * Fetches PlayFab Title Data containing ID mappings
 * @param {string} titleId - PlayFab Title ID
 * @param {string} secretKey - PlayFab Developer Secret Key
 * @returns {Promise<Object>} - Mapping of CustomIDs to PlayFabIDs
 */
async function getTitleData(titleId, secretKey) {
    try {
        const response = await fetch(`https://${titleId}.playfabapi.com/Server/GetTitleData`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: JSON.stringify({
                Keys: ["idMappings"]
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            console.error('PlayFab GetTitleData failed:', data);
            throw new Error(`PlayFab API error: ${data.errorMessage || 'Unknown error'}`);
        }

        return JSON.parse(data.data.Data.idMappings || '{}');
    } catch (e) {
        console.error('Failed to fetch or parse ID mappings:', e);
        throw e; // Re-throw to be handled by the main error handler
    }
}

/**
 * Fetches ban information for a player from PlayFab
 * @param {string} titleId - PlayFab Title ID
 * @param {string} secretKey - PlayFab Developer Secret Key
 * @param {string} playFabId - Player's PlayFab ID
 * @returns {Promise<Array>} - Array of active ban information
 */
async function getBanInfo(titleId, secretKey, playFabId) {
    const response = await fetch(`https://${titleId}.playfabapi.com/Server/GetUserBans`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-SecretKey': secretKey,
        },
        body: JSON.stringify({ PlayFabId: playFabId }),
    });

    const result = await response.json();

    if (!response.ok) {
        console.error('PlayFab GetUserBans failed:', result);
        throw new Error(`PlayFab API error: ${result.errorMessage || 'Unknown error'}`);
    }

    return (result.data.BanData || [])
        .filter(ban => ban.Active)
        .map(ban => ({
            reason: ban.Reason,
            expires: ban.Expires,
            created: ban.Created
        }));
}

/**
 * API handler for checking player ban status
 * Interfaces with PlayFab to retrieve active bans for a given CustomID
 */
export default async function handler(req, res) {
    console.log('Received ban status request for CustomID:', req.body?.customId);
    
    try {
        if (req.method !== 'POST') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        const { customId } = req.body;
        if (!customId) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing customId' 
            });
        }

        // Get ID mapping
        const mappings = await getTitleData(
            process.env.PLAYFAB_TITLE_ID, 
            process.env.PLAYFAB_DEV_SECRET_KEY
        );
        
        const playFabId = mappings[customId];
        if (!playFabId) {
            console.warn(`No PlayFabID found for CustomID: ${customId}`);
            return res.status(404).json({ 
                success: false, 
                error: 'Player not found' 
            });
        }

        // Get ban information
        const activeBans = await getBanInfo(
            process.env.PLAYFAB_TITLE_ID,
            process.env.PLAYFAB_DEV_SECRET_KEY,
            playFabId
        );

        console.log(`Retrieved ${activeBans.length} active bans for PlayFabID: ${playFabId}`);
        
        return res.status(200).json({
            success: true,
            data: { bans: activeBans }
        });

    } catch (err) {
        console.error('Error processing ban status request:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
}