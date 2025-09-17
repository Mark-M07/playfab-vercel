/**
 * API Module for checking player ban status
 * Interfaces with PlayFab to retrieve active ban information for players
 * Uses chunked storage system to handle large numbers of ID mappings
 * Requires PLAYFAB_TITLE_ID and PLAYFAB_DEV_SECRET_KEY environment variables
 */
import fetch from 'node-fetch';

/**
 * Fetches PlayFab Title Data from chunked storage
 * Uses first 2 characters of customId to determine chunk key
 * @param {string} titleId - PlayFab Title ID
 * @param {string} secretKey - PlayFab Developer Secret Key
 * @param {string} customId - Custom ID to look up
 * @returns {Promise<string|null>} - PlayFabID if found, null otherwise
 * @throws {Error} If API call fails
 */
async function getPlayFabIdFromChunkedStorage(titleId, secretKey, customId) {
    // Use first 2 characters for chunk key (idChunk_00 through idChunk_99)
    const chunkKey = `idChunk_${customId.substring(0, 2)}`;
    
    try {
        const response = await fetch(`https://${titleId}.playfabapi.com/Server/GetTitleData`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: JSON.stringify({
                Keys: [chunkKey]
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            console.error(`PlayFab GetTitleData failed for chunk ${chunkKey}:`, data);
            throw new Error(`PlayFab API error: ${data.errorMessage || 'Unknown error'}`);
        }

        // Check if chunk exists and contains data
        if (data.data?.Data?.[chunkKey]) {
            const mappings = JSON.parse(data.data.Data[chunkKey]);
            return mappings[customId] || null;
        }
        
        return null;
    } catch (e) {
        console.error(`Failed to fetch mapping from chunk ${chunkKey}:`, e);
        throw e;
    }
}

/**
 * Fetches ban information for a player from PlayFab
 * Retrieves and filters active bans for the specified player
 * @param {string} titleId - PlayFab Title ID
 * @param {string} secretKey - PlayFab Developer Secret Key
 * @param {string} playFabId - Player's PlayFab ID
 * @returns {Promise<Array>} - Array of active ban information objects
 * @throws {Error} If API call fails
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
 * API endpoint handler for checking player ban status
 * Uses chunked storage system to find player mappings
 * 
 * @route POST /api/getbanstatus
 * @param {Object} req - Express request object with customId in body
 * @param {Object} res - Express response object
 * @returns {Object} JSON response with ban status or error message
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

        // Get PlayFabID from chunked storage
        const playFabId = await getPlayFabIdFromChunkedStorage(
            process.env.PLAYFAB_TITLE_ID, 
            process.env.PLAYFAB_DEV_SECRET_KEY,
            customId
        );
        
        if (!playFabId) {
            console.warn(`No PlayFabID found for CustomID: ${customId} in chunk idChunk_${customId.substring(0, 2)}`);
            return res.status(404).json({ 
                success: false, 
                error: 'Player not found - please log in to update your account' 
            });
        }

        console.log(`Found PlayFabID ${playFabId} for CustomID ${customId}`);

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