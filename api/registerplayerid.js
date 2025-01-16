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
        throw e;
    }
}

/**
 * Updates PlayFab Title Data with new ID mappings
 * @param {string} titleId - PlayFab Title ID
 * @param {string} secretKey - PlayFab Developer Secret Key
 * @param {Object} mappings - Updated mappings object
 * @returns {Promise<Object>} - PlayFab API response
 */
async function setTitleData(titleId, secretKey, mappings) {
    const response = await fetch(`https://${titleId}.playfabapi.com/Server/SetTitleData`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-SecretKey': secretKey
        },
        body: JSON.stringify({
            Key: "idMappings",
            Value: JSON.stringify(mappings)
        })
    });

    const result = await response.json();
    
    if (!response.ok) {
        console.error('PlayFab SetTitleData failed:', result);
        throw new Error(`PlayFab API error: ${result.errorMessage || 'Unknown error'}`);
    }

    return result;
}

export default async function handler(req, res) {
    // Temporary debug logging
    console.log('Current environment variables:', {
        TITLE_ID: process.env.PLAYFAB_TITLE_ID,
        // Don't log the full secret key for security
        SECRET_KEY_START: process.env.PLAYFAB_DEV_SECRET_KEY?.substring(0, 8)
    });
    
    console.log('Received ID mapping request:', req.body);
    
    try {
        if (req.method !== 'POST') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        const { customId, playFabId } = req.body;
        if (!customId || !playFabId) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing customId or playFabId' 
            });
        }

        // Get existing mappings
        const mappings = await getTitleData(
            process.env.PLAYFAB_TITLE_ID, 
            process.env.PLAYFAB_DEV_SECRET_KEY
        );

        // Update mapping
        mappings[customId] = playFabId;
        
        // Store updated mappings
        await setTitleData(
            process.env.PLAYFAB_TITLE_ID, 
            process.env.PLAYFAB_DEV_SECRET_KEY, 
            mappings
        );

        console.log(`Successfully mapped CustomID ${customId} to PlayFabID ${playFabId}`);
        
        return res.status(200).json({ 
            success: true,
            message: 'ID mapping stored successfully'
        });
    } catch (err) {
        console.error('Error processing ID mapping request:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Internal Server Error',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
}