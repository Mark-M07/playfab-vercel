import fetch from 'node-fetch';

/**
 * API Module for Oculus nonce validation and PlayFab login
 * Validates nonce, then performs secure PlayFab Server LoginWithCustomID
 * Requires OCULUS_APP_ID, OCULUS_APP_SECRET, PLAYFAB_TITLE_ID, PLAYFAB_DEV_SECRET_KEY env vars
 * @route POST /api/verifyoculuslogin
 * @param {Object} req - Request with userId and nonce in body
 * @param {Object} res - Response with session details or error
 */
export default async function handler(req, res) {
    console.log('Received Oculus login request:', req.body);
    
    try {
        if (req.method !== 'POST') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        const { userId: receivedUserId, nonce } = req.body;
        if (!receivedUserId || !nonce) {
            return res.status(400).json({ 
                success: false, 
                error: 'Authentication failed'  // Genericized
            });
        }

        // Parse userId for backward compatibility
        let metaId = receivedUserId;
        let appInstanceHash = null;
        if (receivedUserId.includes('|')) {
            const parts = receivedUserId.split('|');
            if (parts.length === 2) {
                metaId = parts[0];
                appInstanceHash = parts[1];
                // Optional: Basic validation of hash format (Base64 SHA256 is typically 44 chars)
                if (!/^[A-Za-z0-9+/=]+$/.test(appInstanceHash) || appInstanceHash.length !== 44) {
                    console.warn(`Invalid hash format: ${appInstanceHash}`);
                    return res.status(400).json({
                        success: false,
                        error: 'Authentication failed'
                    });
                }
            } else {
                // Malformed composite userId
                console.error(`Malformed userId: ${receivedUserId}`);
                return res.status(400).json({
                    success: false,
                    error: 'Authentication failed'
                });
            }
        }

        // Quick sanity check on metaId (Oculus IDs are numeric)
        if (!/^\d+$/.test(metaId)) {
            console.error(`Invalid metaId format: ${metaId}`);
            return res.status(400).json({
                success: false,
                error: 'Authentication failed'
            });
        }

        const appId = process.env.OCULUS_APP_ID;
        const appSecret = process.env.OCULUS_APP_SECRET;
        if (!appId || !appSecret) {
            console.error('Missing Oculus config');  // Log for debugging
            return res.status(500).json({ 
                success: false, 
                error: 'Internal Server Error' 
            });
        }

        const accessToken = `OC|${appId}|${appSecret}`;
        const url = `https://graph.oculus.com/user_nonce_validate?nonce=${nonce}&user_id=${metaId}&access_token=${accessToken}`;

        const oculusResponse = await fetch(url, {
            method: 'POST'
        });

        const oculusBody = await oculusResponse.text();

        if (!oculusResponse.ok) {
            console.error('Oculus validation failed:', oculusBody);
            return res.status(oculusResponse.status).json({
                success: false,
                error: 'Authentication failed',  // Genericized
                details: oculusBody  // Keep details but consider removing if too revealing; log instead
            });
        }

        let oculusResult;
        try {
            oculusResult = JSON.parse(oculusBody);
        } catch (e) {
            console.error('Invalid Oculus response:', e);  // Log error
            return res.status(500).json({
                success: false,
                error: 'Internal Server Error'  // Genericized
            });
        }

        if (!oculusResult.is_valid) {
            return res.status(400).json({
                success: false,
                error: 'Authentication failed'  // Genericized
            });
        }

        // Valid nonce: Check device ban if hash present
        const titleId = process.env.PLAYFAB_TITLE_ID;
        const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;
        
        if (!titleId || !secretKey) {
            console.error('Missing PlayFab config');  // Log for debugging
            return res.status(500).json({ 
                success: false, 
                error: 'Internal Server Error' 
            });
        }

        if (appInstanceHash) {
            // Fetch banned devices from PlayFab Internal Title Data
            const bannedKey = 'BannedHardwareInstances';
            const getInternalDataUrl = `https://${titleId}.playfabapi.com/Admin/GetTitleInternalData`;
            const getInternalDataBody = JSON.stringify({
                Keys: [bannedKey]
            });

            const internalDataResponse = await fetch(getInternalDataUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-SecretKey': secretKey
                },
                body: getInternalDataBody
            });

            const internalData = await internalDataResponse.json();
            if (!internalDataResponse.ok) {
                console.error('PlayFab internal data fetch failed:', internalData);
                // For backward compat, don't fail hard - log and proceed without check
            } else {
                let bannedInstances = [];
                if (internalData.data.Data && internalData.data.Data[bannedKey]) {
                    try {
                        bannedInstances = JSON.parse(internalData.data.Data[bannedKey]);
                    } catch (e) {
                        console.error('Error parsing banned list:', e);
                    }
                }

                if (bannedInstances.includes(appInstanceHash)) {
                    console.log(`Banned instance detected: ${appInstanceHash}`);
                    return res.status(403).json({
                        success: false,
                        error: 'AccountBanned',
                        errorCode: 1002,
                        errorMessage: 'The account making this request is currently banned',
                        banInfo: {
                            reason: 'Severe Modding',
                            expiry: 'Indefinite'
                        },
                        details: 'The account making this request is currently banned'
                    });
                }
            }
        }

        // Perform PlayFab Server LoginWithCustomID
        const playfabUrl = `https://${titleId}.playfabapi.com/Server/LoginWithCustomID`;
        const playfabBody = JSON.stringify({
            CustomId: metaId,
            CreateAccount: true,
            InfoRequestParameters: {
                GetUserAccountInfo: true,
                GetPlayerProfile: true,
                GetUserData: true,
                GetEntityToken: true,
                ProfileConstraints: { ShowDisplayName: true }
            }
        });

        const playfabResponse = await fetch(playfabUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: playfabBody
        });

        const playfabData = await playfabResponse.json();

        if (!playfabResponse.ok) {
            console.error('PlayFab login failed:', playfabData);
            
            // Special handling for account bans
            if (playfabData.error === 'AccountBanned' || playfabData.errorCode === 1002) {
                // Extract ban details
                const banInfo = {
                    reason: null,
                    expiry: null
                };
                
                // PlayFab returns errorDetails as an object with ban reasons as keys
                // and expiry dates as array values
                if (playfabData.errorDetails) {
                    const reasons = Object.keys(playfabData.errorDetails);
                    if (reasons.length > 0) {
                        banInfo.reason = reasons[0]; // e.g., "Testing Ban"
                        const expiryArray = playfabData.errorDetails[reasons[0]];
                        if (Array.isArray(expiryArray) && expiryArray.length > 0) {
                            banInfo.expiry = expiryArray[0]; // e.g., "2025-09-27T06:40:47"
                        }
                    }
                }
                
                return res.status(403).json({
                    success: false,
                    error: 'AccountBanned',
                    errorCode: playfabData.errorCode,
                    errorMessage: playfabData.errorMessage,
                    banInfo: banInfo,
                    details: playfabData.errorMessage // Keep for backward compatibility
                });
            }
            
            // Other PlayFab errors
            return res.status(playfabResponse.status).json({
                success: false,
                error: 'Authentication failed',  // Genericized for non-ban errors
                errorCode: playfabData.errorCode,
                errorMessage: playfabData.errorMessage,
                details: playfabData.errorMessage
            });
        }

        // Successful login: Store hash if present
        if (appInstanceHash) {
            const internalDataKey = 'DeviceID';
            const updateInternalUrl = `https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`;
            const updateInternalBody = JSON.stringify({
                PlayFabId: playfabData.data.PlayFabId,
                Data: {
                    [internalDataKey]: appInstanceHash
                },
                Permission: 'Private'  // Added for explicit privacy (though Internal Data is already secure)
            });

            const updateResponse = await fetch(updateInternalUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-SecretKey': secretKey
                },
                body: updateInternalBody
            });

            if (!updateResponse.ok) {
                const updateError = await updateResponse.json();
                console.error('Failed to update internal data:', updateError);
                // Don't fail the login - just log
            }
        }

        return res.status(200).json({
            success: true,
            sessionTicket: playfabData.data.SessionTicket,
            playFabId: playfabData.data.PlayFabId,
            newlyCreated: playfabData.data.NewlyCreated,
            infoPayload: JSON.stringify(playfabData.data.InfoResultPayload),
            entityToken: playfabData.data.EntityToken.EntityToken,
            entityId: playfabData.data.EntityToken.Entity.Id,
            entityType: playfabData.data.EntityToken.Entity.Type
        });

    } catch (err) {
        console.error('Error processing Oculus login:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Internal Server Error' 
        });
    }
}