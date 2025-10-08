import fetch from 'node-fetch';
import querystring from 'node:querystring';

/**
 * API Module for Oculus nonce validation and PlayFab login
 * Validates nonce, then performs secure PlayFab Server LoginWithCustomID
 * Requires OCULUS_APP_ID, OCULUS_APP_SECRET, PLAYFAB_TITLE_ID, PLAYFAB_DEV_SECRET_KEY env vars
 * @route POST /api/verifyoculuslogin
 * @param {Object} req - Request with userId and nonce in body
 * @param {Object} res - Response with session details or error
 */
export default async function handler(req, res) {
    try {
        if (req.method !== 'POST') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        if (!req.body) {
            return res.status(400).json({ 
                success: false, 
                error: 'Authentication failed'
            });
        }

        let bodyData;
        const contentType = req.headers['content-type'] || '';

        if (contentType.includes('application/x-www-form-urlencoded')) {
            const rawBody = await new Promise((resolve, reject) => {
                let data = '';
                req.on('data', chunk => data += chunk);
                req.on('end', () => resolve(data));
                req.on('error', reject);
            });
            bodyData = querystring.parse(rawBody);
        } else {
            bodyData = req.body;
        }

        const { userId: receivedUserId, nonce } = bodyData;
        if (!receivedUserId || !nonce) {
            return res.status(400).json({ 
                success: false, 
                error: 'Authentication failed'
            });
        }

        let metaId = receivedUserId;
        let appInstanceHash = null;
        if (receivedUserId.includes('|')) {
            const parts = receivedUserId.split('|');
            if (parts.length === 2) {
                metaId = parts[0];
                appInstanceHash = parts[1];
                if (!/^[A-Za-z0-9+/=]+$/.test(appInstanceHash) || appInstanceHash.length !== 44) {
                    return res.status(400).json({
                        success: false,
                        error: 'Authentication failed'
                    });
                }
            } else {
                return res.status(400).json({
                    success: false,
                    error: 'Authentication failed'
                });
            }
        }

        if (!/^\d+$/.test(metaId)) {
            return res.status(400).json({
                success: false,
                error: 'Authentication failed'
            });
        }

        const appId = process.env.OCULUS_APP_ID;
        const appSecret = process.env.OCULUS_APP_SECRET;
        if (!appId || !appSecret) {
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
            return res.status(oculusResponse.status).json({
                success: false,
                error: 'Authentication failed',
                details: oculusBody
            });
        }

        let oculusResult;
        try {
            oculusResult = JSON.parse(oculusBody);
        } catch (e) {
            return res.status(500).json({
                success: false,
                error: 'Internal Server Error'
            });
        }

        if (!oculusResult.is_valid) {
            return res.status(400).json({
                success: false,
                error: 'Authentication failed'
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

        if (appInstanceHash) {
            const bannedKey = 'BannedDevices';
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
            if (internalDataResponse.ok) {
                let bannedInstances = [];
                if (internalData.data.Data && internalData.data.Data[bannedKey]) {
                    try {
                        bannedInstances = JSON.parse(internalData.data.Data[bannedKey]);
                    } catch (e) {}
                }

                if (bannedInstances.includes(appInstanceHash)) {
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
            if (playfabData.error === 'AccountBanned' || playfabData.errorCode === 1002) {
                const banInfo = {
                    reason: null,
                    expiry: null
                };
                
                if (playfabData.errorDetails) {
                    const reasons = Object.keys(playfabData.errorDetails);
                    if (reasons.length > 0) {
                        banInfo.reason = reasons[0];
                        const expiryArray = playfabData.errorDetails[reasons[0]];
                        if (Array.isArray(expiryArray) && expiryArray.length > 0) {
                            banInfo.expiry = expiryArray[0];
                        }
                    }
                }
                
                return res.status(403).json({
                    success: false,
                    error: 'AccountBanned',
                    errorCode: playfabData.errorCode,
                    errorMessage: playfabData.errorMessage,
                    banInfo: banInfo,
                    details: playfabData.errorMessage
                });
            }
            
            return res.status(playfabResponse.status).json({
                success: false,
                error: 'Authentication failed',
                errorCode: playfabData.errorCode,
                errorMessage: playfabData.errorMessage,
                details: playfabData.errorMessage
            });
        }

        if (appInstanceHash) {
            const internalDataKey = 'deviceID';
            const updateInternalUrl = `https://${titleId}.playfabapi.com/Server/UpdateUserInternalData`;
            const updateInternalBody = JSON.stringify({
                PlayFabId: playfabData.data.PlayFabId,
                Data: {
                    [internalDataKey]: appInstanceHash
                },
                Permission: 'Private'
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