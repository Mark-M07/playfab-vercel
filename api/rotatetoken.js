import fetch from 'node-fetch';
import crypto from 'crypto';
import https from 'https';

/**
 * ENHANCED API Module for automated token AND certificate rotation
 * 
 * This cron job:
 * 1. Rotates validation token (existing functionality)
 * 2. Checks PlayFab certificate for rotation
 * 3. Auto-updates PLAYFAB_CERT_FINGERPRINT if changed
 * 
 * Called via Vercel Cron every 1 hour
 * Requires PLAYFAB_TITLE_ID, PLAYFAB_DEV_SECRET_KEY, VERCEL_TOKEN env vars
 * @route GET /api/rotatetoken
 */

async function getCurrentPlayFabCertificate(titleId) {
    return new Promise((resolve) => {
        const options = {
            hostname: `${titleId}.playfabapi.com`,
            port: 443,
            method: 'GET',
            path: '/',
            rejectUnauthorized: true, // Vercel validates TLS
            timeout: 10000
        };

        const req = https.request(options, (res) => {
            try {
                const cert = res.socket.getPeerCertificate();
                
                if (!cert || Object.keys(cert).length === 0) {
                    console.error('Failed to retrieve PlayFab certificate');
                    resolve({ success: false, error: 'NO_CERTIFICATE' });
                    return;
                }

                const fingerprint = cert.fingerprint256;
                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);
                const daysUntilExpiry = Math.floor((validTo - new Date()) / (1000 * 60 * 60 * 24));

                resolve({ 
                    success: true,
                    fingerprint,
                    subject: cert.subject?.CN || 'unknown',
                    issuer: cert.issuer?.CN || 'unknown',
                    validFrom: validFrom.toISOString(),
                    validTo: validTo.toISOString(),
                    daysUntilExpiry
                });
            } catch (error) {
                console.error('Error processing certificate:', error);
                resolve({ success: false, error: 'PROCESSING_ERROR' });
            }
        });

        req.on('error', (error) => {
            console.error('Error fetching certificate:', error);
            resolve({ success: false, error: 'REQUEST_ERROR' });
        });

        req.on('timeout', () => {
            console.error('Certificate fetch timeout');
            req.destroy();
            resolve({ success: false, error: 'TIMEOUT' });
        });

        req.end();
    });
}

/**
 * Updates Vercel environment variable using Vercel API
 * Requires VERCEL_TOKEN with appropriate permissions
 */
async function updateVercelEnvVar(key, value, vercelToken, projectId) {
    try {
        // First, get the current environment variable ID
        const getUrl = `https://api.vercel.com/v9/projects/${projectId}/env`;
        const getResponse = await fetch(getUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${vercelToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (!getResponse.ok) {
            console.error('Failed to fetch env vars:', await getResponse.text());
            return { success: false, error: 'FETCH_FAILED' };
        }

        const envVars = await getResponse.json();
        const existingVar = envVars.envs?.find(env => env.key === key);

        if (existingVar) {
            // Update existing variable
            const updateUrl = `https://api.vercel.com/v9/projects/${projectId}/env/${existingVar.id}`;
            const updateResponse = await fetch(updateUrl, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${vercelToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    value: value,
                    target: ['production', 'preview', 'development']
                })
            });

            if (!updateResponse.ok) {
                console.error('Failed to update env var:', await updateResponse.text());
                return { success: false, error: 'UPDATE_FAILED' };
            }

            return { success: true, action: 'updated' };
        } else {
            // Create new variable
            const createUrl = `https://api.vercel.com/v10/projects/${projectId}/env`;
            const createResponse = await fetch(createUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${vercelToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    key: key,
                    value: value,
                    type: 'encrypted',
                    target: ['production', 'preview', 'development']
                })
            });

            if (!createResponse.ok) {
                console.error('Failed to create env var:', await createResponse.text());
                return { success: false, error: 'CREATE_FAILED' };
            }

            return { success: true, action: 'created' };
        }
    } catch (error) {
        console.error('Error updating Vercel env var:', error);
        return { success: false, error: error.message };
    }
}

async function triggerRedeployment(vercelToken, projectId, deploymentId) {
    try {
        const url = `https://api.vercel.com/v13/deployments`;
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${vercelToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: projectId,
                target: 'production',
                deploymentId: deploymentId
            })
        });

        if (!response.ok) {
            console.error('Failed to trigger redeployment:', await response.text());
            return { success: false };
        }

        return { success: true };
    } catch (error) {
        console.error('Error triggering redeployment:', error);
        return { success: false, error: error.message };
    }
}

export default async function handler(req, res) {
    const startTime = Date.now();
    const results = {
        timestamp: new Date().toISOString(),
        tokenRotation: null,
        certificateCheck: null
    };

    try {
        if (req.method !== 'GET') {
            return res.status(405).json({ 
                success: false, 
                error: 'Method Not Allowed' 
            });
        }

        const titleId = process.env.PLAYFAB_TITLE_ID;
        const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;
        const vercelToken = process.env.VERCEL_TOKEN;
        const vercelProjectId = process.env.VERCEL_PROJECT_ID;
        
        if (!titleId || !secretKey) {
            return res.status(500).json({ 
                success: false, 
                error: 'Internal Server Error',
                details: 'Missing required PlayFab configuration'
            });
        }

        // ============================================
        // PART 1: Rotate Validation Token
        // ============================================
        console.log('🔄 Rotating validation token...');
        
        const newToken = crypto.randomBytes(32).toString('base64');
        
        const updateTokenUrl = `https://${titleId}.playfabapi.com/Admin/SetTitleInternalData`;
        const updateTokenBody = JSON.stringify({
            Key: 'ValidationToken',
            Value: newToken
        });

        const tokenResponse = await fetch(updateTokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: updateTokenBody
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json();
            console.error('Failed to update validation token:', errorData);
            results.tokenRotation = {
                success: false,
                error: errorData
            };
        } else {
            console.log('✅ Validation token rotated successfully');
            results.tokenRotation = {
                success: true,
                rotatedAt: new Date().toISOString()
            };
        }

        // ============================================
        // PART 2: Check PlayFab Certificate
        // ============================================
        console.log('🔍 Checking PlayFab certificate...');
        
        const currentCert = await getCurrentPlayFabCertificate(titleId);
        
        if (!currentCert.success) {
            console.error('Failed to fetch current certificate:', currentCert.error);
            results.certificateCheck = {
                success: false,
                error: currentCert.error
            };
        } else {
            const storedFingerprint = process.env.PLAYFAB_CERT_FINGERPRINT;
            const currentFingerprint = currentCert.fingerprint;
            
            results.certificateCheck = {
                success: true,
                currentFingerprint: currentFingerprint,
                storedFingerprint: storedFingerprint || 'NOT_SET',
                subject: currentCert.subject,
                issuer: currentCert.issuer,
                validUntil: currentCert.validTo,
                daysUntilExpiry: currentCert.daysUntilExpiry
            };

            // Check if fingerprint has changed
            if (!storedFingerprint) {
                console.warn('⚠️  PLAYFAB_CERT_FINGERPRINT not set in environment');
                results.certificateCheck.status = 'NOT_CONFIGURED';
                results.certificateCheck.action = 'Please set PLAYFAB_CERT_FINGERPRINT manually';
            } else if (currentFingerprint === storedFingerprint) {
                console.log('✅ Certificate fingerprint unchanged');
                results.certificateCheck.status = 'UNCHANGED';
                
                // Warn if expiring soon
                if (currentCert.daysUntilExpiry < 30) {
                    console.warn(`⚠️  Certificate expires in ${currentCert.daysUntilExpiry} days!`);
                    results.certificateCheck.warning = `Certificate expires in ${currentCert.daysUntilExpiry} days`;
                }
            } else {
                console.warn('🚨 CERTIFICATE ROTATION DETECTED!');
                console.warn(`Old fingerprint: ${storedFingerprint}`);
                console.warn(`New fingerprint: ${currentFingerprint}`);
                
                results.certificateCheck.status = 'ROTATED';
                results.certificateCheck.oldFingerprint = storedFingerprint;
                results.certificateCheck.newFingerprint = currentFingerprint;

                // Auto-update if Vercel token is configured
                if (vercelToken && vercelProjectId) {
                    console.log('🔄 Auto-updating certificate fingerprint...');
                    
                    const updateResult = await updateVercelEnvVar(
                        'PLAYFAB_CERT_FINGERPRINT',
                        currentFingerprint,
                        vercelToken,
                        vercelProjectId
                    );

                    if (updateResult.success) {
                        console.log('✅ Certificate fingerprint updated successfully');
                        results.certificateCheck.autoUpdateStatus = 'SUCCESS';
                        results.certificateCheck.action = updateResult.action;
                        
                        console.log('🚀 Triggering redeployment...');
                        const redeployResult = await triggerRedeployment(vercelToken, vercelProjectId);
                        results.certificateCheck.redeployment = redeployResult.success ? 'TRIGGERED' : 'FAILED';
                    } else {
                        console.error('❌ Failed to update certificate fingerprint');
                        results.certificateCheck.autoUpdateStatus = 'FAILED';
                        results.certificateCheck.autoUpdateError = updateResult.error;
                        results.certificateCheck.action = 'Manual update required';
                    }
                } else {
                    console.warn('⚠️  VERCEL_TOKEN or VERCEL_PROJECT_ID not configured');
                    results.certificateCheck.autoUpdateStatus = 'SKIPPED';
                    results.certificateCheck.action = 'Manual update required - configure VERCEL_TOKEN and VERCEL_PROJECT_ID for auto-update';
                }
            }
        }

        // ============================================
        // Summary
        // ============================================
        const duration = Date.now() - startTime;
        results.duration = `${duration}ms`;

        const allSuccessful = 
            results.tokenRotation?.success !== false &&
            results.certificateCheck?.success !== false;

        if (allSuccessful) {
            console.log(`✅ Rotation complete in ${duration}ms`);
        } else {
            console.warn(`⚠️  Rotation completed with warnings in ${duration}ms`);
        }

        return res.status(200).json({
            success: allSuccessful,
            ...results
        });

    } catch (err) {
        console.error('Error in rotation job:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Internal Server Error',
            details: err.message,
            ...results
        });
    }
}