import fetch from 'node-fetch';
import crypto from 'crypto';
import https from 'https';

/**
 * SIMPLE Certificate Monitoring (Alert-Only)
 * 
 * This version:
 * 1. Rotates validation token (existing functionality)
 * 2. Checks PlayFab certificate for rotation
 * 3. ALERTS you if rotation detected (does NOT auto-update)
 * 
 * No VERCEL_TOKEN or VERCEL_PROJECT_ID required!
 * 
 * Called via Vercel Cron
 * Requires only: PLAYFAB_TITLE_ID, PLAYFAB_DEV_SECRET_KEY, PLAYFAB_CERT_FINGERPRINT
 * @route GET /api/rotatetoken
 */

/**
 * Fetches current PlayFab certificate fingerprint
 */
async function getCurrentPlayFabCertificate(titleId) {
    return new Promise((resolve) => {
        const options = {
            hostname: `${titleId}.playfabapi.com`,
            port: 443,
            method: 'GET',
            path: '/',
            rejectUnauthorized: true,
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
                console.warn('Current certificate fingerprint:');
                console.warn(currentFingerprint);
                results.certificateCheck.status = 'NOT_CONFIGURED';
                results.certificateCheck.action = 'Set PLAYFAB_CERT_FINGERPRINT in Vercel dashboard';
            } else if (currentFingerprint === storedFingerprint) {
                console.log('✅ Certificate fingerprint matches stored value');
                results.certificateCheck.status = 'VALID';
                
                // Warn if expiring soon
                if (currentCert.daysUntilExpiry < 30) {
                    console.warn(`⚠️  Certificate expires in ${currentCert.daysUntilExpiry} days!`);
                    console.warn('PlayFab will likely rotate the certificate soon.');
                    results.certificateCheck.warning = `Certificate expires in ${currentCert.daysUntilExpiry} days`;
                }
            } else {
                // CERTIFICATE ROTATION DETECTED!
                console.error('═══════════════════════════════════════════════════');
                console.error('🚨 CERTIFICATE ROTATION DETECTED!');
                console.error('═══════════════════════════════════════════════════');
                console.error('Old fingerprint (stored):');
                console.error(storedFingerprint);
                console.error('');
                console.error('New fingerprint (current):');
                console.error(currentFingerprint);
                console.error('═══════════════════════════════════════════════════');
                console.error('ACTION REQUIRED:');
                console.error('1. Go to Vercel Dashboard → Settings → Environment Variables');
                console.error('2. Update PLAYFAB_CERT_FINGERPRINT to:');
                console.error(currentFingerprint);
                console.error('3. Redeploy your application');
                console.error('═══════════════════════════════════════════════════');
                
                results.certificateCheck.status = 'ROTATION_DETECTED';
                results.certificateCheck.oldFingerprint = storedFingerprint;
                results.certificateCheck.newFingerprint = currentFingerprint;
                results.certificateCheck.action = 'MANUAL_UPDATE_REQUIRED';
                results.certificateCheck.instructions = {
                    step1: 'Go to Vercel Dashboard → Settings → Environment Variables',
                    step2: `Update PLAYFAB_CERT_FINGERPRINT to: ${currentFingerprint}`,
                    step3: 'Redeploy your application'
                };

                // TODO: Add webhook notification here if you want
                // await sendSlackAlert(...);
                // await sendDiscordAlert(...);
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

        const needsAttention = 
            results.certificateCheck?.status === 'ROTATION_DETECTED' ||
            results.certificateCheck?.status === 'NOT_CONFIGURED';

        if (needsAttention) {
            console.warn(`⚠️  Rotation complete with MANUAL ACTION REQUIRED (${duration}ms)`);
        } else if (allSuccessful) {
            console.log(`✅ Rotation complete - all checks passed (${duration}ms)`);
        } else {
            console.warn(`⚠️  Rotation completed with warnings (${duration}ms)`);
        }

        return res.status(200).json({
            success: allSuccessful,
            needsAttention: needsAttention,
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