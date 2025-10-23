import fetch from 'node-fetch';
import crypto from 'crypto';
import https from 'https';

/**
 * Certificate Auto-Discovery & Management
 * 
 * This cron job:
 * 1. Rotates validation token
 * 2. Fetches current PlayFab certificate
 * 3. Checks against ValidCertificates in PlayFab Internal Data
 * 4. AUTO-ADDS new valid certificates to the list
 * 5. Tracks statistics for monitoring
 * 
 * NO environment variables needed for certificates!
 * Everything stored in PlayFab Internal Title Data:
 * - ValidCertificates: Array of valid fingerprints
 * - CertificateRegistry: Full metadata and statistics
 */

/**
 * Get valid certificates from PlayFab
 */
async function getValidCertificates(titleId, secretKey) {
    try {
        const url = `https://${titleId}.playfabapi.com/Admin/GetTitleInternalData`;
        const body = JSON.stringify({
            Keys: ['ValidCertificates']
        });

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: body
        });

        if (!response.ok) {
            return { success: false, certificates: [] };
        }

        const data = await response.json();
        const certsJson = data.data?.Data?.ValidCertificates;
        
        if (!certsJson) {
            return { success: true, certificates: [] };
        }

        try {
            const certificates = JSON.parse(certsJson);
            return { 
                success: true, 
                certificates: Array.isArray(certificates) ? certificates : [] 
            };
        } catch (e) {
            return { success: false, certificates: [] };
        }
    } catch (error) {
        return { success: false, certificates: [] };
    }
}

/**
 * Get certificate registry from PlayFab
 */
async function getCertificateRegistry(titleId, secretKey) {
    try {
        const url = `https://${titleId}.playfabapi.com/Admin/GetTitleInternalData`;
        const body = JSON.stringify({
            Keys: ['CertificateRegistry']
        });

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: body
        });

        if (!response.ok) {
            return { success: false, registry: [] };
        }

        const data = await response.json();
        const registryJson = data.data?.Data?.CertificateRegistry;
        
        if (!registryJson) {
            return { success: true, registry: [] };
        }

        try {
            const registry = JSON.parse(registryJson);
            return { 
                success: true, 
                registry: Array.isArray(registry) ? registry : [] 
            };
        } catch (e) {
            return { success: false, registry: [] };
        }
    } catch (error) {
        return { success: false, registry: [] };
    }
}

/**
 * Update valid certificates list in PlayFab
 */
async function updateValidCertificates(titleId, secretKey, certificates) {
    try {
        const url = `https://${titleId}.playfabapi.com/Admin/SetTitleInternalData`;
        const body = JSON.stringify({
            Key: 'ValidCertificates',
            Value: JSON.stringify(certificates)
        });

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: body
        });

        return { success: response.ok };
    } catch (error) {
        return { success: false };
    }
}

/**
 * Update certificate registry in PlayFab
 */
async function updateCertificateRegistry(titleId, secretKey, registry) {
    try {
        const url = `https://${titleId}.playfabapi.com/Admin/SetTitleInternalData`;
        const body = JSON.stringify({
            Key: 'CertificateRegistry',
            Value: JSON.stringify(registry)
        });

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SecretKey': secretKey
            },
            body: body
        });

        return { success: response.ok };
    } catch (error) {
        return { success: false };
    }
}

/**
 * Fetch current PlayFab certificate with retry
 */
async function getCurrentPlayFabCertificate(titleId, attempt = 1, maxAttempts = 3) {
    return new Promise((resolve) => {
        const startTime = Date.now();
        const timeoutMs = 10000 + (attempt - 1) * 5000;
        
        const options = {
            hostname: `${titleId}.playfabapi.com`,
            port: 443,
            method: 'GET',
            path: '/',
            rejectUnauthorized: true,
            timeout: timeoutMs
        };

        const req = https.request(options, (res) => {
            try {
                const duration = Date.now() - startTime;
                const cert = res.socket.getPeerCertificate();
                
                if (!cert || Object.keys(cert).length === 0) {
                    if (attempt < maxAttempts) {
                        setTimeout(async () => {
                            const result = await getCurrentPlayFabCertificate(titleId, attempt + 1, maxAttempts);
                            resolve(result);
                        }, attempt * 1000);
                    } else {
                        resolve({ success: false, error: 'NO_CERTIFICATE', attempts: attempt });
                    }
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
                    issuerOrg: cert.issuer?.O || 'unknown',
                    serialNumber: cert.serialNumber,
                    validFrom: validFrom.toISOString(),
                    validTo: validTo.toISOString(),
                    daysUntilExpiry,
                    attempts: attempt,
                    duration: `${duration}ms`
                });
            } catch (error) {
                if (attempt < maxAttempts) {
                    setTimeout(async () => {
                        const result = await getCurrentPlayFabCertificate(titleId, attempt + 1, maxAttempts);
                        resolve(result);
                    }, attempt * 1000);
                } else {
                    resolve({ success: false, error: 'PROCESSING_ERROR', attempts: attempt });
                }
            }
        });

        req.on('error', (error) => {
            if (attempt < maxAttempts) {
                setTimeout(async () => {
                    const result = await getCurrentPlayFabCertificate(titleId, attempt + 1, maxAttempts);
                    resolve(result);
                }, attempt * 1000);
            } else {
                resolve({ success: false, error: 'REQUEST_ERROR', attempts: attempt });
            }
        });

        req.on('timeout', () => {
            req.destroy();
            if (attempt < maxAttempts) {
                setTimeout(async () => {
                    const result = await getCurrentPlayFabCertificate(titleId, attempt + 1, maxAttempts);
                    resolve(result);
                }, attempt * 1000);
            } else {
                resolve({ success: false, error: 'TIMEOUT', attempts: attempt });
            }
        });

        req.end();
    });
}

export default async function handler(req, res) {
    const startTime = Date.now();
    const results = {
        timestamp: new Date().toISOString(),
        tokenRotation: null,
        certificateManagement: null
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
                error: 'Missing required configuration'
            });
        }

        console.log('═══════════════════════════════════════════════════');
        console.log('🔄 Certificate Auto-Discovery & Token Rotation');
        console.log(`Timestamp: ${results.timestamp}`);
        console.log('═══════════════════════════════════════════════════');

        // ============================================
        // PART 1: Rotate Validation Token
        // ============================================
        console.log('\n📝 Rotating validation token...');
        
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
            console.error('❌ Failed to rotate token:', errorData);
            results.tokenRotation = { success: false, error: errorData };
        } else {
            console.log('✅ Token rotated successfully');
            results.tokenRotation = { success: true, rotatedAt: new Date().toISOString() };
        }

        // ============================================
        // PART 2: Certificate Auto-Discovery
        // ============================================
        console.log('\n🔐 Checking certificate...');
        
        const currentCert = await getCurrentPlayFabCertificate(titleId);
        
        if (!currentCert.success) {
            console.error(`❌ Failed to fetch certificate (${currentCert.attempts} attempts)`);
            results.certificateManagement = {
                success: false,
                error: currentCert.error,
                attempts: currentCert.attempts
            };
        } else {
            console.log(`✅ Certificate fetched (${currentCert.duration}, attempt ${currentCert.attempts})`);
            
            const currentFingerprint = currentCert.fingerprint;
            
            // Get current valid certificates list
            const validCertsResult = await getValidCertificates(titleId, secretKey);
            let validCertificates = validCertsResult.certificates;
            
            // Get certificate registry
            const registryResult = await getCertificateRegistry(titleId, secretKey);
            let registry = registryResult.registry;
            
            // Find or create entry in registry
            let certEntry = registry.find(c => c.fingerprint === currentFingerprint);
            const isNewCertificate = !certEntry;
            
            if (certEntry) {
                // Update existing entry
                certEntry.lastSeen = new Date().toISOString();
                certEntry.seenCount = (certEntry.seenCount || 0) + 1;
            } else {
                // New certificate discovered!
                certEntry = {
                    fingerprint: currentFingerprint,
                    subject: currentCert.subject,
                    issuer: currentCert.issuer,
                    issuerOrg: currentCert.issuerOrg,
                    serialNumber: currentCert.serialNumber,
                    validFrom: currentCert.validFrom,
                    validTo: currentCert.validTo,
                    firstSeen: new Date().toISOString(),
                    lastSeen: new Date().toISOString(),
                    seenCount: 1,
                    autoAdded: true
                };
                registry.push(certEntry);
                
                console.warn('🆕 NEW CERTIFICATE DISCOVERED!');
                console.warn(`Fingerprint: ${currentFingerprint}`);
                console.warn(`Subject: ${currentCert.subject}`);
                console.warn(`Issuer: ${currentCert.issuerOrg}`);
            }
            
            // Update registry
            await updateCertificateRegistry(titleId, secretKey, registry);
            
            // Check if certificate is in valid list
            const isInValidList = validCertificates.includes(currentFingerprint);
            
            if (!isInValidList) {
                // AUTO-ADD to valid certificates!
                console.warn('➕ Auto-adding to ValidCertificates list...');
                validCertificates.push(currentFingerprint);
                const updateResult = await updateValidCertificates(titleId, secretKey, validCertificates);
                
                if (updateResult.success) {
                    console.log('✅ Certificate added to ValidCertificates!');
                } else {
                    console.error('❌ Failed to update ValidCertificates');
                }
            }
            
            results.certificateManagement = {
                success: true,
                currentFingerprint: currentFingerprint,
                validCertificatesCount: validCertificates.length,
                registrySize: registry.length,
                isNewCertificate: isNewCertificate,
                wasAutoAdded: !isInValidList,
                daysUntilExpiry: currentCert.daysUntilExpiry,
                attempts: currentCert.attempts
            };
            
            // Display summary
            console.log('\n📊 CERTIFICATE SUMMARY:');
            console.log(`Valid Certificates: ${validCertificates.length}`);
            console.log(`Registry Size: ${registry.length}`);
            console.log(`Current: ...${currentFingerprint.slice(-12)}`);
            console.log(`Status: ${isNewCertificate ? '🆕 New' : '✅ Known'}`);
            console.log(`Expires: ${currentCert.daysUntilExpiry} days`);
            
            if (currentCert.daysUntilExpiry < 30) {
                console.warn(`⚠️  WARNING: Certificate expires in ${currentCert.daysUntilExpiry} days!`);
                results.certificateManagement.warning = `Expires in ${currentCert.daysUntilExpiry} days`;
            }
            
            // Show all valid certificates
            console.log('\n📋 Valid Certificates:');
            validCertificates.forEach((fp, i) => {
                const isCurrent = fp === currentFingerprint ? ' ← CURRENT' : '';
                console.log(`  ${i + 1}. ...${fp.slice(-12)}${isCurrent}`);
            });
        }

        // ============================================
        // Summary
        // ============================================
        const duration = Date.now() - startTime;
        results.duration = `${duration}ms`;

        const allSuccessful = 
            results.tokenRotation?.success !== false &&
            results.certificateManagement?.success !== false;

        console.log('\n═══════════════════════════════════════════════════');
        if (allSuccessful) {
            console.log(`✅ Job completed successfully in ${duration}ms`);
        } else {
            console.warn(`⚠️  Job completed with issues in ${duration}ms`);
        }
        console.log('═══════════════════════════════════════════════════\n');

        return res.status(200).json({
            success: allSuccessful,
            ...results
        });

    } catch (err) {
        console.error('💥 FATAL ERROR:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Internal Server Error',
            details: err.message,
            ...results
        });
    }
}