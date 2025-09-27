const express = require('express');
const openpgp = require('openpgp');
const path = require('path');

const app = express();
const port = 3000;

// Middleware to parse JSON bodies and serve static files
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- API ROUTES ---

// 1. Generate a new PGP key pair
app.post('/api/generate-keys', async (req, res) => {
    try {
        const { name, email, passphrase } = req.body;

        if (!name || !email || !passphrase) {
            return res.status(400).json({ error: 'Name, email, and passphrase are required.' });
        }

        const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
            type: 'ecc', // Modern Elliptic Curve Cryptography
            curve: 'curve25519',
            userIDs: [{ name: name, email: email }],
            passphrase: passphrase,
            format: 'armored' // The text-based format (-----BEGIN PGP...-----)
        });

        res.json({ privateKey, publicKey });

    } catch (error) {
        console.error('Key generation error:', error);
        res.status(500).json({ error: 'Failed to generate keys.' });
    }
});

// 2. Encrypt a message
app.post('/api/encrypt', async (req, res) => {
    try {
        const { message, publicKeyArmored } = req.body;

        if (!message || !publicKeyArmored) {
            return res.status(400).json({ error: 'Message and public key are required.' });
        }

        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

        const encryptedMessage = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: message }),
            encryptionKeys: publicKey,
        });

        res.json({ encryptedMessage });

    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).json({ error: 'Encryption failed. Is the public key valid?' });
    }
});

// 3. Decrypt a message
app.post('/api/decrypt', async (req, res) => {
    try {
        const { encryptedMessage, privateKeyArmored, passphrase } = req.body;

        if (!encryptedMessage || !privateKeyArmored || !passphrase) {
            return res.status(400).json({ error: 'Encrypted message, private key, and passphrase are required.' });
        }
        
        // Read the armored private key
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

        // Decrypt the private key itself using the passphrase
        const decryptedPrivateKey = await openpgp.decryptKey({
            privateKey: privateKey,
            passphrase: passphrase
        });

        // Decrypt the message using the unlocked private key
        const message = await openpgp.readMessage({ armoredMessage: encryptedMessage });

        const { data: decryptedMessage } = await openpgp.decrypt({
            message,
            decryptionKeys: decryptedPrivateKey
        });

        res.json({ decryptedMessage });

    } catch (error) {
        console.error('Decryption error:', error);
        res.status(500).json({ error: 'Decryption failed. Check the private key, passphrase, and message format.' });
    }
});


app.listen(port, () => {
    console.log(`PGP Encryption server running at http://localhost:${port}`);
});