const express = require('express');
const jwt = require('jsonwebtoken');
const JwksClient = require('jwks-rsa');

const PORT = 8080;
const JWKS_URI = 'https://<insert servername here>.eu.auth0.com/.well-known/jwks.json'
const app = express();

app.get('/balance', async(req, res) => {
    try {
        // get authorization header
        const authorization = req.get('authorization');
        if (!authorization) {
            throw { status: 400, message: 'Missing authorization header' };
        }

        // get token from authorization header
        const [key, token] = authorization.split(' ');
        if (key !== 'Bearer') {
            throw { status: 400, message: 'Invalid Bearer token' };
        }

        // decode token
        const decodedToken = jwt.decode(token, { complete: true });
        if (!decodedToken || !decodedToken.header || !decodedToken.header.kid) {
            throw { status: 401, message: 'Invalid authorization token' };
        }

        // get jwk from jwks based om keyId
        const keyId = decodedToken.header.kid;
        const jwksClient = JwksClient({strictSsl: false, jwksUri: JWKS_URI });

        const jwk = await new Promise((resolve, reject) => {
            jwksClient.getSigningKey(keyId, (error, key) => {
                if(error) {
                    reject({ status: 500, message: 'Unable to fetch signing key' });
                } else {
                    resolve(key.publicKey || key.rsaPublicKey);
                } 
            });
        });

        // check signature
        const jwtPayload = await new Promise((resolve, reject) => {
            jwt.verify(token, jwk, { ignoreExpiration: true }, (error, data) => {
                if(error) {
                    reject({ status: 401, message: 'Invalid authorization token' });
                } else {
                    resolve(data);
                } 
            });
        });

        // check payload
        const now = new Date().valueOf() / 1000;
        const requiredScope = 'read:users';
        console.log(jwtPayload)

        if (!jwtPayload){
            throw { status: 401, message: 'Invalid authorization token' };
        } else if (!jwtPayload.scope || jwtPayload.scope !== requiredScope) {
            throw { status: 401, message: 'Authorization token has insufficient scope' };
        } else if (!jwtPayload.exp || jwtPayload.exp < now) {
            throw { status: 401, message: 'Authorization token has expired' };
        }

        // Get data from database
        const currency = 'EUR';
        const balance = 1500;

        res.send({ currency, balance });

    } catch(error) {
        error = error.status ? error : { status: 500, message: 'Internal Server Error' };
        res.status(error.status).send(error);
    }
})

// Start the server on port 8080
app.listen(PORT, () => console.log(`Oauth CC example server listening on port ${PORT}`));
