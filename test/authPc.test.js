const assert = require( 'assert' ).strict;
const keys = require( './keys/keys' );
const AuthPc = require( '../lib/Auth' );


describe( 'AuthPc middleware test', function () {
    const authPc = new AuthPc( keys );
    const userId = "kkjwhhwllwhwl3l3hh4lljssl";
    let req = {
        user: {
            username: "peter@example.com",
            password: "my-secret-password",
            id: userId
        }
    };
    let res = {};
    let nextFunc = function () {
    };

    afterEach( () => {
        req = {
            user: {
                username: "peter@example.com",
                password: "my-secret-password",
                id: userId
            }
        };
    } );

    describe( 'create salt, hash and tokens', function () {
        it( 'createSalt and attach to req', function ( done ) {
            authPc.createSalt( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.salt, 'Salt is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createPasswordHash and attach to req', function ( done ) {
            authPc.createPasswordHash( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.hash, 'Hash is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createSaltAndPasswordHash and attach to req', function ( done ) {
            authPc.createSaltAndPasswordHash( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.salt, 'Salt is absent' );
                    assert.ok( req.user.hash, 'Hash is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createWebTokenSignedEncrypted and readWebTokenSignedEncrypted', function ( done ) {
            authPc.createWebTokenSignedEncrypted( req, res, nextFunc )
                .then( () => {
                    req.user.id = null;
                    assert.ok( req.user.webToken, 'webToken is absent' );
                } )
                .then( () => {
                    authPc.decryptWebTokenSignedEncrypted( req, res, nextFunc );
                } )
                .then( () => {
                    assert.equal( req.user.id, userId );
                    done();
                } )
                .catch( done );
        } );

        it( 'createPasswordResetToken and attach to req', function ( done ) {
            authPc.createPasswordResetTokenSignedEncrypted( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.token, 'Token is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createWebTokenSignedBase64 and decryptWebTokenSignedBase64', function ( done ) {
            // console.log( req.user );
            authPc.createWebTokenSignedBase64( req, res, nextFunc )
                .then( () => {
                    // console.log( req.user );
                    // authPc.decryptVerifyWebTokenSignedBase64( req, res, nextFunc );
                } )
                .then( () => {
                    // console.log( req.user );
                    done();
                } )
                .catch( done );
        } )
    } );

} );

